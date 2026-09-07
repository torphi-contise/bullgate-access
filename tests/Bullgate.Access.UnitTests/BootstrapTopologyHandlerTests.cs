using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.UnitTests;

public sealed class BootstrapTopologyHandlerTests
{
    [Fact]
    public async Task IdenticalManifest_IsIdempotentAndDoesNotIssueAnotherCredential()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var command = CreateCommand();

        var first = await handler.HandleAsync(command);
        var second = await handler.HandleAsync(command);

        Assert.Single(first.IssuedCredentials);
        Assert.Empty(second.IssuedCredentials);
        Assert.Equal(first.WorkspaceId, second.WorkspaceId);
        Assert.Equal(
            first.Resources.Select(resource => resource.Id),
            second.Resources.Select(resource => resource.Id));
        Assert.Single(store.Secrets);
        Assert.Single(store.Workspaces);
        Assert.Single(store.Apps);
        Assert.Single(store.Realms);
        Assert.Single(store.Environments);
        Assert.Single(store.Configurations);
        Assert.Single(store.IntegrationClients);
        Assert.Single(store.ApplicationClients);
        Assert.Equal("92TvTC0UfaA", store.ApplicationClients[0].SmsRetrieverAppHash);
    }

    [Fact]
    public async Task ChangedAccessPolicy_UpdatesTheExistingEnvironment()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        await handler.HandleAsync(CreateCommand());
        var changedPolicy = new AppAccessPolicy(
            new IdentifierAccessPolicy(
                enabled: true,
                required: true,
                IdentifierVerificationPolicy.Disabled),
            new IdentifierAccessPolicy(
                enabled: false,
                required: false,
                IdentifierVerificationPolicy.Disabled),
            new AuthenticatorAccessPolicy(
                PasswordEnabled: true,
                GoogleEnabled: false,
                AppleEnabled: false));

        var result = await handler.HandleAsync(CreateCommand(accessPolicy: changedPolicy));

        Assert.Empty(result.IssuedCredentials);
        Assert.Equal(changedPolicy, Assert.Single(store.Environments).AccessPolicy);
    }

    [Fact]
    public async Task ChangedPasswordRecoveryUrl_UpdatesAndCanClearExistingEnvironment()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());

        await handler.HandleAsync(CreateCommand(
            passwordRecoveryUrl: "https://baybo.app/reset-password"));
        Assert.Equal(
            "https://baybo.app/reset-password",
            Assert.Single(store.Environments).PasswordRecoveryUrl);

        var updated = await handler.HandleAsync(CreateCommand(
            passwordRecoveryUrl: "https://baybo.app/access/reset-password"));
        Assert.Empty(updated.IssuedCredentials);
        Assert.Equal(
            "https://baybo.app/access/reset-password",
            Assert.Single(store.Environments).PasswordRecoveryUrl);

        var cleared = await handler.HandleAsync(CreateCommand(passwordRecoveryUrl: null));
        Assert.Empty(cleared.IssuedCredentials);
        Assert.Null(Assert.Single(store.Environments).PasswordRecoveryUrl);
    }

    [Fact]
    public async Task EmailVerification_IsRejectedBecauseItIsUnsupported()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var policy = new AppAccessPolicy(
            new IdentifierAccessPolicy(
                enabled: true,
                required: true,
                new IdentifierVerificationPolicy(true, "future-email-provider")),
            new IdentifierAccessPolicy(
                enabled: false,
                required: false,
                IdentifierVerificationPolicy.Disabled),
            new AuthenticatorAccessPolicy(
                PasswordEnabled: true,
                GoogleEnabled: false,
                AppleEnabled: false));

        var exception = await Assert.ThrowsAsync<BootstrapTopologyException>(
            () => handler.HandleAsync(CreateCommand(accessPolicy: policy)));

        Assert.Contains("email verification", exception.Message, StringComparison.Ordinal);
        Assert.Empty(store.Workspaces);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task SocialAuthenticatorPolicy_IsPersistedWhenEnabled(
        bool googleEnabled,
        bool appleEnabled)
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var policy = new AppAccessPolicy(
            new IdentifierAccessPolicy(
                enabled: true,
                required: true,
                IdentifierVerificationPolicy.Disabled),
            new IdentifierAccessPolicy(
                enabled: false,
                required: false,
                IdentifierVerificationPolicy.Disabled),
            new AuthenticatorAccessPolicy(
                PasswordEnabled: true,
                GoogleEnabled: googleEnabled,
                AppleEnabled: appleEnabled));

        await handler.HandleAsync(CreateCommand(accessPolicy: policy));

        var environment = Assert.Single(store.Environments);
        Assert.Equal(googleEnabled, environment.AccessPolicy.Authenticators.GoogleEnabled);
        Assert.Equal(appleEnabled, environment.AccessPolicy.Authenticators.AppleEnabled);
    }

    [Fact]
    public async Task UnknownPhoneVerificationProvider_IsRejected()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var policy = new AppAccessPolicy(
            new IdentifierAccessPolicy(
                enabled: true,
                required: true,
                IdentifierVerificationPolicy.Disabled),
            new IdentifierAccessPolicy(
                enabled: true,
                required: false,
                new IdentifierVerificationPolicy(true, "future-sms-provider")),
            new AuthenticatorAccessPolicy(
                PasswordEnabled: true,
                GoogleEnabled: false,
                AppleEnabled: false));

        var exception = await Assert.ThrowsAsync<BootstrapTopologyException>(
            () => handler.HandleAsync(CreateCommand(accessPolicy: policy)));

        Assert.Contains(
            "unsupported phone verification provider",
            exception.Message,
            StringComparison.Ordinal);
        Assert.Empty(store.Workspaces);
    }

    [Fact]
    public async Task EnabledPhoneVerification_RequiresTwilioProvider()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var command = ConfigureEnvironment(
            CreateCommand(),
            environment => environment with
            {
                Providers = environment.Providers with { TwilioVerify = null },
            });

        var exception = await Assert.ThrowsAsync<BootstrapTopologyException>(
            () => handler.HandleAsync(command));

        Assert.Contains("providers.twilioVerify", exception.Message, StringComparison.Ordinal);
        Assert.Empty(store.Workspaces);
    }

    [Fact]
    public async Task EnabledGoogleAuthentication_RequiresGoogleProvider()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var policy = new AppAccessPolicy(
            new IdentifierAccessPolicy(
                true,
                true,
                IdentifierVerificationPolicy.Disabled),
            new IdentifierAccessPolicy(
                false,
                false,
                IdentifierVerificationPolicy.Disabled),
            new AuthenticatorAccessPolicy(true, true, false));
        var command = ConfigureEnvironment(
            CreateCommand(accessPolicy: policy),
            environment => environment with
            {
                Providers = environment.Providers with { Google = null },
            });

        var exception = await Assert.ThrowsAsync<BootstrapTopologyException>(
            () => handler.HandleAsync(command));

        Assert.Contains("providers.google", exception.Message, StringComparison.Ordinal);
        Assert.Empty(store.Workspaces);
    }

    [Fact]
    public async Task DisabledDevelopmentBypass_RejectsCredentials()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var command = ConfigureEnvironment(
            CreateCommand(),
            environment => environment with
            {
                DevelopmentBypass =
                    new DevelopmentBypassConfiguration(false, "+5511999999999", "123456"),
            });

        var exception = await Assert.ThrowsAsync<BootstrapTopologyException>(
            () => handler.HandleAsync(command));

        Assert.Contains("developmentBypass", exception.Message, StringComparison.Ordinal);
        Assert.Empty(store.Workspaces);
    }

    [Fact]
    public async Task ExistingApplicationClientMetadata_IsUpdatedWithoutChangingIdentity()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var first = await handler.HandleAsync(CreateCommand());
        var applicationClientId = Assert.Single(store.ApplicationClients).Id;

        var changed = CreateCommand("sha256:different");

        var second = await handler.HandleAsync(changed);

        Assert.Equal(first.Resources.Select(item => item.Id), second.Resources.Select(item => item.Id));
        var applicationClient = Assert.Single(store.ApplicationClients);
        Assert.Equal(applicationClientId, applicationClient.Id);
        Assert.Equal("sha256:different", applicationClient.SigningIdentity);
        Assert.Single(store.Secrets);
    }

    [Fact]
    public async Task ExistingApplicationClientAppHash_IsUpdatedWithoutChangingKey()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        await handler.HandleAsync(CreateCommand());

        var changed = ConfigureEnvironment(
            CreateCommand(smsRetrieverAppHash: "AbCdEf12345"),
            environment => environment with
            {
                PublicConfiguration = new AppEnvironmentPublicConfiguration(
                    2,
                    JsonSerializer.SerializeToElement(new { release = "next" })),
                ApplicationClients = environment.ApplicationClients
                    .Select(client => client with
                    {
                        PublicConfiguration = JsonSerializer.SerializeToElement(
                            new { feature = true }),
                    })
                    .ToArray(),
            });

        var second = await handler.HandleAsync(changed);

        Assert.Empty(second.IssuedCredentials);
        var applicationClient = Assert.Single(store.ApplicationClients);
        Assert.Equal("android-internal", applicationClient.Key);
        Assert.Equal("AbCdEf12345", applicationClient.SmsRetrieverAppHash);
        var configuration = Assert.Single(store.Configurations).Value;
        Assert.Equal(2, configuration.PublicConfiguration.Version);
        Assert.Equal(
            "next",
            configuration.PublicConfiguration.Values.GetProperty("release").GetString());
        Assert.True(Assert.Single(configuration.ApplicationClients)
            .PublicConfiguration.GetProperty("feature").GetBoolean());
    }

    [Fact]
    public async Task SmsRetrieverAppHashOnIos_IsRejectedBeforeTransaction()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var command = CreateCommand() with
        {
            Apps =
            [
                new BootstrapAppDefinition(
                    "mobile",
                    "Mobile",
                    [new BootstrapRealmDefinition("mobile-development", "Development realm")],
                    [
                        new BootstrapEnvironmentDefinition(
                            "development",
                            "Development",
                            "mobile-development",
                            CreateAccessPolicy(),
                            CreateVerificationPolicy(),
                            CreateRecoveryPolicy(null),
                            CreateProviders(CreateAccessPolicy(), null),
                            DisabledDevelopmentBypass,
                            [new BootstrapIntegrationClientDefinition("api", "API", [])],
                            [
                                new BootstrapApplicationClientDefinition(
                                    "ios-internal",
                                    "iOS internal",
                                    ApplicationClientPlatform.Ios,
                                    "com.example.mobile",
                                    "team:example",
                                    "92TvTC0UfaA",
                                    JsonSerializer.SerializeToElement(new { })),
                            ]),
                    ]),
            ],
        };

        var exception = await Assert.ThrowsAsync<BootstrapTopologyException>(
            () => handler.HandleAsync(command));

        Assert.Contains("non-Android", exception.Message, StringComparison.Ordinal);
        Assert.Empty(store.Workspaces);
    }

    [Fact]
    public async Task UnknownIntegrationClientPermission_IsRejectedBeforeTransaction()
    {
        var store = new InMemoryTopologyStore();
        var handler = new BootstrapTopologyHandler(
            store,
            new StubCredentialIssuer(),
            new FixedTimeProvider());
        var command = CreateCommand() with
        {
            Apps =
            [
                new BootstrapAppDefinition(
                    "mobile",
                    "Mobile",
                    [new BootstrapRealmDefinition("mobile-development", "Development realm")],
                    [
                        new BootstrapEnvironmentDefinition(
                            "development",
                            "Development",
                            "mobile-development",
                            CreateAccessPolicy(),
                            CreateVerificationPolicy(),
                            CreateRecoveryPolicy(null),
                            CreateProviders(CreateAccessPolicy(), null),
                            DisabledDevelopmentBypass,
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "api",
                                    "API",
                                    ["access:flow:execute"]),
                            ],
                            []),
                    ]),
            ],
        };

        var exception = await Assert.ThrowsAsync<BootstrapTopologyException>(
            () => handler.HandleAsync(command));

        Assert.Contains("not defined", exception.Message, StringComparison.Ordinal);
        Assert.Empty(store.Workspaces);
    }

    private static BootstrapTopologyCommand CreateCommand(
        string signingIdentity = "sha256:certificate",
        string smsRetrieverAppHash = "92TvTC0UfaA",
        AppAccessPolicy? accessPolicy = null,
        string? passwordRecoveryUrl = null)
    {
        var policy = accessPolicy ?? CreateAccessPolicy();
        return new(
            "example",
            "Example",
            [
                new BootstrapAppDefinition(
                    "mobile",
                    "Mobile",
                    [new BootstrapRealmDefinition("mobile-development", "Development realm")],
                    [
                        new BootstrapEnvironmentDefinition(
                            "development",
                            "Development",
                            "mobile-development",
                            policy,
                            CreateVerificationPolicy(),
                            CreateRecoveryPolicy(passwordRecoveryUrl),
                            CreateProviders(policy, passwordRecoveryUrl),
                            DisabledDevelopmentBypass,
                            [new BootstrapIntegrationClientDefinition("api", "API", [])],
                            [
                                new BootstrapApplicationClientDefinition(
                                    "android-internal",
                                    "Android internal",
                                    ApplicationClientPlatform.Android,
                                    "com.example.mobile",
                                    signingIdentity,
                                    smsRetrieverAppHash,
                                    JsonSerializer.SerializeToElement(new { })),
                            ]),
                    ]),
            ]);
    }

    private static AppAccessPolicy CreateAccessPolicy() =>
        new(
            new IdentifierAccessPolicy(
                enabled: true,
                required: true,
                IdentifierVerificationPolicy.Disabled),
            new IdentifierAccessPolicy(
                enabled: true,
                required: false,
                new IdentifierVerificationPolicy(
                    enabled: true,
                    VerificationProviderKey.TwilioVerify)),
            new AuthenticatorAccessPolicy(
                PasswordEnabled: true,
                GoogleEnabled: false,
                AppleEnabled: false));

    private static BootstrapTopologyCommand ConfigureEnvironment(
        BootstrapTopologyCommand command,
        Func<BootstrapEnvironmentDefinition, BootstrapEnvironmentDefinition> configure)
    {
        var app = Assert.Single(command.Apps);
        var environment = Assert.Single(app.Environments);
        return command with
        {
            Apps =
            [
                app with
                {
                    Environments = [configure(environment)],
                },
            ],
        };
    }

    private static AppVerificationPolicy CreateVerificationPolicy() =>
        new(10, 5, 5, 120, 15, 5);

    private static AppRecoveryPolicy CreateRecoveryPolicy(string? passwordRecoveryUrl) =>
        new(passwordRecoveryUrl, 60, 5, 10, 5, 5, 120);

    private static AppEnvironmentProviders CreateProviders(
        AppAccessPolicy policy,
        string? passwordRecoveryUrl) =>
        new(
            passwordRecoveryUrl is null
                ? null
                : new SmtpProviderConfiguration(
                    "smtp.example.test",
                    587,
                    "demo",
                    "secret",
                    "access@example.test",
                    "Example",
                    true,
                    false),
            policy.Phone.Enabled
                ? new TwilioVerifyProviderConfiguration(
                    "SK-demo",
                    "secret",
                    "VA-demo",
                    "sms",
                    "pt-BR",
                    null)
                : null,
            policy.Authenticators.GoogleEnabled
                ? new GoogleProviderConfiguration("google-client")
                : null,
            policy.Authenticators.AppleEnabled
                ? new AppleProviderConfiguration("apple-client")
                : null);

    private static DevelopmentBypassConfiguration DisabledDevelopmentBypass { get; } =
        new(false, null, null);

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.Parse("2026-08-31T20:00:00Z");
    }

    private sealed class StubCredentialIssuer : IIntegrationClientCredentialIssuer
    {
        public GeneratedIntegrationClientCredential Issue(DateTimeOffset createdAt)
        {
            var id = Guid.CreateVersion7();
            return new GeneratedIntegrationClientCredential(
                id,
                new byte[32],
                IntegrationClientSecret.Sha256V1,
                createdAt,
                $"bgic_{id:D}.stub");
        }
    }

    private sealed class InMemoryTopologyStore : IAccessTopologyStore
    {
        public List<Workspace> Workspaces { get; } = [];
        public List<App> Apps { get; } = [];
        public List<Realm> Realms { get; } = [];
        public List<AppEnvironment> Environments { get; } = [];
        public Dictionary<Guid, AppEnvironmentConfiguration> Configurations { get; } = [];
        public List<IntegrationClient> IntegrationClients { get; } = [];
        public List<IntegrationClientPermission> Permissions { get; } = [];
        public List<IntegrationClientSecret> Secrets { get; } = [];
        public List<ApplicationClient> ApplicationClients { get; } = [];

        public Task<IAccessTopologyTransaction> BeginBootstrapTransactionAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult<IAccessTopologyTransaction>(new InMemoryTransaction());

        public Task<Workspace?> FindWorkspaceAsync(
            string key,
            CancellationToken cancellationToken) =>
            Task.FromResult(Workspaces.SingleOrDefault(item => item.Key == key));

        public Task<App?> FindAppAsync(
            Guid workspaceId,
            string key,
            CancellationToken cancellationToken) =>
            Task.FromResult(Apps.SingleOrDefault(
                item => item.WorkspaceId == workspaceId && item.Key == key));

        public Task<Realm?> FindRealmAsync(
            Guid workspaceId,
            string key,
            CancellationToken cancellationToken) =>
            Task.FromResult(Realms.SingleOrDefault(
                item => item.WorkspaceId == workspaceId && item.Key == key));

        public Task<AppEnvironment?> FindEnvironmentAsync(
            Guid appId,
            string key,
            CancellationToken cancellationToken) =>
            Task.FromResult(Environments.SingleOrDefault(
                item => item.AppId == appId && item.Key == key));

        public Task<IntegrationClient?> FindIntegrationClientAsync(
            Guid appEnvironmentId,
            string key,
            CancellationToken cancellationToken) =>
            Task.FromResult(IntegrationClients.SingleOrDefault(
                item => item.AppEnvironmentId == appEnvironmentId && item.Key == key));

        public Task<IReadOnlyList<string>> GetIntegrationClientPermissionsAsync(
            Guid integrationClientId,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>(Permissions
                .Where(item => item.IntegrationClientId == integrationClientId)
                .Select(item => item.Value)
                .Order(StringComparer.Ordinal)
                .ToArray());

        public Task<ApplicationClient?> FindApplicationClientAsync(
            Guid appEnvironmentId,
            string key,
            CancellationToken cancellationToken) =>
            Task.FromResult(ApplicationClients.SingleOrDefault(
                item => item.AppEnvironmentId == appEnvironmentId && item.Key == key));

        public void Add(Workspace workspace) => Workspaces.Add(workspace);
        public void Add(App app) => Apps.Add(app);
        public void Add(Realm realm) => Realms.Add(realm);
        public void Add(AppEnvironment environment) => Environments.Add(environment);
        public void StoreConfiguration(
            AppEnvironment environment,
            AppEnvironmentConfiguration configuration,
            DateTimeOffset updatedAt)
        {
            Configurations[environment.Id] = configuration;
            environment.StoreProtectedConfiguration(
                2,
                new byte[12],
                [1],
                new byte[16],
                updatedAt);
        }
        public void Add(IntegrationClient integrationClient) =>
            IntegrationClients.Add(integrationClient);
        public void Add(IntegrationClientPermission permission) => Permissions.Add(permission);
        public void Add(IntegrationClientSecret secret) => Secrets.Add(secret);
        public void Add(ApplicationClient applicationClient) =>
            ApplicationClients.Add(applicationClient);

        public Task SaveChangesAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        private sealed class InMemoryTransaction : IAccessTopologyTransaction
        {
            public Task CommitAsync(CancellationToken cancellationToken) => Task.CompletedTask;
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}
