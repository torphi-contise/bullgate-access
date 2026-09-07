using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class SocialAccessEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private static readonly int[] ProtocolVersion1 = [1];
    private const string ApplicationClientKey = "android-debug";
    private const string CapabilityHeader = "Bullgate-Flow-Capability";
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private string topologySuffix = null!;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await dbContext.Database.EnsureDeletedAsync();
            await dbContext.Database.EnsureCreatedAsync();
        }

        await BootstrapAsync(TestAccessPolicies.Create(phoneEnabled: false));
    }

    public async Task DisposeAsync()
    {
        client.Dispose();
        await api.DisposeAsync();
    }

    [Fact]
    public async Task Google_ReturnsConflictWhenAuthenticatorIsDisabled()
    {
        var response = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "authenticator-disabled",
            body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Apple_ReturnsConflictWithoutCreatingIdentityWhenAuthenticatorIsDisabled()
    {
        var response = await client.PostAsJsonAsync(
            "/v1/auth/apple",
            new { identityToken = "apple-token" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "authenticator-disabled",
            body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.Identities.AsNoTracking().AnyAsync());
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync());
    }

    [Theory]
    [InlineData(null, HttpStatusCode.BadRequest, "missing-token")]
    [InlineData("invalid", HttpStatusCode.Unauthorized, "invalid-token")]
    public async Task Google_RejectsMissingOrInvalidAccessTokenWithoutCreatingIdentity(
        string? accessToken,
        HttpStatusCode expectedStatus,
        string expectedError)
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            googleEnabled: true));

        var response = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { accessToken });

        Assert.Equal(expectedStatus, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(expectedError, body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.Identities.AsNoTracking().AnyAsync());
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync());
    }

    [Fact]
    public async Task Google_AccessTokenCreatesAndReusesProviderIdentity()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            googleEnabled: true));
        var email = $"google-access-{Guid.NewGuid():N}@example.test";
        var subject = $"google-access-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(email, subject, "Google Access User");

        var created = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { accessToken = "google-access-token" });

        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        using var createdBody = JsonDocument.Parse(
            await created.Content.ReadAsStringAsync());
        var identityId = createdBody.RootElement.GetProperty("identityId").GetGuid();
        Assert.True(createdBody.RootElement.GetProperty("isNew").GetBoolean());
        Assert.Equal(email, createdBody.RootElement.GetProperty("email").GetString());
        Assert.True(createdBody.RootElement.GetProperty("hasGoogle").GetBoolean());

        var login = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { accessToken = "google-access-token" });

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.False(loginBody.RootElement.GetProperty("isNew").GetBoolean());
        Assert.Equal(identityId, loginBody.RootElement.GetProperty("identityId").GetGuid());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var credential = await dbContext.SocialCredentials
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(SocialProvider.Google, credential.Provider);
        Assert.Equal(subject, credential.Subject);
    }

    [Fact]
    public async Task Google_CreatesVerifiedEmailIdentityAndLogsInByProviderSubject()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            googleEnabled: true));
        api.GoogleValidator.Assertion = new(
            "Google.User@Example.Test",
            "google-subject-1",
            "Google User");

        var created = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);

        using var createdBody = JsonDocument.Parse(
            await created.Content.ReadAsStringAsync());
        var createdRoot = createdBody.RootElement;
        var identityId = createdRoot.GetProperty("identityId").GetGuid();
        var sessionToken = createdRoot.GetProperty("sessionToken").GetString();
        Assert.True(createdRoot.GetProperty("isNew").GetBoolean());
        Assert.Equal("google.user@example.test", createdRoot.GetProperty("email").GetString());
        Assert.Equal("product", createdRoot.GetProperty("sessionPurpose").GetString());
        Assert.False(createdRoot.GetProperty("hasPassword").GetBoolean());
        Assert.True(createdRoot.GetProperty("hasGoogle").GetBoolean());
        Assert.Equal(JsonValueKind.Null, createdRoot.GetProperty("phone").ValueKind);
        Assert.Equal(
            JsonValueKind.Null,
            createdRoot.GetProperty("phoneVerifiedAt").ValueKind);
        Assert.Equal(
            "google.user@example.test",
            createdRoot.GetProperty("googleEmail").GetString());
        Assert.False(createdRoot.GetProperty("hasApple").GetBoolean());

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identifier = await dbContext.IdentityIdentifiers
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.Equal(IdentifierScheme.Email, identifier.Scheme);
            Assert.NotNull(identifier.VerifiedAt);
            Assert.Equal("google:email", identifier.VerificationMethod);

            var credential = await dbContext.SocialCredentials
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.Equal(SocialProvider.Google, credential.Provider);
            Assert.Equal("google-subject-1", credential.Subject);
            Assert.Equal("google.user@example.test", credential.Email);
            Assert.False(await dbContext.PasswordCredentials.AnyAsync(
                item => item.IdentityId == identityId));

            var phoneVerifiedAt = new DateTimeOffset(
                2026,
                9,
                2,
                20,
                0,
                0,
                TimeSpan.Zero);
            dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
                Guid.CreateVersion7(),
                identityId,
                identifier.RealmId,
                IdentifierScheme.Phone,
                "+5511987654321",
                phoneVerifiedAt,
                phoneVerifiedAt,
                "sms"));
            await dbContext.SaveChangesAsync();
        }

        var login = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using (var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync()))
        {
            var root = loginBody.RootElement;
            Assert.False(root.GetProperty("isNew").GetBoolean());
            Assert.Equal(identityId, root.GetProperty("identityId").GetGuid());
            Assert.Equal(
                "+5511987654321",
                root.GetProperty("phone").GetString());
            Assert.Equal(
                new DateTimeOffset(2026, 9, 2, 20, 0, 0, TimeSpan.Zero),
                root.GetProperty("phoneVerifiedAt").GetDateTimeOffset());
        }

        var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken });
        Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
        using (var introspectionBody = JsonDocument.Parse(
            await introspection.Content.ReadAsStringAsync()))
        {
            var root = introspectionBody.RootElement;
            Assert.True(root.GetProperty("active").GetBoolean());
            Assert.True(root.GetProperty("hasGoogle").GetBoolean());
            Assert.Equal(
                "+5511987654321",
                root.GetProperty("phone").GetString());
            Assert.Equal(
                new DateTimeOffset(2026, 9, 2, 20, 0, 0, TimeSpan.Zero),
                root.GetProperty("phoneVerifiedAt").GetDateTimeOffset());
            Assert.Equal(
                "google.user@example.test",
                root.GetProperty("googleEmail").GetString());
        }
    }

    [Fact]
    public async Task Google_DoesNotAutoLinkWhenEmailAlreadyBelongsToPasswordIdentity()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            googleEnabled: true));
        var email = $"taken-{Guid.NewGuid():N}@example.test";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);

        api.GoogleValidator.Assertion = new(email.ToUpperInvariant(), "new-google-subject", null);

        var response = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("email-taken", body.RootElement.GetProperty("error").GetString());
    }

    [Theory]
    [InlineData(null, HttpStatusCode.BadRequest, "missing-token")]
    [InlineData("invalid", HttpStatusCode.Unauthorized, "invalid-token")]
    public async Task Apple_RejectsMissingOrInvalidIdentityTokenWithoutCreatingIdentity(
        string? identityToken,
        HttpStatusCode expectedStatus,
        string expectedError)
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            appleEnabled: true));

        var response = await client.PostAsJsonAsync(
            "/v1/auth/apple",
            new { identityToken });

        Assert.Equal(expectedStatus, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(expectedError, body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.Identities.AsNoTracking().AnyAsync());
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync());
    }

    [Fact]
    public async Task Apple_CreatesVerifiedEmailIdentityAndLogsInByProviderSubject()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            appleEnabled: true));
        api.AppleValidator.Assertion = new(
            "Apple.User@Example.Test",
            "apple-subject-1",
            null);

        var created = await client.PostAsJsonAsync(
            "/v1/auth/apple",
            new { identityToken = "apple-token" });

        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        using var createdBody = JsonDocument.Parse(
            await created.Content.ReadAsStringAsync());
        var createdRoot = createdBody.RootElement;
        var identityId = createdRoot.GetProperty("identityId").GetGuid();
        Assert.True(createdRoot.GetProperty("isNew").GetBoolean());
        Assert.Equal(
            "apple.user@example.test",
            createdRoot.GetProperty("email").GetString());
        Assert.True(createdRoot.GetProperty("hasApple").GetBoolean());
        Assert.Equal(
            "apple.user@example.test",
            createdRoot.GetProperty("appleEmail").GetString());
        Assert.False(createdRoot.GetProperty("hasGoogle").GetBoolean());

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identifier = await dbContext.IdentityIdentifiers
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.NotNull(identifier.VerifiedAt);
            Assert.Equal("apple:email", identifier.VerificationMethod);

            var credential = await dbContext.SocialCredentials
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.Equal(SocialProvider.Apple, credential.Provider);
            Assert.Equal("apple-subject-1", credential.Subject);
        }

        var login = await client.PostAsJsonAsync(
            "/v1/auth/apple",
            new { identityToken = "apple-token" });

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.False(loginBody.RootElement.GetProperty("isNew").GetBoolean());
        Assert.Equal(
            identityId,
            loginBody.RootElement.GetProperty("identityId").GetGuid());
    }

    [Fact]
    public async Task Google_LoginKeepsIdentityWhenProviderEmailChanges()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            googleEnabled: true));
        var originalEmail = $"original-{Guid.NewGuid():N}@example.test";
        const string subject = "stable-google-subject";
        api.GoogleValidator.Assertion = new(originalEmail, subject, "Google User");

        var created = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        created.EnsureSuccessStatusCode();
        using var createdBody = JsonDocument.Parse(
            await created.Content.ReadAsStringAsync());
        var identityId = createdBody.RootElement.GetProperty("identityId").GetGuid();

        api.GoogleValidator.Assertion = new(
            $"changed-{Guid.NewGuid():N}@example.test",
            subject,
            "Google User");
        var login = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.False(loginBody.RootElement.GetProperty("isNew").GetBoolean());
        Assert.Equal(
            identityId,
            loginBody.RootElement.GetProperty("identityId").GetGuid());
        Assert.Equal(
            originalEmail,
            loginBody.RootElement.GetProperty("email").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(1, await dbContext.Identities.AsNoTracking().CountAsync());
    }

    [Theory]
    [InlineData("google")]
    [InlineData("apple")]
    public async Task SocialAuthentication_WithPhoneEnabled_ResumesOnePendingRegistration(
        string provider)
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: true,
            phoneRequired: false,
            googleEnabled: true,
            appleEnabled: true));
        var subject = $"pending-{provider}-subject-{Guid.NewGuid():N}";
        var email = $"pending-{provider}-{Guid.NewGuid():N}@example.test";
        SetSocialAssertion(provider, email, subject);

        using var created = await AuthenticateAsync(provider);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        using var createdBody = JsonDocument.Parse(
            await created.Content.ReadAsStringAsync());
        var createdRoot = createdBody.RootElement;
        var identityId = createdRoot.GetProperty("identityId").GetGuid();
        var firstSessionToken = createdRoot.GetProperty("sessionToken").GetString();
        Assert.True(createdRoot.GetProperty("isNew").GetBoolean());
        Assert.Equal(
            "registration",
            createdRoot.GetProperty("sessionPurpose").GetString());

        using var resumed = await AuthenticateAsync(provider);
        Assert.Equal(HttpStatusCode.OK, resumed.StatusCode);
        using var resumedBody = JsonDocument.Parse(
            await resumed.Content.ReadAsStringAsync());
        var resumedRoot = resumedBody.RootElement;
        var resumedSessionToken = resumedRoot.GetProperty("sessionToken").GetString();
        Assert.False(resumedRoot.GetProperty("isNew").GetBoolean());
        Assert.Equal(identityId, resumedRoot.GetProperty("identityId").GetGuid());
        Assert.Equal(
            "registration",
            resumedRoot.GetProperty("sessionPurpose").GetString());
        Assert.NotEqual(firstSessionToken, resumedSessionToken);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var context = await dbContext.RegistrationContexts
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(RegistrationContextStatus.Open, context.Status);

        var credential = await dbContext.SocialCredentials
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(provider, credential.Provider);
        Assert.Equal(subject, credential.Subject);
        Assert.Equal(
            2,
            await dbContext.IdentitySessions.AsNoTracking().CountAsync(
                session => session.IdentityId == identityId
                    && session.Purpose == IdentitySessionPurpose.Registration
                    && session.RevokedAt == null));
    }

    [Fact]
    public async Task Google_OptionalPhoneSkipPromotesRegistrationAndFutureLoginToProduct()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: true,
            phoneRequired: false,
            googleEnabled: true));
        api.GoogleValidator.Assertion = new(
            $"promoted-google-{Guid.NewGuid():N}@example.test",
            $"promoted-google-subject-{Guid.NewGuid():N}",
            "Promoted Google User");

        using var created = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        created.EnsureSuccessStatusCode();
        using var createdBody = JsonDocument.Parse(
            await created.Content.ReadAsStringAsync());
        var identityId = createdBody.RootElement.GetProperty("identityId").GetGuid();
        var firstRegistrationToken = createdBody.RootElement
            .GetProperty("sessionToken")
            .GetString();
        Assert.Equal(
            "registration",
            createdBody.RootElement.GetProperty("sessionPurpose").GetString());

        using var resumed = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        resumed.EnsureSuccessStatusCode();
        using var resumedBody = JsonDocument.Parse(
            await resumed.Content.ReadAsStringAsync());
        var resumedRegistrationToken = resumedBody.RootElement
            .GetProperty("sessionToken")
            .GetString();
        Assert.Equal(
            "registration",
            resumedBody.RootElement.GetProperty("sessionPurpose").GetString());

        using var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = ProtocolVersion1,
                intent = "continueRegistration",
                applicationClientKey = ApplicationClientKey,
                sessionToken = firstRegistrationToken,
            });
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startedBody = JsonDocument.Parse(
            await started.Content.ReadAsStringAsync());
        var startedRoot = startedBody.RootElement;
        var capability = startedRoot.GetProperty("flowCapability").GetString();
        var snapshot = startedRoot.GetProperty("snapshot");
        var flowId = snapshot.GetProperty("flowId").GetGuid();
        var skipAction = FindAction(snapshot, "skipRegistration");

        using var completed = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = snapshot.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = skipAction.GetProperty("id").GetGuid(),
                    type = "skipRegistration",
                },
            });
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);
        using var completedBody = JsonDocument.Parse(
            await completed.Content.ReadAsStringAsync());
        var completedRoot = completedBody.RootElement;
        Assert.Equal(
            "completed",
            completedRoot.GetProperty("snapshot").GetProperty("status").GetString());
        var issuedSession = completedRoot.GetProperty("issuedSession");
        var productSessionToken = issuedSession.GetProperty("sessionToken").GetString();
        Assert.Equal("product", issuedSession.GetProperty("purpose").GetString());

        await AssertSessionAsync(firstRegistrationToken, active: false);
        await AssertSessionAsync(resumedRegistrationToken, active: false);
        await AssertSessionAsync(
            productSessionToken,
            active: true,
            expectedPurpose: "product",
            expectedIdentityId: identityId);

        using var login = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        login.EnsureSuccessStatusCode();
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.False(loginBody.RootElement.GetProperty("isNew").GetBoolean());
        Assert.Equal(identityId, loginBody.RootElement.GetProperty("identityId").GetGuid());
        Assert.Equal(
            "product",
            loginBody.RootElement.GetProperty("sessionPurpose").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var context = await dbContext.RegistrationContexts
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(RegistrationContextStatus.Completed, context.Status);
    }

    private Task<HttpResponseMessage> AuthenticateAsync(string provider) =>
        provider switch
        {
            SocialProvider.Google => client.PostAsJsonAsync(
                "/v1/auth/google",
                new { idToken = "google-token" }),
            SocialProvider.Apple => client.PostAsJsonAsync(
                "/v1/auth/apple",
                new { identityToken = "apple-token" }),
            _ => throw new ArgumentOutOfRangeException(nameof(provider), provider, null),
        };

    private void SetSocialAssertion(string provider, string email, string subject)
    {
        if (provider == SocialProvider.Google)
        {
            api.GoogleValidator.Assertion = new(email, subject, "Social User");
            return;
        }

        if (provider == SocialProvider.Apple)
        {
            api.AppleValidator.Assertion = new(email, subject, null);
            return;
        }

        throw new ArgumentOutOfRangeException(nameof(provider), provider, null);
    }

    private async Task AssertSessionAsync(
        string? sessionToken,
        bool active,
        string? expectedPurpose = null,
        Guid? expectedIdentityId = null)
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken });
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        Assert.Equal(active, root.GetProperty("active").GetBoolean());
        if (expectedPurpose is not null)
        {
            Assert.Equal(expectedPurpose, root.GetProperty("sessionPurpose").GetString());
        }
        if (expectedIdentityId is not null)
        {
            Assert.Equal(expectedIdentityId.Value, root.GetProperty("identityId").GetGuid());
        }
    }

    private async Task<HttpResponseMessage> SendWithCapabilityAsync(
        HttpMethod method,
        string path,
        string? capability,
        object body)
    {
        using var request = new HttpRequestMessage(method, path)
        {
            Content = JsonContent.Create(body),
        };
        request.Headers.TryAddWithoutValidation(CapabilityHeader, capability);
        return await client.SendAsync(request);
    }

    private static JsonElement FindAction(JsonElement snapshot, string type) =>
        Assert.Single(
            snapshot.GetProperty("actions").EnumerateArray(),
            action => string.Equals(
                action.GetProperty("type").GetString(),
                type,
                StringComparison.Ordinal));

    private async Task ConfigurePolicyAsync(AppAccessPolicy policy)
    {
        var result = await BootstrapAsync(policy);
        Assert.Empty(result.IssuedCredentials);
    }

    private async Task<BootstrapTopologyResult> BootstrapAsync(AppAccessPolicy policy)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
        topologySuffix ??= Guid.NewGuid().ToString("N");
        var result = await handler.HandleAsync(CreateBootstrapCommand(topologySuffix, policy));
        if (result.IssuedCredentials.Count > 0)
        {
            var credential = Assert.Single(result.IssuedCredentials);
            client = api.CreateClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", credential.Token);
        }

        return result;
    }

    private static BootstrapTopologyCommand CreateBootstrapCommand(
        string suffix,
        AppAccessPolicy accessPolicy) =>
        new(
            $"social-access-{suffix}",
            "Social access tests",
            [
                new BootstrapAppDefinition(
                    $"baybo-{suffix}",
                    "BAYBO",
                    [new BootstrapRealmDefinition($"realm-{suffix}", "BAYBO tests")],
                    [
                        new BootstrapEnvironmentDefinition(
                            "tests",
                            "Tests",
                            $"realm-{suffix}",
                            accessPolicy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(accessPolicy),
                            TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "api",
                                    "API",
                                    [
                                        AccessPermission.ExecuteFlows,
                                        AccessPermission.IntrospectSessions,
                                        AccessPermission.RevokeCurrentSession,
                                    ]),
                            ],
                            [
                                new BootstrapApplicationClientDefinition(
                                    ApplicationClientKey,
                                    "Android debug",
                                    ApplicationClientPlatform.Android,
                                    "app.baybo",
                                    "sha256:fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
                                    "92TvTC0UfaA",
                                    JsonSerializer.SerializeToElement(new { })),
                            ]),
                    ]),
            ]);
}
