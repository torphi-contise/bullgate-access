using System.Security.Cryptography;
using Bullgate.Access.Application;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.IntegrationClients;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class IntegrationClientAuthenticationTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>
{
    [Fact]
    public async Task IssuedCredential_AuthenticatesWithScopeAndPermissionsFromPostgreSql()
    {
        await using var provider = await CreateServiceProviderAsync();

        BootstrapTopologyResult bootstrapResult;
        await using (var scope = provider.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            bootstrapResult = await handler.HandleAsync(
                CreateBootstrapCommand(Guid.NewGuid().ToString("N")));
        }

        var issuedCredential = Assert.Single(bootstrapResult.IssuedCredentials);

        await using var authenticationScope = provider.CreateAsyncScope();
        var authenticator = authenticationScope.ServiceProvider
            .GetRequiredService<IIntegrationClientAuthenticator>();

        var context = await authenticator.AuthenticateAsync(issuedCredential.Token);

        Assert.NotNull(context);
        Assert.Equal(issuedCredential.IntegrationClientId, context.IntegrationClientId);
        Assert.Contains(AccessPermission.ExecuteFlows, context.Permissions);
        Assert.Contains(AccessPermission.IntrospectSessions, context.Permissions);
        Assert.DoesNotContain(AccessPermission.BlockIdentities, context.Permissions);
        Assert.NotEqual(Guid.Empty, context.WorkspaceId);
        Assert.NotEqual(Guid.Empty, context.AppId);
        Assert.NotEqual(Guid.Empty, context.AppEnvironmentId);
        Assert.NotEqual(Guid.Empty, context.RealmId);
    }

    [Theory]
    [InlineData("workspace")]
    [InlineData("app")]
    [InlineData("realm")]
    [InlineData("environment")]
    [InlineData("integration-client")]
    public async Task InactiveTopologyNode_QuarantinesAndRestoresTheSameCredential(
        string node)
    {
        await using var provider = await CreateServiceProviderAsync();
        var bootstrapResult = await BootstrapAsync(
            provider,
            CreateBootstrapCommand(Guid.NewGuid().ToString("N")));
        var issuedCredential = Assert.Single(bootstrapResult.IssuedCredentials);
        var original = await AuthenticateAsync(provider, issuedCredential.Token);
        Assert.NotNull(original);
        var secretBefore = await ReadSecretAsync(provider, issuedCredential.CredentialId);

        await SetTopologyActivityAsync(provider, original, node, isActive: false);

        Assert.Null(await AuthenticateAsync(provider, issuedCredential.Token));
        var secretWhileInactive = await ReadSecretAsync(
            provider,
            issuedCredential.CredentialId);
        Assert.Equal(secretBefore.SecretHash, secretWhileInactive.SecretHash);
        Assert.Equal(secretBefore.CreatedAt, secretWhileInactive.CreatedAt);
        Assert.Equal(secretBefore.ExpiresAt, secretWhileInactive.ExpiresAt);
        Assert.Equal(secretBefore.RevokedAt, secretWhileInactive.RevokedAt);

        await SetTopologyActivityAsync(provider, original, node, isActive: true);

        var restored = await AuthenticateAsync(provider, issuedCredential.Token);
        Assert.NotNull(restored);
        Assert.Equal(original.IntegrationClientId, restored.IntegrationClientId);
        Assert.Equal(original.AppEnvironmentId, restored.AppEnvironmentId);
        Assert.Equal(original.AppId, restored.AppId);
        Assert.Equal(original.RealmId, restored.RealmId);
        Assert.Equal(original.WorkspaceId, restored.WorkspaceId);
        Assert.Equal(
            original.Permissions.Order(StringComparer.Ordinal),
            restored.Permissions.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task RotatedCredential_OldRevocationLeavesOnlyTheNewCredentialActive()
    {
        await using var provider = await CreateServiceProviderAsync();
        var command = CreateBootstrapCommand(Guid.NewGuid().ToString("N"));
        var bootstrapResult = await BootstrapAsync(provider, command);
        var originalCredential = Assert.Single(bootstrapResult.IssuedCredentials);
        var original = await AuthenticateAsync(provider, originalCredential.Token);
        Assert.NotNull(original);
        var rotatedToken = await AddCredentialAsync(
            provider,
            original.IntegrationClientId);

        var rotated = await AuthenticateAsync(provider, rotatedToken);
        Assert.NotNull(rotated);
        AssertSameContext(original, rotated);

        await RevokeCredentialAsync(provider, originalCredential.CredentialId);

        Assert.Null(await AuthenticateAsync(provider, originalCredential.Token));
        var survivor = await AuthenticateAsync(provider, rotatedToken);
        Assert.NotNull(survivor);
        AssertSameContext(original, survivor);

        var reapplied = await BootstrapAsync(provider, command);
        Assert.Empty(reapplied.IssuedCredentials);
        Assert.Null(await AuthenticateAsync(provider, originalCredential.Token));
        Assert.NotNull(await AuthenticateAsync(provider, rotatedToken));
    }

    [Fact]
    public async Task PermissionChanges_UpdateAuthorityWithoutInvalidatingTheCredential()
    {
        await using var provider = await CreateServiceProviderAsync();
        var bootstrapResult = await BootstrapAsync(
            provider,
            CreateBootstrapCommand(Guid.NewGuid().ToString("N")));
        var issuedCredential = Assert.Single(bootstrapResult.IssuedCredentials);
        var original = await AuthenticateAsync(provider, issuedCredential.Token);
        Assert.NotNull(original);
        Assert.Contains(AccessPermission.ExecuteFlows, original.Permissions);
        Assert.Contains(AccessPermission.IntrospectSessions, original.Permissions);

        await RemovePermissionAsync(
            provider,
            original.IntegrationClientId,
            AccessPermission.ExecuteFlows);

        var reduced = await AuthenticateAsync(provider, issuedCredential.Token);
        Assert.NotNull(reduced);
        Assert.DoesNotContain(AccessPermission.ExecuteFlows, reduced.Permissions);
        Assert.Contains(AccessPermission.IntrospectSessions, reduced.Permissions);
        Assert.Equal(original.IntegrationClientId, reduced.IntegrationClientId);

        await RemovePermissionAsync(
            provider,
            original.IntegrationClientId,
            AccessPermission.IntrospectSessions);

        var withoutPermissions = await AuthenticateAsync(provider, issuedCredential.Token);
        Assert.NotNull(withoutPermissions);
        Assert.Empty(withoutPermissions.Permissions);
        Assert.Equal(original.AppEnvironmentId, withoutPermissions.AppEnvironmentId);
        Assert.Equal(original.RealmId, withoutPermissions.RealmId);
    }

    private async Task<ServiceProvider> CreateServiceProviderAsync()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"ConnectionStrings:{Bullgate.Access.Infrastructure.DependencyInjection.ConnectionStringName}"] =
                    database.ConnectionString,
                ["Bullgate:MasterKey"] =
                    "QnVsbGdhdGUtZGV2ZWxvcG1lbnQtbWFzdGVyLWtleSE=",
            })
            .Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddAccessApplication();
        services.AddAccessInfrastructure(configuration);
        var provider = services.BuildServiceProvider();

        await using var scope = provider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await dbContext.Database.EnsureCreatedAsync();
        return provider;
    }

    private static async Task<BootstrapTopologyResult> BootstrapAsync(
        ServiceProvider provider,
        BootstrapTopologyCommand command)
    {
        await using var scope = provider.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
        return await handler.HandleAsync(command);
    }

    private static async Task<IntegrationClientContext?> AuthenticateAsync(
        ServiceProvider provider,
        string token)
    {
        await using var scope = provider.CreateAsyncScope();
        var authenticator = scope.ServiceProvider
            .GetRequiredService<IIntegrationClientAuthenticator>();
        return await authenticator.AuthenticateAsync(token);
    }

    private static async Task<IntegrationClientSecretSnapshot> ReadSecretAsync(
        ServiceProvider provider,
        Guid credentialId)
    {
        await using var scope = provider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        return await dbContext.IntegrationClientSecrets
            .AsNoTracking()
            .Where(secret => secret.Id == credentialId)
            .Select(secret => new IntegrationClientSecretSnapshot(
                secret.SecretHash,
                secret.CreatedAt,
                secret.ExpiresAt,
                secret.RevokedAt))
            .SingleAsync();
    }

    private static async Task<string> AddCredentialAsync(
        ServiceProvider provider,
        Guid integrationClientId)
    {
        var createdAt = DateTimeOffset.UtcNow;
        var credentialId = Guid.CreateVersion7(createdAt);
        var secret = Enumerable.Range(1, IntegrationClientCredentialToken.SecretByteCount)
            .Select(value => checked((byte)value))
            .ToArray();
        var token = IntegrationClientCredentialToken.Create(credentialId, secret);
        var secretHash = SHA256.HashData(secret);
        CryptographicOperations.ZeroMemory(secret);

        await using var scope = provider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        dbContext.IntegrationClientSecrets.Add(new IntegrationClientSecret(
            credentialId,
            integrationClientId,
            secretHash,
            IntegrationClientSecret.Sha256V1,
            createdAt));
        await dbContext.SaveChangesAsync();
        return token;
    }

    private static async Task RevokeCredentialAsync(
        ServiceProvider provider,
        Guid credentialId)
    {
        await using var scope = provider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var revokedAt = DateTimeOffset.UtcNow;
        var affected = await dbContext.IntegrationClientSecrets
            .Where(secret => secret.Id == credentialId)
            .ExecuteUpdateAsync(update => update.SetProperty(
                secret => secret.RevokedAt,
                revokedAt));
        Assert.Equal(1, affected);
    }

    private static async Task RemovePermissionAsync(
        ServiceProvider provider,
        Guid integrationClientId,
        string permission)
    {
        await using var scope = provider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var affected = await dbContext.IntegrationClientPermissions
            .Where(item => item.IntegrationClientId == integrationClientId
                && item.Value == permission)
            .ExecuteDeleteAsync();
        Assert.Equal(1, affected);
    }

    private static void AssertSameContext(
        IntegrationClientContext expected,
        IntegrationClientContext actual)
    {
        Assert.Equal(expected.IntegrationClientId, actual.IntegrationClientId);
        Assert.Equal(expected.AppEnvironmentId, actual.AppEnvironmentId);
        Assert.Equal(expected.AppId, actual.AppId);
        Assert.Equal(expected.RealmId, actual.RealmId);
        Assert.Equal(expected.WorkspaceId, actual.WorkspaceId);
        Assert.Equal(
            expected.Permissions.Order(StringComparer.Ordinal),
            actual.Permissions.Order(StringComparer.Ordinal));
    }

    private static async Task SetTopologyActivityAsync(
        ServiceProvider provider,
        IntegrationClientContext context,
        string node,
        bool isActive)
    {
        await using var scope = provider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var affected = node switch
        {
            "workspace" => await dbContext.Workspaces
                .Where(item => item.Id == context.WorkspaceId)
                .ExecuteUpdateAsync(update => update.SetProperty(
                    item => item.IsActive,
                    isActive)),
            "app" => await dbContext.Apps
                .Where(item => item.Id == context.AppId)
                .ExecuteUpdateAsync(update => update.SetProperty(
                    item => item.IsActive,
                    isActive)),
            "realm" => await dbContext.Realms
                .Where(item => item.Id == context.RealmId)
                .ExecuteUpdateAsync(update => update.SetProperty(
                    item => item.IsActive,
                    isActive)),
            "environment" => await dbContext.AppEnvironments
                .Where(item => item.Id == context.AppEnvironmentId)
                .ExecuteUpdateAsync(update => update.SetProperty(
                    item => item.IsActive,
                    isActive)),
            "integration-client" => await dbContext.IntegrationClients
                .Where(item => item.Id == context.IntegrationClientId)
                .ExecuteUpdateAsync(update => update.SetProperty(
                    item => item.IsActive,
                    isActive)),
            _ => throw new InvalidOperationException($"Unknown topology node '{node}'."),
        };
        Assert.Equal(1, affected);
    }

    private static BootstrapTopologyCommand CreateBootstrapCommand(string suffix) =>
        new(
            $"integration-tests-{suffix}",
            "Integration tests",
            [
                new BootstrapAppDefinition(
                    $"mobile-{suffix}",
                    "Mobile",
                    [new BootstrapRealmDefinition($"mobile-tests-{suffix}", "Mobile tests")],
                    [
                        new BootstrapEnvironmentDefinition(
                            "tests",
                            "Tests",
                            $"mobile-tests-{suffix}",
                            TestAccessPolicies.Create(),
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(
                                TestAccessPolicies.Create()),
                            TestEnvironmentConfigurations.DevelopmentBypass(
                                TestAccessPolicies.Create()),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "api",
                                    "API",
                                    [
                                        AccessPermission.ExecuteFlows,
                                        AccessPermission.IntrospectSessions,
                                    ]),
                            ],
                            []),
                    ]),
            ]);

    private sealed record IntegrationClientSecretSnapshot(
        byte[] SecretHash,
        DateTimeOffset CreatedAt,
        DateTimeOffset? ExpiresAt,
        DateTimeOffset? RevokedAt);
}
