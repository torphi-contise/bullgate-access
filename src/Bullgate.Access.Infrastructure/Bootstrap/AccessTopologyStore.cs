using System.Data;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Configuration;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Bullgate.Access.Infrastructure.Bootstrap;

/// <summary>
/// Resolves and persists declarative Access topology while holding the installation's
/// bootstrap transaction and protecting environment configuration before storage.
/// </summary>
/// <remarks>
/// Natural-key lookups make compatible manifest application idempotent. The advisory
/// lock makes the read-then-create sequence a single-writer operation across processes.
/// </remarks>
internal sealed class AccessTopologyStore(
    AccessDbContext dbContext,
    IAppEnvironmentConfigurationProtector configurationProtector)
    : IAccessTopologyStore
{
    public async Task<IAccessTopologyTransaction> BeginBootstrapTransactionAsync(
        CancellationToken cancellationToken)
    {
        var transaction = await dbContext.Database.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            cancellationToken);

        try
        {
            // The fixed, transaction-scoped key serializes every bootstrap writer for
            // this Access database. Entity uniqueness alone would reject duplicates but
            // could still leave a partially reconciled manifest after concurrent runs.
            await dbContext.Database.ExecuteSqlRawAsync(
                "SELECT pg_advisory_xact_lock(1101700001)",
                cancellationToken);
            return new AccessTopologyTransaction(transaction);
        }
        catch
        {
            await transaction.DisposeAsync();
            throw;
        }
    }

    public Task<Workspace?> FindWorkspaceAsync(
        string key,
        CancellationToken cancellationToken) =>
        dbContext.Workspaces.SingleOrDefaultAsync(
            workspace => workspace.Key == key,
            cancellationToken);

    public Task<App?> FindAppAsync(
        Guid workspaceId,
        string key,
        CancellationToken cancellationToken) =>
        dbContext.Apps.SingleOrDefaultAsync(
            app => app.WorkspaceId == workspaceId && app.Key == key,
            cancellationToken);

    public Task<Realm?> FindRealmAsync(
        Guid workspaceId,
        string key,
        CancellationToken cancellationToken) =>
        dbContext.Realms.SingleOrDefaultAsync(
            realm => realm.WorkspaceId == workspaceId && realm.Key == key,
            cancellationToken);

    public Task<AppEnvironment?> FindEnvironmentAsync(
        Guid appId,
        string key,
        CancellationToken cancellationToken) =>
        dbContext.AppEnvironments.SingleOrDefaultAsync(
            environment => environment.AppId == appId && environment.Key == key,
            cancellationToken);

    public Task<IntegrationClient?> FindIntegrationClientAsync(
        Guid appEnvironmentId,
        string key,
        CancellationToken cancellationToken) =>
        dbContext.IntegrationClients.SingleOrDefaultAsync(
            client => client.AppEnvironmentId == appEnvironmentId && client.Key == key,
            cancellationToken);

    public async Task<IReadOnlyList<string>> GetIntegrationClientPermissionsAsync(
        Guid integrationClientId,
        CancellationToken cancellationToken) =>
        await dbContext.IntegrationClientPermissions
            .AsNoTracking()
            .Where(permission => permission.IntegrationClientId == integrationClientId)
            .Select(permission => permission.Value)
            .OrderBy(value => value)
            .ToArrayAsync(cancellationToken);

    public Task<ApplicationClient?> FindApplicationClientAsync(
        Guid appEnvironmentId,
        string key,
        CancellationToken cancellationToken) =>
        dbContext.ApplicationClients.SingleOrDefaultAsync(
            client => client.AppEnvironmentId == appEnvironmentId && client.Key == key,
            cancellationToken);

    public void Add(Workspace workspace) => dbContext.Workspaces.Add(workspace);
    public void Add(App app) => dbContext.Apps.Add(app);
    public void Add(Realm realm) => dbContext.Realms.Add(realm);
    public void Add(AppEnvironment environment) => dbContext.AppEnvironments.Add(environment);

    public void StoreConfiguration(
        AppEnvironment environment,
        AppEnvironmentConfiguration configuration,
        DateTimeOffset updatedAt)
    {
        // Protection happens before EF tracks the encrypted fields. Plain provider
        // secrets exist only in the manifest object and are never assigned to columns.
        var protectedConfiguration = configurationProtector.Protect(
            environment.Id,
            configuration);
        environment.StoreProtectedConfiguration(
            protectedConfiguration.FormatVersion,
            protectedConfiguration.Nonce,
            protectedConfiguration.Ciphertext,
            protectedConfiguration.Tag,
            updatedAt);
    }

    public void Add(IntegrationClient integrationClient) =>
        dbContext.IntegrationClients.Add(integrationClient);

    public void Add(IntegrationClientPermission permission) =>
        dbContext.IntegrationClientPermissions.Add(permission);

    public void Add(IntegrationClientSecret secret) =>
        dbContext.IntegrationClientSecrets.Add(secret);

    public void Add(ApplicationClient applicationClient) =>
        dbContext.ApplicationClients.Add(applicationClient);

    public Task SaveChangesAsync(CancellationToken cancellationToken) =>
        dbContext.SaveChangesAsync(cancellationToken);

    private sealed class AccessTopologyTransaction(IDbContextTransaction transaction)
        : IAccessTopologyTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken) =>
            transaction.CommitAsync(cancellationToken);

        public ValueTask DisposeAsync() => transaction.DisposeAsync();
    }
}
