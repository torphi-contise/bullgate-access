using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Bootstrap;

/// <summary>
/// Idempotent persistence boundary used to resolve and apply manifest topology by
/// natural keys.
/// </summary>
public interface IAccessTopologyStore
{
    /// <summary>
    /// Opens the installation-wide single-writer transaction used by one bootstrap run.
    /// </summary>
    Task<IAccessTopologyTransaction> BeginBootstrapTransactionAsync(
        CancellationToken cancellationToken);

    Task<Workspace?> FindWorkspaceAsync(string key, CancellationToken cancellationToken);

    Task<App?> FindAppAsync(
        Guid workspaceId,
        string key,
        CancellationToken cancellationToken);

    Task<Realm?> FindRealmAsync(
        Guid workspaceId,
        string key,
        CancellationToken cancellationToken);

    Task<AppEnvironment?> FindEnvironmentAsync(
        Guid appId,
        string key,
        CancellationToken cancellationToken);

    Task<IntegrationClient?> FindIntegrationClientAsync(
        Guid appEnvironmentId,
        string key,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<string>> GetIntegrationClientPermissionsAsync(
        Guid integrationClientId,
        CancellationToken cancellationToken);

    Task<ApplicationClient?> FindApplicationClientAsync(
        Guid appEnvironmentId,
        string key,
        CancellationToken cancellationToken);

    void Add(Workspace workspace);
    void Add(App app);
    void Add(Realm realm);
    void Add(AppEnvironment environment);
    void StoreConfiguration(
        AppEnvironment environment,
        AppEnvironmentConfiguration configuration,
        DateTimeOffset updatedAt);
    void Add(IntegrationClient integrationClient);
    void Add(IntegrationClientPermission permission);
    void Add(IntegrationClientSecret secret);
    void Add(ApplicationClient applicationClient);

    /// <summary>Flushes the complete reconciled graph inside the open transaction.</summary>
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Explicit bootstrap transaction that commits all topology/configuration changes or
/// rolls them back together.
/// </summary>
public interface IAccessTopologyTransaction : IAsyncDisposable
{
    /// <summary>
    /// Commits topology, permissions, credential hashes, and protected configuration
    /// together.
    /// </summary>
    Task CommitAsync(CancellationToken cancellationToken);
}
