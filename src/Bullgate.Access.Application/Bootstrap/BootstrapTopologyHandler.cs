using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Bootstrap;

/// <summary>
/// Validates and transactionally reconciles a declarative topology manifest by stable
/// natural keys without silently changing security-sensitive existing resources.
/// </summary>
public sealed class BootstrapTopologyHandler(
    IAccessTopologyStore store,
    IIntegrationClientCredentialIssuer credentialIssuer,
    TimeProvider timeProvider)
{
    /// <summary>
    /// Validates and applies the declared topology in one installation-wide bootstrap
    /// transaction.
    /// </summary>
    /// <returns>
    /// Stable ids for resolved resources and one-time credentials only for integration
    /// clients created by this successful run.
    /// </returns>
    /// <remarks>
    /// Resources omitted from <paramref name="command"/> are not deleted. Existing
    /// integration credentials are neither recovered nor rotated by reconciliation.
    /// </remarks>
    public async Task<BootstrapTopologyResult> HandleAsync(
        BootstrapTopologyCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        // Reject the entire manifest before taking the cross-process writer lock. This
        // keeps deterministic shape/policy errors outside the transaction and guarantees
        // that reconciliation below may rely on all declared references and invariants.
        Validate(command);

        var resources = new List<BootstrapResolvedResource>();
        var issuedCredentials = new List<IssuedIntegrationClientCredential>();
        var now = timeProvider.GetUtcNow();

        // Topology and encrypted configuration form one security boundary; partial
        // bootstrap would leave permissions and policy describing different states.
        await using var transaction =
            await store.BeginBootstrapTransactionAsync(cancellationToken);

        var workspace = await ResolveWorkspaceAsync(command, now, resources, cancellationToken);

        foreach (var appDefinition in command.Apps)
        {
            var appPath = $"{command.WorkspaceKey}/{appDefinition.Key}";
            var app = await ResolveAppAsync(
                workspace,
                appDefinition,
                appPath,
                now,
                resources,
                cancellationToken);

            var realms = new Dictionary<string, Realm>(StringComparer.Ordinal);
            foreach (var realmDefinition in appDefinition.Realms)
            {
                var realmPath = $"{appPath}/realms/{realmDefinition.Key}";
                var realm = await ResolveRealmAsync(
                    workspace,
                    realmDefinition,
                    realmPath,
                    now,
                    resources,
                    cancellationToken);
                realms.Add(realmDefinition.Key, realm);
            }

            foreach (var environmentDefinition in appDefinition.Environments)
            {
                var environmentPath = $"{appPath}/{environmentDefinition.Key}";
                var environment = await ResolveEnvironmentAsync(
                    app,
                    realms[environmentDefinition.RealmKey],
                    environmentDefinition,
                    environmentPath,
                    now,
                    resources,
                    cancellationToken);

                await ResolveIntegrationClientsAsync(
                    environment,
                    environmentDefinition,
                    environmentPath,
                    now,
                    resources,
                    issuedCredentials,
                    cancellationToken);

                await ResolveApplicationClientsAsync(
                    environment,
                    environmentDefinition,
                    environmentPath,
                    now,
                    cancellationToken);
            }
        }

        await store.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new BootstrapTopologyResult(workspace.Id, resources, issuedCredentials);
    }

    private async Task<Workspace> ResolveWorkspaceAsync(
        BootstrapTopologyCommand definition,
        DateTimeOffset now,
        List<BootstrapResolvedResource> resources,
        CancellationToken cancellationToken)
    {
        var workspace = await store.FindWorkspaceAsync(
            definition.WorkspaceKey,
            cancellationToken);

        if (workspace is null)
        {
            workspace = new Workspace(
                Guid.CreateVersion7(),
                definition.WorkspaceKey,
                definition.WorkspaceName,
                now);
            store.Add(workspace);
        }
        else
        {
            EnsureMatch(
                definition.WorkspaceKey,
                "workspace",
                ("name", definition.WorkspaceName, workspace.Name),
                ("active", true, workspace.IsActive));
        }

        resources.Add(new BootstrapResolvedResource("workspace", definition.WorkspaceKey, workspace.Id));
        return workspace;
    }

    private async Task<App> ResolveAppAsync(
        Workspace workspace,
        BootstrapAppDefinition definition,
        string path,
        DateTimeOffset now,
        List<BootstrapResolvedResource> resources,
        CancellationToken cancellationToken)
    {
        var app = await store.FindAppAsync(workspace.Id, definition.Key, cancellationToken);

        if (app is null)
        {
            app = new App(Guid.CreateVersion7(), workspace.Id, definition.Key, definition.Name, now);
            store.Add(app);
        }
        else
        {
            EnsureMatch(
                path,
                "app",
                ("workspaceId", workspace.Id, app.WorkspaceId),
                ("name", definition.Name, app.Name),
                ("active", true, app.IsActive));
        }

        resources.Add(new BootstrapResolvedResource("app", path, app.Id));
        return app;
    }

    private async Task<Realm> ResolveRealmAsync(
        Workspace workspace,
        BootstrapRealmDefinition definition,
        string path,
        DateTimeOffset now,
        List<BootstrapResolvedResource> resources,
        CancellationToken cancellationToken)
    {
        var realm = await store.FindRealmAsync(workspace.Id, definition.Key, cancellationToken);

        if (realm is null)
        {
            realm = new Realm(Guid.CreateVersion7(), workspace.Id, definition.Key, definition.Name, now);
            store.Add(realm);
        }
        else
        {
            EnsureMatch(
                path,
                "realm",
                ("workspaceId", workspace.Id, realm.WorkspaceId),
                ("name", definition.Name, realm.Name),
                ("active", true, realm.IsActive));
        }

        resources.Add(new BootstrapResolvedResource("realm", path, realm.Id));
        return realm;
    }

    private async Task<AppEnvironment> ResolveEnvironmentAsync(
        App app,
        Realm realm,
        BootstrapEnvironmentDefinition definition,
        string path,
        DateTimeOffset now,
        List<BootstrapResolvedResource> resources,
        CancellationToken cancellationToken)
    {
        var environment = await store.FindEnvironmentAsync(app.Id, definition.Key, cancellationToken);

        if (environment is null)
        {
            environment = new AppEnvironment(
                Guid.CreateVersion7(),
                app.WorkspaceId,
                app.Id,
                realm.Id,
                definition.Key,
                definition.Name,
                definition.AccessPolicy,
                now,
                definition.RecoveryPolicy.PasswordRecoveryUrl);
            store.Add(environment);
        }
        else
        {
            // Environment policy is intentionally mutable without changing the stable
            // environment identity. Parent scope, realm binding, name, and activity are
            // compatibility boundaries and therefore must still match.
            EnsureMatch(
                path,
                "environment",
                ("workspaceId", app.WorkspaceId, environment.WorkspaceId),
                ("appId", app.Id, environment.AppId),
                ("realmId", realm.Id, environment.RealmId),
                ("name", definition.Name, environment.Name),
                ("active", true, environment.IsActive));
            environment.ConfigureAccess(definition.AccessPolicy);
            environment.ConfigurePasswordRecoveryUrl(
                definition.RecoveryPolicy.PasswordRecoveryUrl);
        }

        store.StoreConfiguration(environment, definition.Configuration, now);

        resources.Add(new BootstrapResolvedResource("environment", path, environment.Id));
        return environment;
    }

    private async Task ResolveIntegrationClientsAsync(
        AppEnvironment environment,
        BootstrapEnvironmentDefinition environmentDefinition,
        string environmentPath,
        DateTimeOffset now,
        List<BootstrapResolvedResource> resources,
        List<IssuedIntegrationClientCredential> issuedCredentials,
        CancellationToken cancellationToken)
    {
        foreach (var definition in environmentDefinition.IntegrationClients)
        {
            var path = $"{environmentPath}/integration-clients/{definition.Key}";
            var integrationClient = await store.FindIntegrationClientAsync(
                environment.Id,
                definition.Key,
                cancellationToken);

            if (integrationClient is null)
            {
                integrationClient = new IntegrationClient(
                    Guid.CreateVersion7(),
                    environment.Id,
                    definition.Key,
                    definition.Name,
                    now);
                store.Add(integrationClient);

                foreach (var permission in definition.Permissions.Order(StringComparer.Ordinal))
                {
                    store.Add(new IntegrationClientPermission(integrationClient.Id, permission));
                }

                // The clear credential is returned exactly once, only when the client is
                // created. Re-running bootstrap never retrieves or rotates an old secret.
                var generated = credentialIssuer.Issue(now);
                store.Add(new IntegrationClientSecret(
                    generated.CredentialId,
                    integrationClient.Id,
                    generated.SecretHash,
                    generated.HashAlgorithm,
                    generated.CreatedAt));
                issuedCredentials.Add(new IssuedIntegrationClientCredential(
                    path,
                    integrationClient.Id,
                    generated.CredentialId,
                    generated.Token));
            }
            else
            {
                // Existing security-sensitive values must match the manifest. Bootstrap is
                // idempotent reconciliation, not an implicit permission mutation endpoint.
                EnsureMatch(
                    path,
                    "integration client",
                    ("environmentId", environment.Id, integrationClient.AppEnvironmentId),
                    ("name", definition.Name, integrationClient.Name),
                    ("active", true, integrationClient.IsActive));

                var actualPermissions = await store.GetIntegrationClientPermissionsAsync(
                    integrationClient.Id,
                    cancellationToken);
                EnsurePermissionsMatch(path, definition.Permissions, actualPermissions);
            }

            resources.Add(new BootstrapResolvedResource(
                "integrationClient",
                path,
                integrationClient.Id));
        }
    }

    private async Task ResolveApplicationClientsAsync(
        AppEnvironment environment,
        BootstrapEnvironmentDefinition environmentDefinition,
        string environmentPath,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        foreach (var definition in environmentDefinition.ApplicationClients)
        {
            var path = $"{environmentPath}/application-clients/{definition.Key}";
            var applicationClient = await store.FindApplicationClientAsync(
                environment.Id,
                definition.Key,
                cancellationToken);

            if (applicationClient is null)
            {
                applicationClient = new ApplicationClient(
                    Guid.CreateVersion7(),
                    environment.Id,
                    definition.Key,
                    definition.Name,
                    definition.Platform,
                    definition.ApplicationId,
                    definition.SigningIdentity,
                    definition.SmsRetrieverAppHash,
                    now);
                store.Add(applicationClient);
            }
            else
            {
                // Application clients are public build metadata, not secret principals.
                // Their stable key/id and environment scope remain fixed while release
                // metadata may be reconciled by a later manifest.
                EnsureMatch(
                    path,
                    "application client",
                    ("environmentId", environment.Id, applicationClient.AppEnvironmentId),
                    ("active", true, applicationClient.IsActive));
                applicationClient.Configure(
                    definition.Name,
                    definition.Platform,
                    definition.ApplicationId,
                    definition.SigningIdentity,
                    definition.SmsRetrieverAppHash);
            }
        }
    }

    private static void Validate(BootstrapTopologyCommand command)
    {
        TopologyValue.Key(command.WorkspaceKey, nameof(command.WorkspaceKey));
        TopologyValue.Name(command.WorkspaceName, nameof(command.WorkspaceName));
        RequireItems(command.Apps, "workspace.apps");
        EnsureDistinct(command.Apps.Select(app => app.Key), "workspace.apps");

        // Realm keys are workspace-wide identity-partition names even though the
        // manifest nests declarations under apps. Rejecting cross-app reuse prevents
        // visually separate declarations from referring to one identity namespace.
        var realmKeys = new HashSet<string>(StringComparer.Ordinal);

        foreach (var app in command.Apps)
        {
            var appPath = $"workspace.apps[{app.Key}]";
            TopologyValue.Key(app.Key, appPath);
            TopologyValue.Name(app.Name, appPath);
            RequireItems(app.Realms, $"{appPath}.realms");
            RequireItems(app.Environments, $"{appPath}.environments");
            EnsureDistinct(app.Realms.Select(realm => realm.Key), $"{appPath}.realms");
            EnsureDistinct(
                app.Environments.Select(environment => environment.Key),
                $"{appPath}.environments");

            var appRealmKeys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var realm in app.Realms)
            {
                TopologyValue.Key(realm.Key, $"{appPath}.realms.key");
                TopologyValue.Name(realm.Name, $"{appPath}.realms.name");
                appRealmKeys.Add(realm.Key);

                if (!realmKeys.Add(realm.Key))
                {
                    throw new BootstrapTopologyException(
                        $"Realm key '{realm.Key}' is declared by more than one app.");
                }
            }

            foreach (var environment in app.Environments)
            {
                var environmentPath = $"{appPath}.environments[{environment.Key}]";
                TopologyValue.Key(environment.Key, environmentPath);
                TopologyValue.Name(environment.Name, environmentPath);
                TopologyValue.Key(environment.RealmKey, $"{environmentPath}.realmKey");
                AppEnvironmentConfigurationValidator.Validate(environment.Configuration, environmentPath);

                if (!appRealmKeys.Contains(environment.RealmKey))
                {
                    throw new BootstrapTopologyException(
                        $"Environment '{environment.Key}' references undeclared realm "
                        + $"'{environment.RealmKey}'.");
                }


            }
        }
    }

    private static void RequireItems<T>(IReadOnlyList<T>? items, string path)
    {
        if (items is null || items.Count == 0)
        {
            throw new BootstrapTopologyException($"'{path}' must contain at least one item.");
        }
    }

    private static void EnsureDistinct(IEnumerable<string> values, string path)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (!seen.Add(value))
            {
                throw new BootstrapTopologyException(
                    $"'{path}' contains duplicate value '{value}'.");
            }
        }
    }

    private static void EnsurePermissionsMatch(
        string path,
        IReadOnlyList<string> expected,
        IReadOnlyList<string> actual)
    {
        var expectedSet = expected.Order(StringComparer.Ordinal).ToArray();
        var actualSet = actual.Order(StringComparer.Ordinal).ToArray();

        // Permissions are an exact security set, not additive desired state. Bootstrap
        // must never grant or revoke authority as a side effect of reapplying topology.
        if (!expectedSet.SequenceEqual(actualSet, StringComparer.Ordinal))
        {
            throw new BootstrapTopologyException(
                $"Existing integration client '{path}' has different permissions.");
        }
    }

    private static void EnsureMatch(
        string path,
        string resourceType,
        params (string Field, object? Expected, object? Actual)[] comparisons)
    {
        foreach (var comparison in comparisons)
        {
            if (!Equals(comparison.Expected, comparison.Actual))
            {
                // Natural keys find identity; they do not authorize renaming, moving, or
                // reactivating an existing resource to make a new manifest fit.
                throw new BootstrapTopologyException(
                    $"Existing {resourceType} '{path}' differs in '{comparison.Field}'.");
            }
        }
    }
}
