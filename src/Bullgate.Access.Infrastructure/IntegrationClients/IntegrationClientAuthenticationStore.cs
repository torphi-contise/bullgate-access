using Bullgate.Access.Application.IntegrationClients;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.IntegrationClients;

/// <summary>
/// Resolves one credential id to its hash, complete topology scope, activation state,
/// and permission set for application-layer authentication.
/// </summary>
/// <remarks>
/// Activity is evaluated across workspace, app, realm, environment, and client. A
/// disabled ancestor invalidates the credential without rewriting the secret row.
/// </remarks>
internal sealed class IntegrationClientAuthenticationStore(AccessDbContext dbContext)
    : IIntegrationClientAuthenticationStore
{
    public async Task<IntegrationClientAuthenticationCandidate?> FindByCredentialIdAsync(
        Guid credentialId,
        CancellationToken cancellationToken)
    {
        var rows = await (
            from secret in dbContext.IntegrationClientSecrets.AsNoTracking()
            join client in dbContext.IntegrationClients.AsNoTracking()
                on secret.IntegrationClientId equals client.Id
            join environment in dbContext.AppEnvironments.AsNoTracking()
                on client.AppEnvironmentId equals environment.Id
            join app in dbContext.Apps.AsNoTracking()
                on environment.AppId equals app.Id
            join realm in dbContext.Realms.AsNoTracking()
                on environment.RealmId equals realm.Id
            join workspace in dbContext.Workspaces.AsNoTracking()
                on environment.WorkspaceId equals workspace.Id
            join permission in dbContext.IntegrationClientPermissions.AsNoTracking()
                on client.Id equals permission.IntegrationClientId into permissions
            // Keep a credential with no permissions visible to authentication. An inner
            // join would make it indistinguishable from an unknown credential and would
            // hide its otherwise valid fixed scope from the validation layer.
            from permission in permissions.DefaultIfEmpty()
            where secret.Id == credentialId
            select new
            {
                CredentialId = secret.Id,
                client.Id,
                AppEnvironmentId = environment.Id,
                environment.AppId,
                environment.RealmId,
                environment.WorkspaceId,
                secret.SecretHash,
                secret.HashAlgorithm,
                secret.CreatedAt,
                secret.ExpiresAt,
                secret.RevokedAt,
                // Effective activity is derived, not copied from the credential row.
                // Disabling any topology ancestor quarantines every descendant credential
                // without changing its independent expiry or revocation audit state.
                IsScopeActive = client.IsActive
                    && environment.IsActive
                    && app.IsActive
                    && realm.IsActive
                    && workspace.IsActive,
                Permission = permission == null ? null : permission.Value,
            }).ToArrayAsync(cancellationToken);

        if (rows.Length == 0)
        {
            // Credential ids are public selectors. Unknown ids and structurally missing
            // topology both remain absence; neither path performs secret comparison.
            return null;
        }

        var candidate = rows[0];
        // The join repeats credential data once per permission. Resolve a deterministic
        // set here so authorization behavior does not depend on database row order.
        var resolvedPermissions = rows
            .Select(row => row.Permission)
            .OfType<string>()
            .Order(StringComparer.Ordinal)
            .ToArray();

        return new IntegrationClientAuthenticationCandidate(
            candidate.CredentialId,
            candidate.Id,
            candidate.AppEnvironmentId,
            candidate.AppId,
            candidate.RealmId,
            candidate.WorkspaceId,
            candidate.SecretHash,
            candidate.HashAlgorithm,
            candidate.CreatedAt,
            candidate.ExpiresAt,
            candidate.RevokedAt,
            candidate.IsScopeActive,
            resolvedPermissions);
    }
}
