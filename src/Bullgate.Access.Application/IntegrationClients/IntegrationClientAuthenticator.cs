using System.Collections.Frozen;
using System.Security.Cryptography;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.IntegrationClients;

/// <summary>
/// Authenticates an opaque server credential and returns its fixed tenancy scope and
/// permissions.
/// </summary>
public interface IIntegrationClientAuthenticator
{
    /// <summary>
    /// Validates one canonical opaque credential and returns its immutable server-derived
    /// scope, or <see langword="null"/> for every invalid credential condition.
    /// </summary>
    Task<IntegrationClientContext?> AuthenticateAsync(
        string? credentialToken,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Immutable tenant scope and permission set derived from an authenticated integration
/// credential. Callers must not replace these ids with request-provided values.
/// </summary>
/// <param name="IntegrationClientId">Authenticated client and credential owner.</param>
/// <param name="AppEnvironmentId">Environment fixed by the client topology.</param>
/// <param name="AppId">App containing the authenticated environment.</param>
/// <param name="RealmId">Identity boundary fixed by the environment.</param>
/// <param name="WorkspaceId">Top-level topology owner.</param>
/// <param name="Permissions">Immutable exact permission names granted to the client.</param>
public sealed record IntegrationClientContext(
    Guid IntegrationClientId,
    Guid AppEnvironmentId,
    Guid AppId,
    Guid RealmId,
    Guid WorkspaceId,
    IReadOnlySet<string> Permissions);

internal sealed class IntegrationClientAuthenticator(
    IIntegrationClientAuthenticationStore store,
    TimeProvider timeProvider) : IIntegrationClientAuthenticator
{
    public async Task<IntegrationClientContext?> AuthenticateAsync(
        string? credentialToken,
        CancellationToken cancellationToken = default)
    {
        if (!IntegrationClientCredentialToken.TryParse(
                credentialToken,
                out var credentialId,
                out var secret))
        {
            return null;
        }

        try
        {
            var candidate = await store.FindByCredentialIdAsync(
                credentialId,
                cancellationToken);
            if (candidate is null)
            {
                return null;
            }

            var now = timeProvider.GetUtcNow();
            // Reject the whole credential when any cryptographic, temporal, topology, or
            // permission invariant is invalid. Partial authentication is never useful.
            if (candidate.CredentialId != credentialId
                || candidate.HashAlgorithm != IntegrationClientSecret.Sha256V1
                || candidate.SecretHash.Length != SHA256.HashSizeInBytes
                || candidate.CreatedAt > now
                || candidate.ExpiresAt <= now
                || candidate.RevokedAt is not null
                || !candidate.IsScopeActive
                || candidate.Permissions.Any(permission => !AccessPermission.IsDefined(permission)))
            {
                return null;
            }

            Span<byte> presentedHash = stackalloc byte[SHA256.HashSizeInBytes];
            SHA256.HashData(secret, presentedHash);

            try
            {
                // Constant-time comparison avoids leaking useful information about the
                // stored secret hash through response timing.
                if (!CryptographicOperations.FixedTimeEquals(
                        presentedHash,
                        candidate.SecretHash))
                {
                    return null;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(presentedHash);
            }

            return new IntegrationClientContext(
                candidate.IntegrationClientId,
                candidate.AppEnvironmentId,
                candidate.AppId,
                candidate.RealmId,
                candidate.WorkspaceId,
                // An empty set is valid authentication. Endpoint authorization then
                // denies permission-protected routes with 403 rather than changing the
                // credential failure surface to 401.
                candidate.Permissions.ToFrozenSet(StringComparer.Ordinal));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
