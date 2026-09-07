namespace Bullgate.Access.Application.IntegrationClients;

/// <summary>
/// Resolves an integration credential id and secret hash to active topology and
/// permission state.
/// </summary>
public interface IIntegrationClientAuthenticationStore
{
    /// <summary>
    /// Resolves the complete stored authentication candidate by public credential id.
    /// Secret comparison remains an application-layer responsibility.
    /// </summary>
    Task<IntegrationClientAuthenticationCandidate?> FindByCredentialIdAsync(
        Guid credentialId,
        CancellationToken cancellationToken);
}

/// <summary>
/// Stored credential, topology activity, and permissions evaluated as one authentication
/// candidate.
/// </summary>
/// <remarks>
/// This projection contains a secret hash and must remain inside authentication code; it
/// is not a transport DTO or safe structured-log value.
/// </remarks>
/// <param name="CredentialId">Public lookup id parsed from the canonical token.</param>
/// <param name="IntegrationClientId">Client that owns the credential and grants.</param>
/// <param name="AppEnvironmentId">Environment fixed by that client.</param>
/// <param name="AppId">App containing the environment.</param>
/// <param name="RealmId">Identity boundary selected by the environment.</param>
/// <param name="WorkspaceId">Common owner of the app and realm.</param>
/// <param name="SecretHash">Stored hash used for constant-time authentication.</param>
/// <param name="HashAlgorithm">Versioned interpretation of the hash bytes.</param>
/// <param name="CreatedAt">Credential lifecycle creation time.</param>
/// <param name="ExpiresAt">Optional exclusive validity upper bound.</param>
/// <param name="RevokedAt">Optional explicit revocation time.</param>
/// <param name="IsScopeActive">Conjunction of client and topology-ancestor activity.</param>
/// <param name="Permissions">Deterministically ordered stored permission names.</param>
public sealed record IntegrationClientAuthenticationCandidate(
    Guid CredentialId,
    Guid IntegrationClientId,
    Guid AppEnvironmentId,
    Guid AppId,
    Guid RealmId,
    Guid WorkspaceId,
    byte[] SecretHash,
    string HashAlgorithm,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt,
    bool IsScopeActive,
    IReadOnlyList<string> Permissions);
