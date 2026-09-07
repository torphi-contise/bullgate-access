using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.Application.Identities;

/// <summary>
/// Transactional persistence boundary for mutations authorized by a current product
/// session.
/// </summary>
/// <remarks>
/// Implementations must validate session, environment, realm, and identity together.
/// Identity deletion also removes flows reachable through AccessFlowDataSubject and
/// must not depend on an external provider call. The identity UUID is never accepted
/// as deletion authority: the opaque product-session bearer selects it inside the
/// integration credential's fixed scope.
/// </remarks>
public interface ICurrentIdentityStore
{
    /// <summary>
    /// Resolves an active session and its current identity snapshot inside the target
    /// app environment.
    /// </summary>
    /// <remarks>
    /// The caller must still compare the returned realm and require product purpose;
    /// finding a token hash is not sufficient authorization for a mutation.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment to which the bearer must be bound.</param>
    /// <param name="sessionTokenHash">Hash of the untrusted presented bearer.</param>
    /// <param name="now">Current UTC time used for exclusive expiry.</param>
    /// <param name="cancellationToken">Cancels the preliminary query.</param>
    Task<CurrentIdentityCandidate?> FindBySessionAsync(
        Guid appEnvironmentId,
        byte[] sessionTokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the current email while serializing uniqueness and invalidating
    /// recovery artifacts tied to the previous address.
    /// </summary>
    /// <remarks>
    /// Session, identity, realm, environment, and purpose are revalidated in the
    /// transaction. A successful preliminary lookup is not authority to commit.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="identityId">Identity selected by the preliminary session lookup.</param>
    /// <param name="sessionId">Durable authorizing-session selector.</param>
    /// <param name="normalizedEmail">Canonical replacement primary e-mail.</param>
    /// <param name="now">UTC authorization and invalidation time.</param>
    /// <param name="cancellationToken">Cancels the mutation transaction.</param>
    Task<CurrentIdentityMutationStatus> TryChangeEmailAsync(
        Guid realmId,
        Guid appEnvironmentId,
        Guid identityId,
        Guid sessionId,
        string normalizedEmail,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Hard-deletes the authenticated identity and all attributable Access data in
    /// one Access database transaction.
    /// </summary>
    /// <remarks>
    /// The implementation must revalidate the bearer-selected session and identity
    /// under database locks. It removes complete flow graphs before the identity so
    /// restrictive evidence relationships cannot leave attributable snapshots behind;
    /// identity-owned identifiers, authenticators, sessions, registration state, and
    /// recovery artifacts may then follow database cascades.
    ///
    /// This operation does not delete a consumer profile, revoke an account at a social
    /// provider, or contact e-mail, SMS, and identity providers. Its atomic boundary is
    /// the Access database transaction only.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="sessionTokenHash">Hash of the untrusted presented product bearer.</param>
    /// <param name="now">Current UTC time used for session authorization.</param>
    /// <param name="cancellationToken">Cancels the local erasure transaction.</param>
    /// <returns>
    /// <see langword="true"/> only when one identity was deleted and the local
    /// transaction committed; otherwise <see langword="false"/> when the bearer and
    /// fixed scope did not authorize an active product identity.
    /// </returns>
    Task<bool> TryDeleteAsync(
        Guid realmId,
        Guid appEnvironmentId,
        byte[] sessionTokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken);
}

/// <summary>Realm-scoped product session and current identity projection.</summary>
/// <param name="IdentityId">Identity selected by the session.</param>
/// <param name="SessionId">Durable session selector, not bearer authority.</param>
/// <param name="RealmId">Identity realm independently checked against integration scope.</param>
/// <param name="Email">Current canonical primary e-mail.</param>
/// <param name="Phone">Optional current canonical phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone-possession proof time.</param>
/// <param name="ExpiresAt">UTC exclusive session inactivity boundary.</param>
/// <param name="Purpose">Registration or product authority class.</param>
/// <param name="Authenticators">Current authenticator availability.</param>
public sealed record CurrentIdentityCandidate(
    Guid IdentityId,
    Guid SessionId,
    Guid RealmId,
    string Email,
    string? Phone,
    DateTimeOffset? PhoneVerifiedAt,
    DateTimeOffset ExpiresAt,
    IdentitySessionPurpose Purpose,
    AccessAuthenticatorSnapshot Authenticators);

/// <summary>Transactional outcomes of a current-identity mutation.</summary>
public enum CurrentIdentityMutationStatus
{
    /// <summary>The requested mutation committed.</summary>
    Updated,

    /// <summary>Locked identity or authorizing session lost eligibility.</summary>
    IdentityNotFound,

    /// <summary>Realm-scoped normalized e-mail uniqueness rejected the replacement.</summary>
    EmailTaken,
}
