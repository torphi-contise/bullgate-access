using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.Application.EmailPassword;

/// <summary>
/// Transactional persistence boundary for registration, password authentication,
/// session introspection/revocation, and password replacement.
/// </summary>
/// <remarks>
/// Implementations enforce realm-scoped identifier uniqueness and session purpose at
/// commit time. Application prechecks cannot replace database constraints or locks.
/// </remarks>
public interface IEmailPasswordAccessStore
{
    /// <summary>
    /// Finds active identity, password, registration, contact, and authenticator state
    /// for a normalized e-mail inside one realm.
    /// </summary>
    /// <remarks>This is a preliminary lookup; registration uniqueness is decided at commit.</remarks>
    Task<PasswordIdentityCandidate?> FindByEmailAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string normalizedEmail,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically persists the complete initial identity graph and translates a
    /// concurrent e-mail uniqueness loss into a false result.
    /// </summary>
    Task<bool> TryCreateRegistrationAsync(
        Identity identity,
        IdentityIdentifier identifier,
        PasswordCredential passwordCredential,
        RegistrationContext registrationContext,
        IdentitySession session,
        CancellationToken cancellationToken);

    /// <summary>Persists a newly issued login session for an existing identity.</summary>
    Task AddSessionAsync(IdentitySession session, CancellationToken cancellationToken);

    /// <summary>
    /// Finds session and current identity state in the target environment, including
    /// revoked or expired state needed for uniform introspection.
    /// </summary>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="tokenHash">Hash of the untrusted presented bearer.</param>
    /// <param name="cancellationToken">Cancels the persistence operation.</param>
    /// <returns>
    /// Current active-identity state, or <see langword="null"/> when no scoped candidate
    /// can safely be disclosed to the application layer.
    /// </returns>
    Task<SessionIntrospectionCandidate?> FindSessionAsync(
        Guid appEnvironmentId,
        byte[] tokenHash,
        CancellationToken cancellationToken);

    /// <summary>
    /// Idempotently marks the not-yet-revoked session matching a token hash in the
    /// target environment.
    /// </summary>
    /// <remarks>
    /// Absence and previous revocation are successful no-ops. Expiry is not a filter:
    /// an expired matching row may still receive its first explicit revocation time.
    /// Implementations preserve that first timestamp rather than rewriting it on retries.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="tokenHash">Hash of the untrusted presented bearer.</param>
    /// <param name="revokedAt">UTC time recorded only when the session was still unrevoked.</param>
    /// <param name="cancellationToken">Cancels the persistence operation.</param>
    Task RevokeSessionAsync(
        Guid appEnvironmentId,
        byte[] tokenHash,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically adds or replaces the password, consumes active reset tokens, and
    /// revokes every session except the current product session.
    /// </summary>
    /// <remarks>
    /// The expected password hash is an optimistic concurrency condition. A mismatch
    /// means another request changed the credential after it was read, so the store must
    /// leave the credential, reset tokens, and sessions unchanged.
    /// </remarks>
    /// <param name="identityId">Identity whose password credential is being changed.</param>
    /// <param name="currentSessionId">Authorizing product session that remains active.</param>
    /// <param name="expectedPasswordHash">Password hash observed before this operation, or <see langword="null"/> when adding the first password.</param>
    /// <param name="passwordHash">New encoded password credential.</param>
    /// <param name="changedAt">UTC timestamp shared by the credential and revocation changes.</param>
    /// <param name="cancellationToken">Cancels the persistence operation.</param>
    /// <returns><see langword="true"/> when the expected credential state matched and the complete mutation committed; otherwise, <see langword="false"/>.</returns>
    Task<bool> TrySetPasswordAndRevokeOtherSessionsAsync(
        Guid identityId,
        Guid currentSessionId,
        string? expectedPasswordHash,
        string passwordHash,
        DateTimeOffset changedAt,
        CancellationToken cancellationToken);
}

/// <summary>Identity, password, registration, and authenticator state resolved by email.</summary>
public sealed record PasswordIdentityCandidate(
    Guid IdentityId,
    string NormalizedEmail,
    string PasswordHash,
    bool HasOpenRegistrationContext,
    AccessAuthenticatorSnapshot Authenticators,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null);

/// <summary>Session and identity state required for introspection and password mutation.</summary>
/// <remarks>
/// The store intentionally retains expiry and revocation in this projection so the
/// application can collapse every inactive state into one public result.
/// </remarks>
/// <param name="SessionId">Durable session selector, not bearer authority.</param>
/// <param name="IdentityId">Owner of the scoped session.</param>
/// <param name="NormalizedEmail">Current canonical e-mail.</param>
/// <param name="ExpiresAt">UTC session inactivity boundary.</param>
/// <param name="RevokedAt">UTC first-revocation time, when present.</param>
/// <param name="Purpose">Registration or product authority class.</param>
/// <param name="Authenticators">Current authenticator availability.</param>
/// <param name="PasswordHash">Current encoded password credential when present.</param>
/// <param name="Phone">Optional current canonical phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone-possession proof time.</param>
public sealed record SessionIntrospectionCandidate(
    Guid SessionId,
    Guid IdentityId,
    string NormalizedEmail,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? RevokedAt,
    IdentitySessionPurpose Purpose,
    AccessAuthenticatorSnapshot Authenticators,
    string? PasswordHash,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null);
