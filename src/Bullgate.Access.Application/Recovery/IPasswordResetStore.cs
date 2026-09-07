using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.Application.Recovery;

/// <summary>
/// Transactional store for anti-enumerable reset issuance and single-use token
/// consumption.
/// </summary>
public interface IPasswordResetStore
{
    /// <summary>
    /// Atomically verifies identity and environment eligibility, applies an optional
    /// issuance limit, and persists a new hashed reset token.
    /// </summary>
    /// <remarks>
    /// When supplied, the issuance constraint counts durable reset tokens for the
    /// identity across environments and recovery channels, regardless of later use.
    /// </remarks>
    /// <param name="token">New hashed bearer with identity and environment binding.</param>
    /// <param name="expectedNormalizedEmail">Optional exact current delivery ownership.</param>
    /// <param name="issueConstraint">Optional identity-wide durable-token issue limit.</param>
    /// <param name="cancellationToken">Cancels the issuance transaction.</param>
    Task<PasswordResetIssueStoreResult> TryIssueAsync(
        PasswordResetToken token,
        string? expectedNormalizedEmail,
        PasswordResetIssueConstraint? issueConstraint,
        CancellationToken cancellationToken);

    /// <summary>Retry-safely invalidates an active token without changing the password.</summary>
    /// <remarks>
    /// The successful update records the same <c>UsedAt</c> lifecycle field as normal
    /// reset consumption. That field ends authority but does not record why it ended.
    /// Expired tokens are already inactive and remain unchanged.
    /// </remarks>
    /// <returns>
    /// <see langword="true"/> when this call consumed the token; otherwise
    /// <see langword="false"/> when it was absent, expired, or already used.
    /// </returns>
    /// <param name="tokenId">Durable selector, not the clear reset bearer.</param>
    /// <param name="invalidatedAt">UTC consumption time strictly before expiry.</param>
    /// <param name="cancellationToken">Cancels the idempotent update.</param>
    Task<bool> TryInvalidateAsync(
        Guid tokenId,
        DateTimeOffset invalidatedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Finds an eligible identity and app name for an anti-enumerable public e-mail
    /// recovery request.
    /// </summary>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment that owns recovery configuration.</param>
    /// <param name="normalizedEmail">Canonical e-mail used only for candidate discovery.</param>
    /// <param name="cancellationToken">Cancels the preliminary query.</param>
    Task<PasswordResetEmailCandidate?> FindByEmailAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string normalizedEmail,
        CancellationToken cancellationToken);

    /// <summary>
    /// Finds recovery delivery data for a specific identity selected by trusted
    /// orchestration, such as an AccessFlow conflict-resolution action.
    /// </summary>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment that owns recovery configuration.</param>
    /// <param name="identityId">Identity selected from trusted server state.</param>
    /// <param name="cancellationToken">Cancels the preliminary query.</param>
    Task<PasswordResetEmailCandidate?> FindByIdentityAsync(
        Guid realmId,
        Guid appEnvironmentId,
        Guid identityId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Performs a non-authoritative fast check for an active token in the target
    /// environment.
    /// </summary>
    /// <remarks>
    /// A successful result does not reserve the token. Password reset must still use
    /// <see cref="TryResetPasswordAsync"/> to consume it transactionally.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment to which the bearer must be bound.</param>
    /// <param name="tokenHash">Hash of the untrusted presented bearer.</param>
    /// <param name="now">Current UTC time used for exclusive expiry.</param>
    /// <param name="cancellationToken">Cancels the preliminary query.</param>
    Task<bool> IsActiveAsync(
        Guid appEnvironmentId,
        byte[] tokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically consumes the reset token, replaces the password, revokes active
    /// sessions, and invalidates competing reset tokens for the same identity.
    /// </summary>
    /// <returns>The password owner, or <see langword="null"/> when the token lost eligibility.</returns>
    /// <param name="appEnvironmentId">Environment to which the bearer must be bound.</param>
    /// <param name="tokenHash">Hash of the untrusted presented bearer.</param>
    /// <param name="passwordHash">New platform-encoded password credential.</param>
    /// <param name="resetAt">UTC time shared by password and invalidation mutations.</param>
    /// <param name="cancellationToken">Cancels the atomic reset transaction.</param>
    Task<Guid?> TryResetPasswordAsync(
        Guid appEnvironmentId,
        byte[] tokenHash,
        string passwordHash,
        DateTimeOffset resetAt,
        CancellationToken cancellationToken);
}

/// <summary>Transactional token-issuance outcomes after eligibility and rate checks.</summary>
public enum PasswordResetIssueStoreResult
{
    /// <summary>Eligibility, optional ownership, rate check, and insert committed.</summary>
    Issued,

    /// <summary>Identity, environment, realm, or expected e-mail was not eligible.</summary>
    IdentityIneligible,

    /// <summary>The optional identity-wide durable-token limit was reached.</summary>
    RateLimited,
}

/// <summary>Optional per-identity issuance limit applied inside the store transaction.</summary>
/// <param name="IssuedSince">Inclusive UTC start of the counting window.</param>
/// <param name="MaximumIssues">Positive maximum durable-token count in that window.</param>
public sealed record PasswordResetIssueConstraint(
    DateTimeOffset IssuedSince,
    int MaximumIssues)
{
    /// <summary>Validates UTC window and positive maximum before persistence begins.</summary>
    public void Validate()
    {
        if (IssuedSince.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Timestamp must use the UTC offset.",
                nameof(IssuedSince));
        }
        if (MaximumIssues <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumIssues));
        }
    }
}

/// <summary>Normalized identity and app data needed to construct a recovery email.</summary>
/// <remarks>This preliminary projection is not token-issuance authority.</remarks>
/// <param name="IdentityId">Candidate identity revalidated under lock during issuance.</param>
/// <param name="Email">Current canonical e-mail selected for delivery.</param>
/// <param name="AppName">Environment-owned display name.</param>
/// <param name="PasswordRecoveryUrl">Optional environment-owned reset URL base.</param>
public sealed record PasswordResetEmailCandidate(
    Guid IdentityId,
    string Email,
    string AppName,
    string? PasswordRecoveryUrl);
