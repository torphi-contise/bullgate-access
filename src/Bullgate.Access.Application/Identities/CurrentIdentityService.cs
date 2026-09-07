using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.Application.Identities;

/// <summary>Stable failures for product-session identity mutations.</summary>
public enum CurrentIdentityError
{
    /// <summary>The presented session is malformed, absent, expired, revoked, or wrong-scope.</summary>
    SessionInactive,

    /// <summary>The session is active but cannot authorize product account mutation.</summary>
    SessionPurposeInvalid,

    /// <summary>The replacement e-mail cannot be normalized.</summary>
    InvalidEmail,

    /// <summary>Another identity already owns the normalized e-mail in the realm.</summary>
    EmailTaken,
}

/// <summary>Returns the current product identity snapshot or a semantic session error.</summary>
/// <param name="IdentityId">Identity selected by the authorizing product session.</param>
/// <param name="SessionId">Product session that authorized the operation.</param>
/// <param name="Email">Current canonical primary e-mail.</param>
/// <param name="Phone">Optional current canonical phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone-possession proof time.</param>
/// <param name="ExpiresAt">Expiry of the unchanged authorizing session.</param>
/// <param name="Purpose">Validated product authority class.</param>
/// <param name="Authenticators">Current authenticator availability.</param>
/// <param name="Error">Stable failure category when no snapshot is returned.</param>
public sealed record CurrentIdentityResult(
    Guid IdentityId,
    Guid SessionId,
    string Email,
    string? Phone,
    DateTimeOffset? PhoneVerifiedAt,
    DateTimeOffset ExpiresAt,
    IdentitySessionPurpose Purpose,
    AccessAuthenticatorSnapshot Authenticators,
    CurrentIdentityError? Error)
{
    /// <summary>Indicates that no current-identity error was recorded.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without identity or session disclosure.</summary>
    public static CurrentIdentityResult Failure(CurrentIdentityError error) =>
        new(
            Guid.Empty,
            Guid.Empty,
            string.Empty,
            null,
            null,
            default,
            IdentitySessionPurpose.Product,
            new AccessAuthenticatorSnapshot(false, false, null, false, null),
            error);
}

/// <summary>
/// Applies authenticated identity mutations within the realm and environment fixed by
/// the caller's integration credential.
/// </summary>
public sealed class CurrentIdentityService(
    ICurrentIdentityStore store,
    ISessionTokenService sessionTokens,
    TimeProvider timeProvider)
{
    /// <summary>
    /// Replaces the current identity's e-mail after product-session authorization and
    /// returns the resulting identity snapshot.
    /// </summary>
    /// <remarks>
    /// Repeating the exact canonical e-mail is an idempotent read-only success. A real
    /// replacement clears old verification evidence and invalidates outstanding recovery
    /// authority in the store transaction.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="sessionToken">Untrusted clear product-session bearer.</param>
    /// <param name="email">Untrusted replacement e-mail.</param>
    /// <param name="cancellationToken">Cancels lookup or mutation.</param>
    public async Task<CurrentIdentityResult> ChangeEmailAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        string? email,
        CancellationToken cancellationToken = default)
    {
        RequireScope(realmId, appEnvironmentId);
        var now = timeProvider.GetUtcNow();
        var current = await FindCurrentAsync(
            realmId,
            appEnvironmentId,
            sessionToken,
            now,
            cancellationToken);
        if (current.Error is not null)
        {
            return CurrentIdentityResult.Failure(current.Error.Value);
        }

        if (!EmailPasswordAccessService.TryNormalizeEmail(email, out var normalizedEmail))
        {
            return CurrentIdentityResult.Failure(CurrentIdentityError.InvalidEmail);
        }

        var candidate = current.Candidate!;
        // Treat an exact normalized match as an idempotent success rather than forcing a
        // write or reporting that the identity already owns its email.
        if (string.Equals(candidate.Email, normalizedEmail, StringComparison.Ordinal))
        {
            return Success(candidate);
        }

        var status = await store.TryChangeEmailAsync(
            realmId,
            appEnvironmentId,
            candidate.IdentityId,
            candidate.SessionId,
            normalizedEmail,
            now,
            cancellationToken);
        return status switch
        {
            CurrentIdentityMutationStatus.Updated => Success(candidate with
            {
                Email = normalizedEmail,
            }),
            CurrentIdentityMutationStatus.EmailTaken =>
                CurrentIdentityResult.Failure(CurrentIdentityError.EmailTaken),
            CurrentIdentityMutationStatus.IdentityNotFound =>
                CurrentIdentityResult.Failure(CurrentIdentityError.SessionInactive),
            _ => throw new ArgumentOutOfRangeException(nameof(status), status, null),
        };
    }

    /// <summary>
    /// Hard-deletes the identity authorized by the supplied product session from the
    /// Access database.
    /// </summary>
    /// <remarks>
    /// Consumer profile deletion is a separate transaction owned by the integrating
    /// product. Provider availability is not a precondition for local erasure. The
    /// caller supplies no identity UUID: the hashed bearer selects the identity, while
    /// the authenticated integration credential fixes the only acceptable realm and
    /// environment.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="sessionToken">Untrusted clear product-session bearer.</param>
    /// <param name="cancellationToken">Cancels local erasure.</param>
    /// <returns>
    /// <see langword="null"/> only after the local Access deletion commits; otherwise
    /// <see cref="CurrentIdentityError.SessionInactive"/>. Because successful deletion
    /// also removes the authorizing session, repeating the request with that bearer is
    /// not a second success and resolves as inactive.
    /// </returns>
    public async Task<CurrentIdentityError?> DeleteAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        CancellationToken cancellationToken = default)
    {
        RequireScope(realmId, appEnvironmentId);
        if (!sessionTokens.TryHash(sessionToken, out var tokenHash))
        {
            return CurrentIdentityError.SessionInactive;
        }

        var now = timeProvider.GetUtcNow();
        // The store owns the complete local erasure transaction, including sessions,
        // authenticators, reset material, and every linked AccessFlow data subject.
        // Do not resolve an identity id here and then delete it later: that would turn a
        // stale preliminary read into authority and open a scope/lifecycle race.
        var deleted = await store.TryDeleteAsync(
            realmId,
            appEnvironmentId,
            tokenHash,
            now,
            cancellationToken);
        return deleted ? null : CurrentIdentityError.SessionInactive;
    }

    private async Task<CurrentIdentityLookup> FindCurrentAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!sessionTokens.TryHash(sessionToken, out var tokenHash))
        {
            return new(null, CurrentIdentityError.SessionInactive);
        }

        var candidate = await store.FindBySessionAsync(
            appEnvironmentId,
            tokenHash,
            now,
            cancellationToken);
        // Environment is part of the lookup, but realm remains an independent tenancy
        // boundary fixed by the integration credential and must also match the identity.
        if (candidate is null || candidate.RealmId != realmId)
        {
            return new(null, CurrentIdentityError.SessionInactive);
        }
        return candidate.Purpose == IdentitySessionPurpose.Product
            ? new(candidate, null)
            : new(null, CurrentIdentityError.SessionPurposeInvalid);
    }

    private static CurrentIdentityResult Success(CurrentIdentityCandidate candidate) =>
        new(
            candidate.IdentityId,
            candidate.SessionId,
            candidate.Email,
            candidate.Phone,
            candidate.PhoneVerifiedAt,
            candidate.ExpiresAt,
            candidate.Purpose,
            candidate.Authenticators,
            null);

    private static void RequireScope(Guid realmId, Guid appEnvironmentId)
    {
        if (realmId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(realmId));
        }
        if (appEnvironmentId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(appEnvironmentId));
        }
    }

    private sealed record CurrentIdentityLookup(
        CurrentIdentityCandidate? Candidate,
        CurrentIdentityError? Error);
}
