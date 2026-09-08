using System.Net.Mail;
using Bullgate.Access.Application.Policies;
using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.EmailPassword;

/// <summary>Stable failure reasons returned by registration and password login.</summary>
public enum EmailPasswordAccessError
{
    /// <summary>The submitted e-mail cannot be normalized to the canonical form.</summary>
    InvalidEmail,

    /// <summary>The password does not meet the minimum length contract.</summary>
    PasswordTooShort,

    /// <summary>The normalized e-mail already belongs to an identity in the realm.</summary>
    EmailTaken,

    /// <summary>Login intentionally collapses absent identity and wrong password.</summary>
    InvalidCredentials,

    /// <summary>Environment policy disables e-mail or password authentication.</summary>
    AuthenticatorDisabled,
}

/// <summary>Stable failure reasons returned when an authenticated identity changes its password.</summary>
public enum ChangePasswordAccessError
{
    /// <summary>The presented session is malformed, absent, expired, or revoked.</summary>
    SessionInactive,

    /// <summary>The session is active but is not product-purpose authority.</summary>
    SessionPurposeInvalid,

    /// <summary>Environment policy disables password authentication.</summary>
    AuthenticatorDisabled,

    /// <summary>No replacement password was supplied.</summary>
    MissingNewPassword,

    /// <summary>The replacement password does not meet the minimum length.</summary>
    PasswordTooShort,

    /// <summary>An existing password credential requires current-password proof.</summary>
    CurrentPasswordRequired,

    /// <summary>The submitted current password does not match the stored credential.</summary>
    CurrentPasswordWrong,
    PasswordChangeConflict,
}

/// <summary>
/// Describes the still-active product session after an authenticated password change.
/// </summary>
/// <param name="IdentityId">Identity whose password and authenticators were updated.</param>
/// <param name="SessionId">Product session intentionally retained as current authority.</param>
/// <param name="Email">Current normalized e-mail.</param>
/// <param name="ExpiresAt">Expiry of the retained current session.</param>
/// <param name="Purpose">Validated product purpose of the retained session.</param>
/// <param name="Authenticators">Post-change authenticator availability.</param>
/// <param name="Error">Stable failure category when the mutation did not commit.</param>
/// <param name="Phone">Optional current normalized phone.</param>
/// <param name="PhoneVerifiedAt">Optional time at which phone possession was established.</param>
public sealed record CurrentIdentitySessionResult(
    Guid IdentityId,
    Guid SessionId,
    string Email,
    DateTimeOffset ExpiresAt,
    IdentitySessionPurpose Purpose,
    AccessAuthenticatorSnapshot Authenticators,
    ChangePasswordAccessError? Error,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null)
{
    /// <summary>Indicates that no change-password error was recorded.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without identity or session authority.</summary>
    public static CurrentIdentitySessionResult Failure(
        ChangePasswordAccessError error) =>
        new(
            Guid.Empty,
            Guid.Empty,
            string.Empty,
            default,
            IdentitySessionPurpose.Product,
            new AccessAuthenticatorSnapshot(false, false, null, false, null),
            error);
}

/// <summary>
/// Returns either a newly issued session and identity snapshot or a semantic access error.
/// </summary>
/// <remarks><see cref="SessionToken"/> is clear bearer authority retained by the BFF.</remarks>
/// <param name="IdentityId">Authenticated or newly created Access identity.</param>
/// <param name="Email">Canonical realm-scoped e-mail.</param>
/// <param name="SessionToken">Clear registration or product bearer.</param>
/// <param name="SessionExpiresAt">Absolute expiry of the issued session.</param>
/// <param name="SessionPurpose">Authority class determined by registration state.</param>
/// <param name="IsNew">True only when this operation created the identity.</param>
/// <param name="Authenticators">Current authenticator availability for the identity.</param>
/// <param name="Error">Stable registration or login failure category.</param>
/// <param name="Phone">Optional current normalized phone.</param>
/// <param name="PhoneVerifiedAt">Optional time at which phone possession was established.</param>
public sealed record EmailPasswordAccessResult(
    Guid IdentityId,
    string Email,
    string SessionToken,
    DateTimeOffset SessionExpiresAt,
    IdentitySessionPurpose SessionPurpose,
    bool IsNew,
    AccessAuthenticatorSnapshot Authenticators,
    EmailPasswordAccessError? Error,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null)
{
    /// <summary>Indicates that no registration or login error was recorded.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without identity or bearer material.</summary>
    public static EmailPasswordAccessResult Failure(EmailPasswordAccessError error) =>
        new(
            Guid.Empty,
            string.Empty,
            string.Empty,
            default,
            IdentitySessionPurpose.Product,
            false,
            new AccessAuthenticatorSnapshot(false, false, null, false, null),
            error);
}

/// <summary>
/// Safe introspection projection; inactive sessions intentionally reveal no identity fields.
/// </summary>
/// <param name="Active">Whether the exact scoped session is currently authoritative.</param>
/// <param name="IdentityId">Identity revealed only for an active session.</param>
/// <param name="SessionId">Durable identifier revealed only for an active session.</param>
/// <param name="Email">Current normalized e-mail revealed only for an active session.</param>
/// <param name="ExpiresAt">Absolute expiry revealed only for an active session.</param>
/// <param name="Purpose">Registration or product authority of the active session.</param>
/// <param name="Authenticators">Current authenticator availability.</param>
/// <param name="Phone">Optional current normalized phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone verification time.</param>
public sealed record SessionIntrospectionResult(
    bool Active,
    Guid? IdentityId = null,
    Guid? SessionId = null,
    string? Email = null,
    DateTimeOffset? ExpiresAt = null,
    IdentitySessionPurpose? Purpose = null,
    AccessAuthenticatorSnapshot? Authenticators = null,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null);

/// <summary>
/// Implements realm-scoped email/password registration, login, session introspection,
/// revocation, and authenticated password changes.
/// </summary>
public sealed class EmailPasswordAccessService(
    IEmailPasswordAccessStore store,
    IAppAccessPolicyReader policies,
    IPasswordHashService passwordHashes,
    ISessionTokenService sessionTokens,
    TimeProvider timeProvider)
{
    /// <summary>Minimum UTF-16 code-unit length accepted by the current password policy.</summary>
    public const int MinimumPasswordLength = 8;
    private static readonly TimeSpan SessionDuration = TimeSpan.FromDays(30);

    /// <summary>
    /// Registers a realm-scoped e-mail/password identity and issues a registration or
    /// product session according to current environment policy.
    /// </summary>
    public async Task<EmailPasswordAccessResult> RegisterAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? email,
        string? password,
        CancellationToken cancellationToken = default)
    {
        RequireScope(realmId, appEnvironmentId);

        var policy = await RequirePolicyAsync(appEnvironmentId, cancellationToken);
        if (!policy.Email.Enabled || !policy.Authenticators.PasswordEnabled)
        {
            return EmailPasswordAccessResult.Failure(
                EmailPasswordAccessError.AuthenticatorDisabled);
        }

        if (!TryNormalizeEmail(email, out var normalizedEmail))
        {
            return EmailPasswordAccessResult.Failure(EmailPasswordAccessError.InvalidEmail);
        }

        if (password is null || password.Length < MinimumPasswordLength)
        {
            return EmailPasswordAccessResult.Failure(EmailPasswordAccessError.PasswordTooShort);
        }

        // This early check improves the normal response, but correctness comes from the
        // transactional uniqueness check below because another request may win the race.
        if (await store.FindByEmailAsync(
                realmId,
                appEnvironmentId,
                normalizedEmail,
                cancellationToken) is not null)
        {
            return EmailPasswordAccessResult.Failure(EmailPasswordAccessError.EmailTaken);
        }

        var now = timeProvider.GetUtcNow();
        var identityId = Guid.CreateVersion7(now);
        var issuedToken = sessionTokens.Issue();
        var expiresAt = now.Add(SessionDuration);
        var identity = new Identity(identityId, realmId, now);
        var identifier = new IdentityIdentifier(
            Guid.CreateVersion7(),
            identityId,
            realmId,
            IdentifierScheme.Email,
            normalizedEmail,
            now);
        var passwordCredential = new PasswordCredential(
            identityId,
            passwordHashes.Hash(password),
            now);
        var registrationContext = new RegistrationContext(
            Guid.CreateVersion7(),
            realmId,
            appEnvironmentId,
            identityId,
            now);
        var requiresRegistrationFlow = policy.Cpf.Enabled
            || policy.Phone.Enabled
            || policy.Email.Verification.Enabled;
        // A registration-purpose session cannot authorize product APIs. Promote it
        // immediately only when policy leaves no registration work to complete.
        if (!requiresRegistrationFlow)
        {
            registrationContext.Complete(now);
        }
        var session = new IdentitySession(
            Guid.CreateVersion7(),
            identityId,
            appEnvironmentId,
            requiresRegistrationFlow
                ? IdentitySessionPurpose.Registration
                : IdentitySessionPurpose.Product,
            issuedToken.TokenHash,
            now,
            expiresAt);

        var created = await store.TryCreateRegistrationAsync(
            identity,
            identifier,
            passwordCredential,
            registrationContext,
            session,
            cancellationToken);
        if (!created)
        {
            return EmailPasswordAccessResult.Failure(EmailPasswordAccessError.EmailTaken);
        }

        return new EmailPasswordAccessResult(
            identityId,
            normalizedEmail,
            issuedToken.Token,
            expiresAt,
            session.Purpose,
            true,
            AccessAuthenticatorSnapshot.PasswordOnly,
            null);
    }

    /// <summary>
    /// Authenticates one normalized e-mail/password pair without exposing which
    /// credential check failed.
    /// </summary>
    public async Task<EmailPasswordAccessResult> LoginAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? email,
        string? password,
        CancellationToken cancellationToken = default)
    {
        RequireScope(realmId, appEnvironmentId);

        var policy = await RequirePolicyAsync(appEnvironmentId, cancellationToken);
        if (!policy.Email.Enabled || !policy.Authenticators.PasswordEnabled)
        {
            return EmailPasswordAccessResult.Failure(
                EmailPasswordAccessError.AuthenticatorDisabled);
        }

        // Login deliberately collapses malformed identifiers and wrong passwords into
        // one error so callers cannot use response shape to enumerate accounts.
        if (!TryNormalizeEmail(email, out var normalizedEmail)
            || string.IsNullOrEmpty(password))
        {
            return EmailPasswordAccessResult.Failure(
                EmailPasswordAccessError.InvalidCredentials);
        }

        var candidate = await store.FindByEmailAsync(
            realmId,
            appEnvironmentId,
            normalizedEmail,
            cancellationToken);
        if (candidate is null || !passwordHashes.Verify(candidate.PasswordHash, password))
        {
            return EmailPasswordAccessResult.Failure(
                EmailPasswordAccessError.InvalidCredentials);
        }

        var now = timeProvider.GetUtcNow();
        var issuedToken = sessionTokens.Issue();
        var expiresAt = now.Add(SessionDuration);
        var purpose = candidate.HasOpenRegistrationContext
            ? IdentitySessionPurpose.Registration
            : IdentitySessionPurpose.Product;
        // Password possession authenticates the identity but does not complete product
        // registration. An open context therefore keeps the newly issued session in the
        // registration authority class instead of promoting it through login.
        var session = new IdentitySession(
            Guid.CreateVersion7(),
            candidate.IdentityId,
            appEnvironmentId,
            purpose,
            issuedToken.TokenHash,
            now,
            expiresAt);
        await store.AddSessionAsync(session, cancellationToken);

        return new EmailPasswordAccessResult(
            candidate.IdentityId,
            candidate.NormalizedEmail,
            issuedToken.Token,
            expiresAt,
            purpose,
            false,
            candidate.Authenticators,
            null,
            candidate.Phone,
            candidate.PhoneVerifiedAt);
    }

    /// <summary>
    /// Returns active state for an opaque session token without using absence as HTTP
    /// authentication failure.
    /// </summary>
    /// <remarks>
    /// Active means the scoped row belongs to an active identity, is unrevoked, and has
    /// not reached its exclusive expiry. Callers must still inspect purpose before using
    /// the result as product authority.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment fixed by integration authentication.</param>
    /// <param name="sessionToken">Untrusted clear session bearer.</param>
    /// <param name="cancellationToken">Cancels the scoped lookup.</param>
    /// <returns>
    /// An active projection with identity fields, or a uniform inactive projection
    /// without them.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="appEnvironmentId"/> is empty.</exception>
    public async Task<SessionIntrospectionResult> IntrospectAsync(
        Guid appEnvironmentId,
        string? sessionToken,
        CancellationToken cancellationToken = default)
    {
        if (appEnvironmentId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(appEnvironmentId));
        }

        if (!sessionTokens.TryHash(sessionToken, out var tokenHash))
        {
            return new SessionIntrospectionResult(false);
        }

        var candidate = await store.FindSessionAsync(
            appEnvironmentId,
            tokenHash,
            cancellationToken);
        if (candidate is null
            || candidate.RevokedAt is not null
            || candidate.ExpiresAt <= timeProvider.GetUtcNow())
        {
            return new SessionIntrospectionResult(false);
        }

        return new SessionIntrospectionResult(
            true,
            candidate.IdentityId,
            candidate.SessionId,
            candidate.NormalizedEmail,
            candidate.ExpiresAt,
            candidate.Purpose,
            candidate.Authenticators,
            candidate.Phone,
            candidate.PhoneVerifiedAt);
    }

    /// <summary>
    /// Idempotently revokes the matching current session without revealing whether the
    /// token existed.
    /// </summary>
    /// <remarks>
    /// A matching unrevoked row is stamped even if it has already expired. Malformed,
    /// absent, and previously revoked tokens remain successful no-ops so the operation
    /// does not become a session-existence oracle.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment fixed by integration authentication.</param>
    /// <param name="sessionToken">Untrusted clear session bearer.</param>
    /// <param name="cancellationToken">Cancels the scoped update.</param>
    /// <exception cref="ArgumentException"><paramref name="appEnvironmentId"/> is empty.</exception>
    public async Task RevokeCurrentSessionAsync(
        Guid appEnvironmentId,
        string? sessionToken,
        CancellationToken cancellationToken = default)
    {
        if (appEnvironmentId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(appEnvironmentId));
        }

        if (!sessionTokens.TryHash(sessionToken, out var tokenHash))
        {
            return;
        }

        await store.RevokeSessionAsync(
            appEnvironmentId,
            tokenHash,
            timeProvider.GetUtcNow(),
            cancellationToken);
    }

    /// <summary>
    /// Changes or adds the current identity password after product-session proof.
    /// </summary>
    /// <remarks>
    /// An identity without a password may add its first one without an old password.
    /// Success keeps the authorizing session active, revokes other sessions, and
    /// consumes outstanding password-reset tokens.
    /// </remarks>
    public async Task<CurrentIdentitySessionResult> ChangePasswordAsync(
        Guid appEnvironmentId,
        string? sessionToken,
        string? currentPassword,
        string? newPassword,
        CancellationToken cancellationToken = default)
    {
        if (appEnvironmentId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(appEnvironmentId));
        }

        var policy = await RequirePolicyAsync(appEnvironmentId, cancellationToken);
        if (!policy.Authenticators.PasswordEnabled)
        {
            return CurrentIdentitySessionResult.Failure(
                ChangePasswordAccessError.AuthenticatorDisabled);
        }

        if (string.IsNullOrEmpty(newPassword))
        {
            return CurrentIdentitySessionResult.Failure(
                ChangePasswordAccessError.MissingNewPassword);
        }
        if (newPassword.Length < MinimumPasswordLength)
        {
            return CurrentIdentitySessionResult.Failure(
                ChangePasswordAccessError.PasswordTooShort);
        }

        if (!sessionTokens.TryHash(sessionToken, out var tokenHash))
        {
            return CurrentIdentitySessionResult.Failure(
                ChangePasswordAccessError.SessionInactive);
        }

        var candidate = await store.FindSessionAsync(
            appEnvironmentId,
            tokenHash,
            cancellationToken);
        var now = timeProvider.GetUtcNow();
        if (candidate is null
            || candidate.RevokedAt is not null
            || candidate.ExpiresAt <= now)
        {
            return CurrentIdentitySessionResult.Failure(
                ChangePasswordAccessError.SessionInactive);
        }
        if (candidate.Purpose != IdentitySessionPurpose.Product)
        {
            return CurrentIdentitySessionResult.Failure(
                ChangePasswordAccessError.SessionPurposeInvalid);
        }

        // A social-only identity may add its first password without an old password.
        // Once a password exists, proof of the current password is mandatory.
        if (candidate.PasswordHash is not null)
        {
            if (string.IsNullOrWhiteSpace(currentPassword))
            {
                return CurrentIdentitySessionResult.Failure(
                    ChangePasswordAccessError.CurrentPasswordRequired);
            }
            if (!passwordHashes.Verify(candidate.PasswordHash, currentPassword))
            {
                return CurrentIdentitySessionResult.Failure(
                ChangePasswordAccessError.CurrentPasswordWrong);
            }
        }

        // Password replacement, reset-token consumption, and revocation of every other
        // session are one persistence operation. The authorizing session remains active
        // so this request can return a usable current-session snapshot. The expected
        // previous hash prevents a concurrent password change from being overwritten.
        var changed = await store.TrySetPasswordAndRevokeOtherSessionsAsync(
            candidate.IdentityId,
            candidate.SessionId,
            candidate.PasswordHash,
            passwordHashes.Hash(newPassword),
            now,
            cancellationToken);
        if (!changed)
        {
            return CurrentIdentitySessionResult.Failure(
                ChangePasswordAccessError.PasswordChangeConflict);
        }

        return new CurrentIdentitySessionResult(
            candidate.IdentityId,
            candidate.SessionId,
            candidate.NormalizedEmail,
            candidate.ExpiresAt,
            candidate.Purpose,
            candidate.Authenticators with { HasPassword = true },
            null,
            candidate.Phone,
            candidate.PhoneVerifiedAt);
    }

    internal static bool TryNormalizeEmail(string? value, out string normalizedEmail)
    {
        normalizedEmail = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.Length > IdentityLimits.IdentifierValueMaxLength
            || !MailAddress.TryCreate(trimmed, out var parsed)
            || !string.Equals(parsed.Address, trimmed, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        normalizedEmail = parsed.Address.ToLowerInvariant();
        return true;
    }

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

    private async Task<AppAccessPolicy> RequirePolicyAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        await policies.FindAsync(appEnvironmentId, cancellationToken)
        ?? throw new InvalidOperationException(
            "The app environment access policy could not be resolved.");
}
