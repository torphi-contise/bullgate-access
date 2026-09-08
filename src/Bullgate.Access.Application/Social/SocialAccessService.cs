using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Social;

/// <summary>Stable failures produced by Google or Apple registration and login.</summary>
public enum SocialAccessError
{
    /// <summary>No supported provider token was supplied.</summary>
    MissingToken,

    /// <summary>The provider assertion was rejected or lacks required identity claims.</summary>
    InvalidToken,

    /// <summary>The asserted e-mail or provider subject lost exclusive ownership.</summary>
    EmailTaken,

    /// <summary>Environment policy disables e-mail identity or the selected provider.</summary>
    AuthenticatorDisabled,
}

/// <summary>Stable failures produced when linking or unlinking a social authenticator.</summary>
public enum SocialManagementError
{
    /// <summary>The presented product session is malformed, absent, expired, or revoked.</summary>
    SessionInactive,

    /// <summary>The session is active but cannot authorize product account management.</summary>
    SessionPurposeInvalid,

    /// <summary>Environment policy disables the selected social provider.</summary>
    AuthenticatorDisabled,

    /// <summary>No supported provider token was supplied for linking.</summary>
    MissingToken,

    /// <summary>The provider assertion was rejected or lacks required identity claims.</summary>
    InvalidToken,

    /// <summary>The identity already owns another subject for the selected provider.</summary>
    ProviderAlreadyLinked,

    /// <summary>The provider subject is already owned by another identity.</summary>
    CredentialAlreadyInUse,

    /// <summary>The identity has no credential for the selected provider.</summary>
    ProviderNotLinked,

    /// <summary>Removal would leave the identity without an authenticator.</summary>
    LastAuthenticator,
}

/// <summary>
/// Returns the authenticated product session after a social authenticator mutation.
/// </summary>
/// <param name="IdentityId">Identity whose authenticator set was inspected or changed.</param>
/// <param name="SessionId">Product session that authorized the operation.</param>
/// <param name="Email">Current canonical primary e-mail.</param>
/// <param name="ExpiresAt">Expiry of the unchanged authorizing session.</param>
/// <param name="Purpose">Validated product purpose of the authorizing session.</param>
/// <param name="Authenticators">Post-operation authenticator availability.</param>
/// <param name="Error">Stable failure category when the operation did not succeed.</param>
/// <param name="Phone">Optional current canonical phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone-possession proof time.</param>
public sealed record SocialManagementResult(
    Guid IdentityId,
    Guid SessionId,
    string Email,
    DateTimeOffset ExpiresAt,
    IdentitySessionPurpose Purpose,
    AccessAuthenticatorSnapshot Authenticators,
    SocialManagementError? Error,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null)
{
    /// <summary>Indicates that no social-management error was recorded.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without identity or session authority.</summary>
    public static SocialManagementResult Failure(SocialManagementError error) =>
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
/// Returns either an issued session and normalized identity snapshot or a semantic error.
/// </summary>
/// <remarks><see cref="SessionToken"/> is clear bearer authority retained by the BFF.</remarks>
/// <param name="IdentityId">Authenticated or newly created Access identity.</param>
/// <param name="Email">Current canonical primary e-mail.</param>
/// <param name="SessionToken">Clear registration or product bearer.</param>
/// <param name="SessionExpiresAt">Absolute expiry of the issued session.</param>
/// <param name="SessionPurpose">Authority class determined by registration state.</param>
/// <param name="IsNew">True only when this operation created the identity.</param>
/// <param name="Authenticators">Current authenticator availability.</param>
/// <param name="Error">Stable social authentication or registration failure.</param>
/// <param name="Phone">Optional current canonical phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone-possession proof time.</param>
public sealed record SocialAccessResult(
    Guid IdentityId,
    string Email,
    string SessionToken,
    DateTimeOffset SessionExpiresAt,
    IdentitySessionPurpose SessionPurpose,
    bool IsNew,
    AccessAuthenticatorSnapshot Authenticators,
    SocialAccessError? Error,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null)
{
    /// <summary>Indicates that no social-access error was recorded.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without identity or bearer material.</summary>
    public static SocialAccessResult Failure(SocialAccessError error) =>
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
/// Validates provider assertions server-side and manages Google and Apple authenticators
/// without inferring identity ownership from email alone.
/// </summary>
public sealed class SocialAccessService(
    ISocialAccessStore store,
    IAppEnvironmentConfigurationReader configurations,
    IGoogleIdentityValidator google,
    IAppleIdentityValidator apple,
    ISessionTokenService sessionTokens,
    TimeProvider timeProvider)
{
    private static readonly TimeSpan SessionDuration = TimeSpan.FromDays(30);

    /// <summary>
    /// Authenticates or registers a Google subject using a server-validated ID token or
    /// access token and issues the appropriate session purpose.
    /// </summary>
    public async Task<SocialAccessResult> GoogleAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? idToken,
        string? accessToken,
        CancellationToken cancellationToken = default)
    {
        RequireScope(realmId, appEnvironmentId);

        var configuration = await RequireConfigurationAsync(
            appEnvironmentId,
            cancellationToken);
        var policy = configuration.AccessPolicy;
        // Authentication can create a primary e-mail identifier, so both the e-mail
        // identity feature and the selected provider must be enabled in this environment.
        if (!policy.Email.Enabled || !policy.Authenticators.GoogleEnabled)
        {
            return SocialAccessResult.Failure(SocialAccessError.AuthenticatorDisabled);
        }

        RequireProviderClientId(configuration.Providers.Google?.ClientId, "Google");

        SocialIdentityAssertion? assertion = null;
        // Prefer an ID token when both are present because it is the provider's direct
        // authentication assertion. Access-token lookup remains a supported fallback.
        if (!string.IsNullOrWhiteSpace(idToken))
        {
            assertion = await google.ValidateIdTokenAsync(
                appEnvironmentId,
                idToken,
                cancellationToken);
        }
        else if (!string.IsNullOrWhiteSpace(accessToken))
        {
            assertion = await google.ValidateAccessTokenAsync(
                appEnvironmentId,
                accessToken,
                cancellationToken);
        }
        else
        {
            return SocialAccessResult.Failure(SocialAccessError.MissingToken);
        }

        return assertion is null
            ? SocialAccessResult.Failure(SocialAccessError.InvalidToken)
            : await AuthenticateAsync(
                realmId,
                appEnvironmentId,
                SocialProvider.Google,
                assertion,
                policy,
                cancellationToken);
    }

    /// <summary>
    /// Authenticates or registers an Apple subject using a server-validated identity
    /// token and issues the appropriate session purpose.
    /// </summary>
    public async Task<SocialAccessResult> AppleAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? identityToken,
        CancellationToken cancellationToken = default)
    {
        RequireScope(realmId, appEnvironmentId);

        var configuration = await RequireConfigurationAsync(
            appEnvironmentId,
            cancellationToken);
        var policy = configuration.AccessPolicy;
        // Authentication can create a primary e-mail identifier, so both the e-mail
        // identity feature and the selected provider must be enabled in this environment.
        if (!policy.Email.Enabled || !policy.Authenticators.AppleEnabled)
        {
            return SocialAccessResult.Failure(SocialAccessError.AuthenticatorDisabled);
        }

        RequireProviderClientId(configuration.Providers.Apple?.ClientId, "Apple");

        if (string.IsNullOrWhiteSpace(identityToken))
        {
            return SocialAccessResult.Failure(SocialAccessError.MissingToken);
        }

        var assertion = await apple.ValidateAsync(
            appEnvironmentId,
            identityToken,
            cancellationToken);
        return assertion is null
            ? SocialAccessResult.Failure(SocialAccessError.InvalidToken)
            : await AuthenticateAsync(
                realmId,
                appEnvironmentId,
                SocialProvider.Apple,
                assertion,
                policy,
                cancellationToken);
    }

    /// <summary>Links a validated Google subject to the current product identity.</summary>
    public async Task<SocialManagementResult> LinkGoogleAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        string? idToken,
        string? accessToken,
        CancellationToken cancellationToken = default)
    {
        RequireScope(realmId, appEnvironmentId);
        var configuration = await RequireConfigurationAsync(
            appEnvironmentId,
            cancellationToken);
        var policy = configuration.AccessPolicy;
        // Linking starts from an existing identity and does not replace its primary
        // e-mail. The assertion e-mail remains provider metadata, so only the provider
        // feature gate applies here.
        if (!policy.Authenticators.GoogleEnabled)
        {
            return SocialManagementResult.Failure(
                SocialManagementError.AuthenticatorDisabled);
        }

        RequireProviderClientId(configuration.Providers.Google?.ClientId, "Google");

        SocialIdentityAssertion? assertion;
        if (!string.IsNullOrWhiteSpace(idToken))
        {
            assertion = await google.ValidateIdTokenAsync(
                appEnvironmentId,
                idToken,
                cancellationToken);
        }
        else if (!string.IsNullOrWhiteSpace(accessToken))
        {
            assertion = await google.ValidateAccessTokenAsync(
                appEnvironmentId,
                accessToken,
                cancellationToken);
        }
        else
        {
            return SocialManagementResult.Failure(SocialManagementError.MissingToken);
        }

        return assertion is null
            ? SocialManagementResult.Failure(SocialManagementError.InvalidToken)
            : await LinkAsync(
                realmId,
                appEnvironmentId,
                sessionToken,
                SocialProvider.Google,
                assertion,
                cancellationToken);
    }

    /// <summary>Links a validated Apple subject to the current product identity.</summary>
    public async Task<SocialManagementResult> LinkAppleAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        string? identityToken,
        CancellationToken cancellationToken = default)
    {
        RequireScope(realmId, appEnvironmentId);
        var configuration = await RequireConfigurationAsync(
            appEnvironmentId,
            cancellationToken);
        var policy = configuration.AccessPolicy;
        // Linking starts from an existing identity and does not replace its primary
        // e-mail. The assertion e-mail remains provider metadata, so only the provider
        // feature gate applies here.
        if (!policy.Authenticators.AppleEnabled)
        {
            return SocialManagementResult.Failure(
                SocialManagementError.AuthenticatorDisabled);
        }

        RequireProviderClientId(configuration.Providers.Apple?.ClientId, "Apple");

        if (string.IsNullOrWhiteSpace(identityToken))
        {
            return SocialManagementResult.Failure(SocialManagementError.MissingToken);
        }

        var assertion = await apple.ValidateAsync(
            appEnvironmentId,
            identityToken,
            cancellationToken);
        return assertion is null
            ? SocialManagementResult.Failure(SocialManagementError.InvalidToken)
            : await LinkAsync(
                realmId,
                appEnvironmentId,
                sessionToken,
                SocialProvider.Apple,
                assertion,
                cancellationToken);
    }

    /// <summary>Unlinks Google while preserving at least one identity authenticator.</summary>
    public Task<SocialManagementResult> UnlinkGoogleAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        CancellationToken cancellationToken = default) =>
        UnlinkAsync(
            realmId,
            appEnvironmentId,
            sessionToken,
            SocialProvider.Google,
            cancellationToken);

    /// <summary>Unlinks Apple while preserving at least one identity authenticator.</summary>
    public Task<SocialManagementResult> UnlinkAppleAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        CancellationToken cancellationToken = default) =>
        UnlinkAsync(
            realmId,
            appEnvironmentId,
            sessionToken,
            SocialProvider.Apple,
            cancellationToken);

    private async Task<SocialManagementResult> LinkAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        string provider,
        SocialIdentityAssertion assertion,
        CancellationToken cancellationToken)
    {
        var candidate = await FindActiveProductSessionAsync(
            realmId,
            appEnvironmentId,
            sessionToken,
            cancellationToken);
        if (candidate.Error is not null)
        {
            return candidate;
        }
        if (!EmailPasswordAccessService.TryNormalizeEmail(
                assertion.Email,
                out var normalizedEmail)
            || string.IsNullOrWhiteSpace(assertion.Subject))
        {
            return SocialManagementResult.Failure(SocialManagementError.InvalidToken);
        }

        // The store enforces both invariants atomically: one credential per identity and
        // one owner per provider subject. Matching email never authorizes an account merge.
        var status = await store.LinkAsync(
            realmId,
            candidate.IdentityId,
            provider,
            assertion.Subject.Trim(),
            normalizedEmail,
            timeProvider.GetUtcNow(),
            cancellationToken);
        if (status == SocialLinkStoreStatus.ProviderAlreadyLinked)
        {
            return SocialManagementResult.Failure(
                SocialManagementError.ProviderAlreadyLinked);
        }
        if (status == SocialLinkStoreStatus.CredentialAlreadyInUse)
        {
            return SocialManagementResult.Failure(
                SocialManagementError.CredentialAlreadyInUse);
        }

        var authenticators = provider == SocialProvider.Google
            ? candidate.Authenticators with
            {
                HasGoogle = true,
                GoogleEmail = normalizedEmail,
            }
            : candidate.Authenticators with
            {
                HasApple = true,
                AppleEmail = normalizedEmail,
            };
        return candidate with { Authenticators = authenticators };
    }

    private async Task<SocialManagementResult> UnlinkAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        string provider,
        CancellationToken cancellationToken)
    {
        RequireScope(realmId, appEnvironmentId);
        var candidate = await FindActiveProductSessionAsync(
            realmId,
            appEnvironmentId,
            sessionToken,
            cancellationToken);
        if (candidate.Error is not null)
        {
            return candidate;
        }

        // Last-authenticator protection belongs in the transaction because concurrent
        // unlink/password-removal operations must not strand an inaccessible identity.
        var status = await store.UnlinkAsync(
            realmId,
            candidate.IdentityId,
            provider,
            cancellationToken);
        if (status == SocialUnlinkStoreStatus.NotLinked)
        {
            return SocialManagementResult.Failure(
                SocialManagementError.ProviderNotLinked);
        }
        if (status == SocialUnlinkStoreStatus.LastAuthenticator)
        {
            return SocialManagementResult.Failure(
                SocialManagementError.LastAuthenticator);
        }

        var authenticators = provider == SocialProvider.Google
            ? candidate.Authenticators with
            {
                HasGoogle = false,
                GoogleEmail = null,
            }
            : candidate.Authenticators with
            {
                HasApple = false,
                AppleEmail = null,
            };
        return candidate with { Authenticators = authenticators };
    }

    private async Task<SocialManagementResult> FindActiveProductSessionAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? sessionToken,
        CancellationToken cancellationToken)
    {
        if (!sessionTokens.TryHash(sessionToken, out var tokenHash))
        {
            return SocialManagementResult.Failure(
                SocialManagementError.SessionInactive);
        }
        var candidate = await store.FindSessionAsync(
            realmId,
            appEnvironmentId,
            tokenHash,
            cancellationToken);
        if (candidate is null
            || candidate.RevokedAt is not null
            || candidate.ExpiresAt <= timeProvider.GetUtcNow())
        {
            return SocialManagementResult.Failure(
                SocialManagementError.SessionInactive);
        }
        if (candidate.Purpose != IdentitySessionPurpose.Product)
        {
            return SocialManagementResult.Failure(
                SocialManagementError.SessionPurposeInvalid);
        }

        return new SocialManagementResult(
            candidate.IdentityId,
            candidate.SessionId,
            candidate.NormalizedEmail,
            candidate.ExpiresAt,
            candidate.Purpose,
            candidate.Authenticators,
            null,
            candidate.Phone,
            candidate.PhoneVerifiedAt);
    }

    private async Task<SocialAccessResult> AuthenticateAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string provider,
        SocialIdentityAssertion assertion,
        AppAccessPolicy policy,
        CancellationToken cancellationToken)
    {
        if (!EmailPasswordAccessService.TryNormalizeEmail(
                assertion.Email,
                out var normalizedEmail))
        {
            return SocialAccessResult.Failure(SocialAccessError.InvalidToken);
        }

        if (string.IsNullOrWhiteSpace(assertion.Subject))
        {
            return SocialAccessResult.Failure(SocialAccessError.InvalidToken);
        }

        // Provider plus immutable subject is authoritative. Email is contact metadata and
        // cannot select an existing identity because providers may recycle or change it.
        var candidate = await store.FindByProviderAsync(
            realmId,
            appEnvironmentId,
            provider,
            assertion.Subject.Trim(),
            cancellationToken);
        if (candidate is not null)
        {
            return await IssueExistingSessionAsync(
                appEnvironmentId,
                candidate,
                cancellationToken);
        }

        return await CreateRegistrationAsync(
            realmId,
            appEnvironmentId,
            provider,
            assertion.Subject.Trim(),
            normalizedEmail,
            policy,
            cancellationToken);
    }

    private async Task<SocialAccessResult> IssueExistingSessionAsync(
        Guid appEnvironmentId,
        SocialIdentityCandidate candidate,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var issuedToken = sessionTokens.Issue();
        var expiresAt = now.Add(SessionDuration);
        var purpose = candidate.HasOpenRegistrationContext
            ? IdentitySessionPurpose.Registration
            : IdentitySessionPurpose.Product;
        // Provider possession authenticates the stable subject but does not complete
        // an unfinished registration journey. Preserve registration-purpose authority
        // until the server-owned flow closes that context.
        var session = new IdentitySession(
            Guid.CreateVersion7(),
            candidate.IdentityId,
            appEnvironmentId,
            purpose,
            issuedToken.TokenHash,
            now,
            expiresAt);
        await store.AddSessionAsync(session, cancellationToken);

        return new SocialAccessResult(
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

    private async Task<SocialAccessResult> CreateRegistrationAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string provider,
        string subject,
        string normalizedEmail,
        AppAccessPolicy policy,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var identityId = Guid.CreateVersion7(now);
        var issuedToken = sessionTokens.Issue();
        var expiresAt = now.Add(SessionDuration);
        var identity = new Identity(identityId, realmId, now);
        // The accepted provider assertion supplies the e-mail recorded as verified by
        // this contract. Identity ownership still comes from provider plus subject,
        // never from the e-mail value alone.
        var emailIdentifier = new IdentityIdentifier(
            Guid.CreateVersion7(),
            identityId,
            realmId,
            IdentifierScheme.Email,
            normalizedEmail,
            now,
            now,
            $"{provider}:email");
        var socialCredential = new SocialCredential(
            Guid.CreateVersion7(),
            identityId,
            realmId,
            provider,
            subject,
            normalizedEmail,
            now);
        var registrationContext = new RegistrationContext(
            Guid.CreateVersion7(),
            realmId,
            appEnvironmentId,
            identityId,
            now);
        // Social registration already supplies the accepted e-mail claim. Required
        // civil data or an enabled phone journey keeps the initial session restricted
        // until the server-owned registration flow completes.
        var requiresRegistrationFlow = policy.Cpf.Enabled || policy.Phone.Enabled;
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
            emailIdentifier,
            socialCredential,
            registrationContext,
            session,
            cancellationToken);
        if (!created)
        {
            return SocialAccessResult.Failure(SocialAccessError.EmailTaken);
        }

        var authenticators = new AccessAuthenticatorSnapshot(
            false,
            provider == SocialProvider.Google,
            provider == SocialProvider.Google ? normalizedEmail : null,
            provider == SocialProvider.Apple,
            provider == SocialProvider.Apple ? normalizedEmail : null);

        return new SocialAccessResult(
            identityId,
            normalizedEmail,
            issuedToken.Token,
            expiresAt,
            session.Purpose,
            true,
            authenticators,
            null);
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

    private async Task<AppEnvironmentConfiguration> RequireConfigurationAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        await configurations.FindAsync(appEnvironmentId, cancellationToken)
        ?? throw new InvalidOperationException(
            "The app environment configuration could not be resolved.");

    private static void RequireProviderClientId(string? clientId, string provider)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new InvalidOperationException(
                $"{provider} is enabled but its client id is not configured.");
        }
    }
}
