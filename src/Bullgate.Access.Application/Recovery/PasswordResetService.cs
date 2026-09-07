using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Recovery;

/// <summary>Stable failures produced while issuing a single-use reset token.</summary>
public enum PasswordResetIssueError
{
    /// <summary>Environment policy disables password authentication.</summary>
    AuthenticatorDisabled,

    /// <summary>Identity, environment, realm, or expected e-mail is no longer eligible.</summary>
    IdentityIneligible,

    /// <summary>The transactional per-identity issuance limit was reached.</summary>
    RateLimited,
}

/// <summary>Stable failures produced while consuming a reset token.</summary>
public enum PasswordResetError
{
    /// <summary>Environment policy disables password authentication.</summary>
    AuthenticatorDisabled,

    /// <summary>The bearer is malformed, absent, expired, used, or lost a consumption race.</summary>
    InvalidToken,

    /// <summary>No replacement password was supplied.</summary>
    MissingNewPassword,

    /// <summary>The replacement password does not meet the shared minimum length.</summary>
    PasswordTooShort,
}

/// <summary>Contains a newly issued reset token or its semantic failure.</summary>
/// <remarks><see cref="Token"/> is clear single-use authority and must not be logged.</remarks>
/// <param name="IdentityId">Identity authorized by the issued token.</param>
/// <param name="TokenId">Durable selector for bounded invalidation, not reset authority.</param>
/// <param name="Token">Clear reset bearer returned only on successful issuance.</param>
/// <param name="ExpiresAt">UTC exclusive inactivity boundary.</param>
/// <param name="Error">Stable failure category when no bearer was issued.</param>
public sealed record PasswordResetIssueResult(
    Guid IdentityId,
    Guid TokenId,
    string Token,
    DateTimeOffset ExpiresAt,
    PasswordResetIssueError? Error)
{
    /// <summary>Indicates that no issuance error was recorded.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without identity or bearer material.</summary>
    public static PasswordResetIssueResult Failure(PasswordResetIssueError error) =>
        new(Guid.Empty, Guid.Empty, string.Empty, default, error);
}

/// <summary>Identifies the password owner after successful atomic token consumption.</summary>
/// <param name="IdentityId">Identity whose password and credential paths were updated.</param>
/// <param name="Error">Stable failure category when reset did not commit.</param>
public sealed record PasswordResetResult(
    Guid IdentityId,
    PasswordResetError? Error)
{
    /// <summary>Indicates that no reset error was recorded.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without identity disclosure.</summary>
    public static PasswordResetResult Failure(PasswordResetError error) =>
        new(Guid.Empty, error);
}

/// <summary>
/// Issues, invalidates, and atomically consumes opaque password-reset tokens.
/// </summary>
public sealed class PasswordResetService(
    IPasswordResetStore store,
    IAppEnvironmentConfigurationReader configurations,
    IPasswordHashService passwordHashes,
    IPasswordResetTokenService resetTokens,
    TimeProvider timeProvider)
{
    /// <summary>Issues reset authority after current configuration and identity checks.</summary>
    /// <param name="identityId">Identity selected by trusted orchestration.</param>
    /// <param name="appEnvironmentId">Environment to which the token is confined.</param>
    /// <param name="issueConstraint">Optional transactional per-identity issue limit.</param>
    /// <param name="cancellationToken">Cancels validation and persistence.</param>
    public Task<PasswordResetIssueResult> IssueAsync(
        Guid identityId,
        Guid appEnvironmentId,
        PasswordResetIssueConstraint? issueConstraint = null,
        CancellationToken cancellationToken = default) =>
        IssueCoreAsync(
            identityId,
            appEnvironmentId,
            null,
            issueConstraint,
            cancellationToken);

    /// <summary>
    /// Issues reset authority only while the identity still owns the exact normalized
    /// e-mail selected for delivery.
    /// </summary>
    /// <remarks>
    /// Binding issuance to the expected e-mail prevents a concurrent contact change from
    /// delivering newly created authority to stale identity metadata.
    /// </remarks>
    /// <param name="identityId">Identity selected by current Access state.</param>
    /// <param name="appEnvironmentId">Environment to which the token is confined.</param>
    /// <param name="expectedNormalizedEmail">Exact canonical e-mail authorized for delivery.</param>
    /// <param name="issueConstraint">Optional transactional per-identity issue limit.</param>
    /// <param name="cancellationToken">Cancels validation and persistence.</param>
    public Task<PasswordResetIssueResult> IssueForEmailAsync(
        Guid identityId,
        Guid appEnvironmentId,
        string expectedNormalizedEmail,
        PasswordResetIssueConstraint? issueConstraint = null,
        CancellationToken cancellationToken = default)
    {
        if (!EmailPasswordAccessService.TryNormalizeEmail(
                expectedNormalizedEmail,
                out var normalizedEmail)
            || !string.Equals(
                expectedNormalizedEmail,
                normalizedEmail,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Email must already be normalized.",
                nameof(expectedNormalizedEmail));
        }

        return IssueCoreAsync(
            identityId,
            appEnvironmentId,
            expectedNormalizedEmail,
            issueConstraint,
            cancellationToken);
    }

    /// <summary>
    /// Consumes a token without changing the password when a larger coordinating
    /// operation cannot complete.
    /// </summary>
    /// <remarks>
    /// This is bounded compensation, not rollback of an external delivery. A false
    /// result is safe on retry and means the token was absent, expired, or already used.
    /// </remarks>
    /// <param name="tokenId">Durable token selector, never the clear bearer.</param>
    /// <param name="cancellationToken">Cancels the invalidation attempt.</param>
    /// <returns>Whether this call consumed an otherwise active token.</returns>
    /// <exception cref="ArgumentException"><paramref name="tokenId"/> is empty.</exception>
    public Task<bool> InvalidateAsync(
        Guid tokenId,
        CancellationToken cancellationToken = default)
    {
        RequireId(tokenId, nameof(tokenId));
        return store.TryInvalidateAsync(
            tokenId,
            timeProvider.GetUtcNow(),
            cancellationToken);
    }

    private async Task<PasswordResetIssueResult> IssueCoreAsync(
        Guid identityId,
        Guid appEnvironmentId,
        string? expectedNormalizedEmail,
        PasswordResetIssueConstraint? issueConstraint,
        CancellationToken cancellationToken)
    {
        RequireId(identityId, nameof(identityId));
        RequireId(appEnvironmentId, nameof(appEnvironmentId));
        issueConstraint?.Validate();

        var configuration = await RequireConfigurationAsync(
            appEnvironmentId,
            cancellationToken);
        if (!configuration.AccessPolicy.Authenticators.PasswordEnabled)
        {
            return PasswordResetIssueResult.Failure(
                PasswordResetIssueError.AuthenticatorDisabled);
        }

        var now = timeProvider.GetUtcNow();
        var expiresAt = now.AddMinutes(
            configuration.RecoveryPolicy.TokenLifetimeMinutes);
        var issued = resetTokens.Issue();
        var token = new PasswordResetToken(
            Guid.CreateVersion7(now),
            identityId,
            appEnvironmentId,
            issued.TokenHash,
            now,
            expiresAt);

        // Eligibility and throttling are decided in the same transaction that stores the
        // token, preventing parallel requests from bypassing either rule.
        var storeResult = await store.TryIssueAsync(
            token,
            expectedNormalizedEmail,
            issueConstraint,
            cancellationToken);
        if (storeResult != PasswordResetIssueStoreResult.Issued)
        {
            return PasswordResetIssueResult.Failure(
                storeResult == PasswordResetIssueStoreResult.RateLimited
                    ? PasswordResetIssueError.RateLimited
                    : PasswordResetIssueError.IdentityIneligible);
        }

        return new PasswordResetIssueResult(
            identityId,
            token.Id,
            issued.Token,
            expiresAt,
            null);
    }

    /// <summary>
    /// Validates and atomically consumes reset authority while replacing the password
    /// and revoking competing credential paths.
    /// </summary>
    /// <remarks>
    /// Success revokes every identity session and consumes every still-active reset
    /// token for the identity, including the presented bearer.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="token">Untrusted clear single-use reset bearer.</param>
    /// <param name="newPassword">Replacement password evaluated by the shared policy.</param>
    /// <param name="cancellationToken">Cancels validation or the atomic reset.</param>
    public async Task<PasswordResetResult> ResetAsync(
        Guid appEnvironmentId,
        string? token,
        string? newPassword,
        CancellationToken cancellationToken = default)
    {
        RequireId(appEnvironmentId, nameof(appEnvironmentId));

        var configuration = await RequireConfigurationAsync(
            appEnvironmentId,
            cancellationToken);
        if (!configuration.AccessPolicy.Authenticators.PasswordEnabled)
        {
            return PasswordResetResult.Failure(
                PasswordResetError.AuthenticatorDisabled);
        }
        if (!resetTokens.TryHash(token, out var tokenHash))
        {
            return PasswordResetResult.Failure(PasswordResetError.InvalidToken);
        }
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            return PasswordResetResult.Failure(
                PasswordResetError.MissingNewPassword);
        }
        if (newPassword.Length < EmailPasswordAccessService.MinimumPasswordLength)
        {
            return PasswordResetResult.Failure(
                PasswordResetError.PasswordTooShort);
        }

        var now = timeProvider.GetUtcNow();
        // This read allows a clear fast failure, but TryResetPasswordAsync remains the
        // authority and must atomically consume the token to defeat concurrent reuse.
        if (!await store.IsActiveAsync(
                appEnvironmentId,
                tokenHash,
                now,
                cancellationToken))
        {
            return PasswordResetResult.Failure(PasswordResetError.InvalidToken);
        }

        var identityId = await store.TryResetPasswordAsync(
            appEnvironmentId,
            tokenHash,
            passwordHashes.Hash(newPassword),
            now,
            cancellationToken);
        return identityId is null
            ? PasswordResetResult.Failure(PasswordResetError.InvalidToken)
            : new PasswordResetResult(identityId.Value, null);
    }

    private async Task<AppEnvironmentConfiguration> RequireConfigurationAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        await configurations.FindAsync(appEnvironmentId, cancellationToken)
        ?? throw new InvalidOperationException(
            "The app environment configuration could not be resolved.");

    private static void RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }
    }
}
