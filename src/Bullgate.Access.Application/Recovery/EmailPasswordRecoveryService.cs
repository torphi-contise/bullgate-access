using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.Application.Recovery;

/// <summary>Stable outcomes of an email password-recovery request.</summary>
public enum EmailPasswordRecoveryOutcome
{
    /// <summary>The SMTP adapter accepted the recovery message operation.</summary>
    Sent,

    /// <summary>The submitted e-mail could not be normalized.</summary>
    InvalidEmail,

    /// <summary>No eligible identity owned the submitted or selected e-mail.</summary>
    IdentityNotFound,

    /// <summary>The per-identity issuance limit rejected a new token.</summary>
    RateLimited,

    /// <summary>SMTP configuration or provider delivery was unavailable.</summary>
    DeliveryUnavailable,

    /// <summary>The environment lacks a usable password-recovery URL.</summary>
    EnvironmentNotConfigured,
}

/// <summary>
/// Reports delivery outcome and the issued token id, when present, so a coordinating
/// caller can invalidate a link if its larger operation fails.
/// </summary>
/// <remarks>
/// <see cref="TokenId"/> is a durable selector for bounded compensation, not the clear
/// reset bearer and not evidence that SMTP reached the person's inbox.
/// </remarks>
/// <param name="Outcome">Internal operational outcome hidden by public anti-enumeration.</param>
/// <param name="TokenId">Issued token selector when persistence preceded delivery outcome.</param>
public sealed record EmailPasswordRecoveryResult(
    EmailPasswordRecoveryOutcome Outcome,
    Guid? TokenId);

/// <summary>
/// Coordinates eligible token issuance with an external email delivery provider.
/// </summary>
public sealed class EmailPasswordRecoveryService(
    IPasswordResetStore store,
    PasswordResetService passwordReset,
    IAppEnvironmentConfigurationReader configurations,
    IPasswordRecoveryEmailSender emailSender,
    TimeProvider timeProvider)
{
    /// <summary>Requests e-mail recovery by a caller-supplied address.</summary>
    /// <remarks>
    /// The application result retains internal operational distinctions. A public HTTP
    /// adapter must collapse identity absence, throttling, and delivery state into its
    /// documented anti-enumeration response.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment that owns policy and SMTP configuration.</param>
    /// <param name="email">Untrusted e-mail selector supplied by the person.</param>
    /// <param name="cancellationToken">Cancels lookup, issuance, or delivery.</param>
    /// <returns>An internal outcome that the public endpoint must not reflect.</returns>
    public async Task<EmailPasswordRecoveryOutcome> RequestAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? email,
        CancellationToken cancellationToken = default)
    {
        RequireId(realmId, nameof(realmId));
        RequireId(appEnvironmentId, nameof(appEnvironmentId));

        if (!EmailPasswordAccessService.TryNormalizeEmail(email, out var normalizedEmail))
        {
            return EmailPasswordRecoveryOutcome.InvalidEmail;
        }

        // Public HTTP mapping must collapse IdentityNotFound into the same accepted shape
        // as Sent; keeping the distinction here preserves observability and internal use.
        var candidate = await store.FindByEmailAsync(
            realmId,
            appEnvironmentId,
            normalizedEmail,
            cancellationToken);
        var result = await SendAsync(candidate, appEnvironmentId, cancellationToken);
        return result.Outcome;
    }

    /// <summary>
    /// Requests recovery for an identity selected by trusted server orchestration and
    /// returns the issued token id for bounded compensation.
    /// </summary>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment that owns policy and SMTP configuration.</param>
    /// <param name="identityId">Identity selected by trusted server state, not public input.</param>
    /// <param name="cancellationToken">Cancels lookup, issuance, or delivery.</param>
    /// <returns>Operational outcome plus a compensatable token selector when issued.</returns>
    public async Task<EmailPasswordRecoveryResult> RequestForIdentityAsync(
        Guid realmId,
        Guid appEnvironmentId,
        Guid identityId,
        CancellationToken cancellationToken = default)
    {
        RequireId(realmId, nameof(realmId));
        RequireId(appEnvironmentId, nameof(appEnvironmentId));
        RequireId(identityId, nameof(identityId));

        var candidate = await store.FindByIdentityAsync(
            realmId,
            appEnvironmentId,
            identityId,
            cancellationToken);
        return await SendAsync(candidate, appEnvironmentId, cancellationToken);
    }

    /// <summary>Consumes an issued token when its coordinating operation cannot complete.</summary>
    /// <remarks>
    /// This best-effort compensation cannot retract an e-mail already accepted by the
    /// provider and does not imply that a password reset occurred.
    /// </remarks>
    /// <param name="tokenId">Durable selector returned by trusted issuance orchestration.</param>
    /// <param name="cancellationToken">Cancels the compensation attempt.</param>
    /// <returns>Whether this call consumed an otherwise active token.</returns>
    public Task<bool> InvalidateAsync(
        Guid tokenId,
        CancellationToken cancellationToken = default) =>
        passwordReset.InvalidateAsync(tokenId, cancellationToken);

    private async Task<EmailPasswordRecoveryResult> SendAsync(
        PasswordResetEmailCandidate? candidate,
        Guid appEnvironmentId,
        CancellationToken cancellationToken)
    {
        if (candidate is null)
        {
            return new EmailPasswordRecoveryResult(
                EmailPasswordRecoveryOutcome.IdentityNotFound,
                null);
        }
        var configuration = await configurations.FindAsync(
            appEnvironmentId,
            cancellationToken);
        if (configuration is null
            || configuration.RecoveryPolicy.PasswordRecoveryUrl is null)
        {
            return new EmailPasswordRecoveryResult(
                EmailPasswordRecoveryOutcome.EnvironmentNotConfigured,
                null);
        }
        if (!await emailSender.IsAvailableAsync(
                appEnvironmentId,
                cancellationToken))
        {
            return new EmailPasswordRecoveryResult(
                EmailPasswordRecoveryOutcome.DeliveryUnavailable,
                null);
        }

        var issueConstraint = new PasswordResetIssueConstraint(
            timeProvider.GetUtcNow().AddHours(-1),
            configuration.RecoveryPolicy.MaxRequestsPerHourPerIdentity);
        var issued = await passwordReset.IssueForEmailAsync(
            candidate.IdentityId,
            appEnvironmentId,
            candidate.Email,
            issueConstraint,
            cancellationToken);
        if (!issued.Succeeded)
        {
            return new EmailPasswordRecoveryResult(
                issued.Error == PasswordResetIssueError.RateLimited
                    ? EmailPasswordRecoveryOutcome.RateLimited
                    : EmailPasswordRecoveryOutcome.IdentityNotFound,
                null);
        }

        // The URL carries the only clear copy of the reset bearer. Keep it inside the
        // delivery boundary and never include it in logs or ordinary result objects.
        var resetUrl = $"{configuration.RecoveryPolicy.PasswordRecoveryUrl}?token={Uri.EscapeDataString(issued.Token)}";
        // The token is already durable before email is attempted. The returned token id
        // lets trusted orchestration invalidate it when its larger operation cannot
        // complete; the clear token itself never returns through that coordination path.
        var sent = await emailSender.TrySendAsync(
            appEnvironmentId,
            new PasswordRecoveryEmailDelivery(
                candidate.Email,
                candidate.AppName,
                resetUrl,
                configuration.RecoveryPolicy.TokenLifetimeMinutes),
            cancellationToken);
        // SMTP acceptance cannot prove inbox delivery. Conversely, a false provider
        // result cannot roll back the already committed token. Return its id so trusted
        // orchestration can attempt bounded compensation when required; cancellation is
        // propagated and therefore produces no result object.
        return new EmailPasswordRecoveryResult(
            sent
                ? EmailPasswordRecoveryOutcome.Sent
                : EmailPasswordRecoveryOutcome.DeliveryUnavailable,
            issued.TokenId);
    }

    private static void RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }
    }
}
