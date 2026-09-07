using System.Security.Cryptography;
using System.Text;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.Extensions.Logging;

namespace Bullgate.Access.Application.Recovery;

/// <summary>Stable failures for the two-step phone password-recovery journey.</summary>
public enum PhonePasswordRecoveryError
{
    /// <summary>Password, phone, verification, or Twilio recovery policy is disabled.</summary>
    RecoveryDisabled,

    /// <summary>No phone value was supplied.</summary>
    MissingPhone,

    /// <summary>The phone does not match the canonical Access shape.</summary>
    InvalidPhone,

    /// <summary>The public application-client key is malformed, unknown, or inactive.</summary>
    ApplicationClientInvalid,

    /// <summary>No confirmation code was supplied.</summary>
    MissingCode,

    /// <summary>The code or its challenge is wrong, inactive, exhausted, or ineligible.</summary>
    InvalidCode,

    /// <summary>Provider delivery, approval, or durable activation was unavailable.</summary>
    DeliveryUnavailable,
}

/// <summary>
/// Returns public timing for an accepted recovery request without revealing whether the
/// phone belongs to an identity.
/// </summary>
/// <param name="ExpiresAt">Advertised exclusive expiry for an accepted request.</param>
/// <param name="ResendAvailableAt">Advertised earliest time for another request.</param>
/// <param name="Error">Explicit input, configuration, or provider failure.</param>
public sealed record PhonePasswordRecoveryRequestResult(
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? ResendAvailableAt,
    PhonePasswordRecoveryError? Error)
{
    /// <summary>Indicates that an accepted public timing envelope was returned.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without challenge timing.</summary>
    public static PhonePasswordRecoveryRequestResult Failure(
        PhonePasswordRecoveryError error) =>
        new(null, null, error);
}

/// <summary>Returns a short-lived password-reset token after successful phone proof.</summary>
/// <remarks><see cref="Token"/> is clear reset authority and must not be logged.</remarks>
/// <param name="Token">Clear single-use password-reset bearer.</param>
/// <param name="ExpiresAt">UTC exclusive inactivity boundary of the bearer.</param>
/// <param name="Error">Stable failure category when no reset authority was issued.</param>
public sealed record PhonePasswordRecoveryConfirmResult(
    string? Token,
    DateTimeOffset? ExpiresAt,
    PhonePasswordRecoveryError? Error)
{
    /// <summary>Indicates that reset authority was issued after finalized phone proof.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only result without bearer material.</summary>
    public static PhonePasswordRecoveryConfirmResult Failure(
        PhonePasswordRecoveryError error) =>
        new(null, null, error);
}

/// <summary>
/// Coordinates local single-use verification challenges, external SMS delivery, and
/// issuance of password-reset authority.
/// </summary>
public sealed class PhonePasswordRecoveryService(
    IPhonePasswordRecoveryStore store,
    IAppEnvironmentConfigurationReader configurations,
    IPhoneVerificationSender phoneSender,
    IPasswordResetTokenService resetTokens,
    TimeProvider timeProvider,
    ILogger<PhonePasswordRecoveryService> logger)
{
    /// <summary>Exact number of ASCII digits accepted by phone recovery.</summary>
    private const int CodeDigits = 6;

    /// <summary>Starts an anti-enumerable phone recovery challenge when eligible.</summary>
    /// <remarks>
    /// Unknown phone ownership, hourly limit, and resend cooldown share the accepted
    /// timing envelope. Input, client configuration, policy, and provider failures remain
    /// explicit under the current transport contract.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment that owns recovery policy.</param>
    /// <param name="phone">Untrusted phone selector requiring canonical normalization.</param>
    /// <param name="applicationClientKey">Public client selector for delivery metadata.</param>
    /// <param name="cancellationToken">Cancels reservation, provider work, or finalization.</param>
    public async Task<PhonePasswordRecoveryRequestResult> RequestAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? phone,
        string? applicationClientKey,
        CancellationToken cancellationToken = default)
    {
        RequireId(realmId, nameof(realmId));
        RequireId(appEnvironmentId, nameof(appEnvironmentId));

        if (string.IsNullOrWhiteSpace(phone))
        {
            return PhonePasswordRecoveryRequestResult.Failure(
                PhonePasswordRecoveryError.MissingPhone);
        }
        if (!PhoneValue.TryNormalize(phone, out var normalizedPhone))
        {
            return PhonePasswordRecoveryRequestResult.Failure(
                PhonePasswordRecoveryError.InvalidPhone);
        }
        var configuration = await RequireConfigurationAsync(
            appEnvironmentId,
            cancellationToken);
        if (!IsRecoveryEnabled(configuration))
        {
            return PhonePasswordRecoveryRequestResult.Failure(
                PhonePasswordRecoveryError.RecoveryDisabled);
        }
        var bypass = IsDevelopmentBypass(
            configuration.DevelopmentBypass,
            normalizedPhone);
        if (!bypass
            && !await phoneSender.IsAvailableAsync(
                appEnvironmentId,
                cancellationToken))
        {
            return PhonePasswordRecoveryRequestResult.Failure(
                PhonePasswordRecoveryError.DeliveryUnavailable);
        }

        if (!TryValidateApplicationClientKey(
                applicationClientKey,
                out var validatedApplicationClientKey))
        {
            return PhonePasswordRecoveryRequestResult.Failure(
                PhonePasswordRecoveryError.ApplicationClientInvalid);
        }

        var applicationClient = await store.FindApplicationClientAsync(
            appEnvironmentId,
            validatedApplicationClientKey,
            cancellationToken);
        if (applicationClient is null)
        {
            return PhonePasswordRecoveryRequestResult.Failure(
                PhonePasswordRecoveryError.ApplicationClientInvalid);
        }
        var smsRetrieverAppHash = applicationClient.SmsRetrieverAppHash;

        var now = timeProvider.GetUtcNow();
        var policy = configuration.RecoveryPolicy;
        var accepted = new PhonePasswordRecoveryRequestResult(
            now.AddMinutes(policy.PhoneCodeLifetimeMinutes),
            now.AddSeconds(policy.PhoneResendCooldownSeconds),
            null);
        var candidate = await store.FindCandidateAsync(
            realmId,
            appEnvironmentId,
            normalizedPhone,
            cancellationToken);
        // Unknown phones receive the same accepted timings as known phones. This prevents
        // the request endpoint from becoming an account-enumeration oracle.
        if (candidate is null)
        {
            return accepted;
        }

        var code = bypass
            ? configuration.DevelopmentBypass.Code!
            : GenerateCode();
        var codeHash = HashCode(code);
        var challenge = new PhonePasswordResetChallenge(
            Guid.CreateVersion7(now),
            candidate.IdentityId,
            appEnvironmentId,
            normalizedPhone,
            codeHash,
            policy.PhoneCodeMaxAttempts,
            now,
            accepted.ExpiresAt!.Value,
            accepted.ResendAvailableAt!.Value);
        CryptographicOperations.ZeroMemory(codeHash);

        // Reserve and enforce cooldown/rate limits before causing an external SMS effect.
        // A rejected reservation intentionally keeps the anti-enumeration response.
        var reservation = await store.TryReserveAsync(
            realmId,
            challenge,
            now.AddHours(-1),
            policy.PhoneMaxRequestsPerHourPerIdentity,
            now,
            cancellationToken);
        if (reservation.Status != PhonePasswordRecoveryReservationStatus.Reserved)
        {
            return accepted;
        }

        var previous = reservation.SupersededChallenge;
        if (previous is
            {
                ProviderReference: not null,
                ProviderApprovedAt: null,
            })
        {
            try
            {
                await phoneSender.CancelAsync(
                    appEnvironmentId,
                    previous.ProviderReference,
                    cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await TryCompensateAsync(
                    compensationToken => store.TryRollbackReservationAsync(
                        challenge.Id,
                        previous.ChallengeId,
                        timeProvider.GetUtcNow(),
                        compensationToken),
                    challenge.Id,
                    "roll back a canceled phone password reset reservation");
                throw;
            }
            catch (Exception exception)
            {
                await TryCompensateAsync(
                    compensationToken => store.TryRollbackReservationAsync(
                        challenge.Id,
                        previous.ChallengeId,
                        timeProvider.GetUtcNow(),
                        compensationToken),
                    challenge.Id,
                    "roll back a failed phone password reset reservation");
                logger.LogWarning(
                    exception,
                    "Could not cancel superseded phone password reset challenge {ChallengeId}.",
                    previous.ChallengeId);
                return PhonePasswordRecoveryRequestResult.Failure(
                    PhonePasswordRecoveryError.DeliveryUnavailable);
            }
        }

        string? providerReference = null;
        if (!bypass)
        {
            try
            {
                providerReference = await phoneSender.SendAsync(
                    appEnvironmentId,
                    new PhoneVerificationDelivery(
                        normalizedPhone,
                        code,
                        smsRetrieverAppHash,
                        PhoneVerificationPurpose.PasswordReset),
                    cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await TryCancelAsync(
                    appEnvironmentId,
                    providerReference,
                    challenge.Id);
                await TryCompensateAsync(
                    compensationToken => store.FailDeliveryAsync(
                        challenge.Id,
                        timeProvider.GetUtcNow(),
                        compensationToken),
                    challenge.Id,
                    "close a canceled phone password reset delivery");
                throw;
            }
            catch (Exception exception)
            {
                await TryCancelAsync(
                    appEnvironmentId,
                    providerReference,
                    challenge.Id);
                await TryCompensateAsync(
                    compensationToken => store.FailDeliveryAsync(
                        challenge.Id,
                        timeProvider.GetUtcNow(),
                        compensationToken),
                    challenge.Id,
                    "close a failed phone password reset delivery");
                logger.LogWarning(
                    exception,
                    "Phone password reset delivery failed for challenge {ChallengeId}.",
                    challenge.Id);
                return PhonePasswordRecoveryRequestResult.Failure(
                    PhonePasswordRecoveryError.DeliveryUnavailable);
            }
        }
        // Delivery alone is not enough: the provider reference must be attached to the
        // durable challenge before the code is considered confirmable.
        if (!await store.TryActivateAsync(
                challenge.Id,
                providerReference,
                timeProvider.GetUtcNow(),
                cancellationToken))
        {
            await TryCancelAsync(
                appEnvironmentId,
                providerReference,
                challenge.Id);
            return PhonePasswordRecoveryRequestResult.Failure(
                PhonePasswordRecoveryError.DeliveryUnavailable);
        }

        return accepted;
    }

    /// <summary>Confirms one phone code and issues single-use password-reset authority.</summary>
    /// <remarks>
    /// Wrong, expired, exhausted, reused, wrong-scope, and ownership-invalidated
    /// challenges collapse to <see cref="PhonePasswordRecoveryError.InvalidCode"/>.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment that owns recovery policy.</param>
    /// <param name="phone">Same canonical phone used to start recovery.</param>
    /// <param name="code">Untrusted six-digit ASCII confirmation code.</param>
    /// <param name="cancellationToken">Cancels local or provider confirmation work.</param>
    public async Task<PhonePasswordRecoveryConfirmResult> ConfirmAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string? phone,
        string? code,
        CancellationToken cancellationToken = default)
    {
        RequireId(realmId, nameof(realmId));
        RequireId(appEnvironmentId, nameof(appEnvironmentId));

        if (string.IsNullOrWhiteSpace(phone))
        {
            return PhonePasswordRecoveryConfirmResult.Failure(
                PhonePasswordRecoveryError.MissingPhone);
        }
        if (!PhoneValue.TryNormalize(phone, out var normalizedPhone))
        {
            return PhonePasswordRecoveryConfirmResult.Failure(
                PhonePasswordRecoveryError.InvalidPhone);
        }
        if (string.IsNullOrWhiteSpace(code))
        {
            return PhonePasswordRecoveryConfirmResult.Failure(
                PhonePasswordRecoveryError.MissingCode);
        }

        var normalizedCode = code.Trim();
        if (!IsCode(normalizedCode))
        {
            return PhonePasswordRecoveryConfirmResult.Failure(
                PhonePasswordRecoveryError.InvalidCode);
        }
        var configuration = await RequireConfigurationAsync(
            appEnvironmentId,
            cancellationToken);
        if (!IsRecoveryEnabled(configuration))
        {
            return PhonePasswordRecoveryConfirmResult.Failure(
                PhonePasswordRecoveryError.RecoveryDisabled);
        }

        var codeHash = HashCode(normalizedCode);
        PhonePasswordRecoveryCodeCheck check;
        try
        {
            check = await store.TryBeginConfirmationAsync(
                realmId,
                appEnvironmentId,
                normalizedPhone,
                codeHash,
                timeProvider.GetUtcNow(),
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(codeHash);
        }

        // All non-ready states intentionally collapse to InvalidCode so expiry, exhaustion,
        // reuse, and wrong input cannot reveal the challenge lifecycle.
        if (check.Status != PhonePasswordRecoveryCodeCheckStatus.Ready)
        {
            if (check.CancelProvider)
            {
                await TryCancelAsync(
                    appEnvironmentId,
                    check.ProviderReference,
                    check.ChallengeId);
            }
            return PhonePasswordRecoveryConfirmResult.Failure(
                PhonePasswordRecoveryError.InvalidCode);
        }

        var bypass = IsDevelopmentBypass(
            configuration.DevelopmentBypass,
            normalizedPhone);
        DateTimeOffset providerApprovedAt;
        // The bypass is explicit environment configuration for controlled development;
        // production journeys must still receive provider approval before finalization.
        if (bypass)
        {
            providerApprovedAt = timeProvider.GetUtcNow();
        }
        else
        {
            try
            {
                await phoneSender.ApproveAsync(
                    appEnvironmentId,
                    check.ProviderReference,
                    cancellationToken);
                providerApprovedAt = timeProvider.GetUtcNow();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await TryReleaseConfirmationAsync(check.ChallengeId);
                throw;
            }
            catch (Exception exception)
            {
                await TryReleaseConfirmationAsync(check.ChallengeId);
                logger.LogWarning(
                    exception,
                    "Phone password reset provider approval failed for challenge {ChallengeId}.",
                    check.ChallengeId);
                return PhonePasswordRecoveryConfirmResult.Failure(
                    PhonePasswordRecoveryError.DeliveryUnavailable);
            }
        }

        var finalizedAt = timeProvider.GetUtcNow();
        var expiresAt = finalizedAt.AddMinutes(
            configuration.RecoveryPolicy.TokenLifetimeMinutes);
        var issued = resetTokens.Issue();
        PasswordResetToken resetToken;
        try
        {
            resetToken = new PasswordResetToken(
                Guid.CreateVersion7(finalizedAt),
                check.IdentityId,
                appEnvironmentId,
                issued.TokenHash,
                finalizedAt,
                expiresAt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issued.TokenHash);
        }

        // Provider approval crosses a transaction boundary. Finalization uses a bounded,
        // independent token so caller cancellation cannot discard already-proven authority.
        bool finalized;
        try
        {
            using var finalization = new CancellationTokenSource(
                TimeSpan.FromSeconds(5));
            finalized = await store.TryFinalizeAsync(
                check.ChallengeId,
                resetToken,
                providerApprovedAt,
                finalizedAt,
                finalization.Token);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Phone password reset finalization failed for challenge {ChallengeId} after provider approval.",
                check.ChallengeId);
            throw;
        }
        if (!finalized)
        {
            return PhonePasswordRecoveryConfirmResult.Failure(
                PhonePasswordRecoveryError.InvalidCode);
        }

        return new PhonePasswordRecoveryConfirmResult(
            issued.Token,
            expiresAt,
            null);
    }

    private async Task<AppEnvironmentConfiguration> RequireConfigurationAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        await configurations.FindAsync(appEnvironmentId, cancellationToken)
        ?? throw new InvalidOperationException(
            "The app environment configuration could not be resolved.");

    private static bool IsRecoveryEnabled(
        AppEnvironmentConfiguration configuration) =>
        configuration.AccessPolicy.Authenticators.PasswordEnabled
            && configuration.AccessPolicy.Phone.Enabled
            && configuration.AccessPolicy.Phone.Verification.Enabled
            && string.Equals(
                configuration.AccessPolicy.Phone.Verification.Provider,
                VerificationProviderKey.TwilioVerify,
                StringComparison.Ordinal);

    private static bool IsDevelopmentBypass(
        DevelopmentBypassConfiguration bypass,
        string normalizedPhone) =>
        bypass.Enabled
        && string.Equals(bypass.Phone?.Trim(), normalizedPhone, StringComparison.Ordinal);

    private async Task TryReleaseConfirmationAsync(Guid challengeId) =>
        await TryCompensateAsync(
            compensationToken => store.TryReleaseConfirmationAsync(
                challengeId,
                timeProvider.GetUtcNow(),
                compensationToken),
            challengeId,
            "release a phone password reset confirmation");

    private async Task TryCancelAsync(
        Guid appEnvironmentId,
        string? providerReference,
        Guid challengeId)
    {
        if (providerReference is null)
        {
            return;
        }

        try
        {
            using var compensation = new CancellationTokenSource(
                TimeSpan.FromSeconds(5));
            await phoneSender.CancelAsync(
                appEnvironmentId,
                providerReference,
                compensation.Token);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Could not cancel phone password reset provider verification for challenge {ChallengeId}.",
                challengeId);
        }
    }

    private async Task TryCompensateAsync(
        Func<CancellationToken, Task> compensate,
        Guid challengeId,
        string operation)
    {
        try
        {
            using var compensation = new CancellationTokenSource(
                TimeSpan.FromSeconds(5));
            await compensate(compensation.Token);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Could not {Operation} for challenge {ChallengeId}.",
                operation,
                challengeId);
        }
    }

    private static bool IsCode(string value) =>
        value.Length == CodeDigits && value.All(char.IsAsciiDigit);

    private static bool TryValidateApplicationClientKey(
        string? value,
        out string validatedKey)
    {
        try
        {
            validatedKey = TopologyValue.Key(value!, nameof(value));
            return true;
        }
        catch (ArgumentException)
        {
            validatedKey = string.Empty;
            return false;
        }
    }

    private static string GenerateCode() =>
        RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");

    private static byte[] HashCode(string code) =>
        SHA256.HashData(Encoding.ASCII.GetBytes(code));

    private static void RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }
    }
}
