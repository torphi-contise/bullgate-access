using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.Application.Recovery;

/// <summary>
/// Transactional store for phone-recovery reservation, delivery state, code checks,
/// rate limits, and reset-token issuance.
/// </summary>
public interface IPhonePasswordRecoveryStore
{
    /// <summary>
    /// Resolves active public-client metadata inside the already authenticated app
    /// environment.
    /// </summary>
    /// <remarks>
    /// The application-client key selects message metadata such as the Android SMS
    /// Retriever hash. It is public metadata and does not authorize recovery.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="applicationClientKey">Validated public client selector.</param>
    /// <param name="cancellationToken">Cancels the metadata query.</param>
    Task<PhonePasswordRecoveryApplicationClient?> FindApplicationClientAsync(
        Guid appEnvironmentId,
        string applicationClientKey,
        CancellationToken cancellationToken);

    /// <summary>
    /// Finds an active identity that currently owns the verified phone and is eligible
    /// for password recovery in the requested realm and environment.
    /// </summary>
    /// <remarks>
    /// This lookup supports anti-enumerable request handling. Reservation must recheck
    /// the same facts transactionally because ownership or policy may change afterward.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment that owns recovery policy.</param>
    /// <param name="normalizedPhone">Canonical phone used only for candidate discovery.</param>
    /// <param name="cancellationToken">Cancels the preliminary query.</param>
    Task<PhonePasswordRecoveryCandidate?> FindCandidateAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string normalizedPhone,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically revalidates eligibility, enforces rate and resend limits, supersedes
    /// an eligible open challenge, and reserves the new challenge before SMS delivery.
    /// </summary>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="challenge">New pending-delivery challenge to reserve.</param>
    /// <param name="rateWindowStartsAt">Inclusive UTC start of the issuance-count window.</param>
    /// <param name="maximumRequests">Maximum identity reservations across environments.</param>
    /// <param name="reservedAt">UTC time used for cooldown and supersession decisions.</param>
    /// <param name="cancellationToken">Cancels the atomic reservation.</param>
    Task<PhonePasswordRecoveryReservation> TryReserveAsync(
        Guid realmId,
        PhonePasswordResetChallenge challenge,
        DateTimeOffset rateWindowStartsAt,
        int maximumRequests,
        DateTimeOffset reservedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes a still-pending reservation after delivery failure and restores its
    /// safely reusable predecessor when possible.
    /// </summary>
    /// <param name="challengeId">Pending replacement reservation to remove.</param>
    /// <param name="supersededChallengeId">Optional predecessor considered for restoration.</param>
    /// <param name="rolledBackAt">UTC time used to reject expired restoration.</param>
    /// <param name="cancellationToken">Cancels the compensating transaction.</param>
    /// <returns>Whether the pending replacement was still eligible for rollback.</returns>
    Task<bool> TryRollbackReservationAsync(
        Guid challengeId,
        Guid? supersededChallengeId,
        DateTimeOffset rolledBackAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Makes a delivered, unexpired reservation available for code confirmation and
    /// records the provider reference used for later approval or cancellation.
    /// </summary>
    /// <param name="challengeId">Pending reservation whose delivery completed.</param>
    /// <param name="providerReference">Opaque provider operation id, or bypass absence.</param>
    /// <param name="activatedAt">UTC delivery-finalization time before expiry.</param>
    /// <param name="cancellationToken">Cancels the activation transaction.</param>
    /// <returns>Whether the reservation became active.</returns>
    Task<bool> TryActivateAsync(
        Guid challengeId,
        string? providerReference,
        DateTimeOffset activatedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Marks a still-pending challenge as failed when no usable delivery was produced.
    /// </summary>
    /// <param name="challengeId">Pending reservation to close.</param>
    /// <param name="failedAt">UTC terminal-transition time.</param>
    /// <param name="cancellationToken">Cancels the failure transaction.</param>
    Task FailDeliveryAsync(
        Guid challengeId,
        DateTimeOffset failedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically checks current scope and phone ownership, records an OTP failure or
    /// reserves a valid challenge for one confirmer.
    /// </summary>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment that owns the challenge.</param>
    /// <param name="normalizedPhone">Canonical phone repeated by the confirmer.</param>
    /// <param name="codeHash">Fixed-size hash of the untrusted submitted code.</param>
    /// <param name="attemptedAt">UTC time for activity and exhaustion decisions.</param>
    /// <param name="cancellationToken">Cancels the confirmation reservation.</param>
    Task<PhonePasswordRecoveryCodeCheck> TryBeginConfirmationAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string normalizedPhone,
        byte[] codeHash,
        DateTimeOffset attemptedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Releases a confirmation reservation after provider failure, unless expiry makes
    /// the challenge terminal.
    /// </summary>
    /// <param name="challengeId">Exclusively confirming challenge.</param>
    /// <param name="releasedAt">UTC provider-failure time.</param>
    /// <param name="cancellationToken">Cancels the release transaction.</param>
    /// <returns>Whether a confirming row was released or terminally closed.</returns>
    Task<bool> TryReleaseConfirmationAsync(
        Guid challengeId,
        DateTimeOffset releasedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically completes provider-approved confirmation and persists the resulting
    /// password-reset authority after revalidating identity, environment, and phone.
    /// </summary>
    /// <param name="challengeId">Exclusively confirming challenge.</param>
    /// <param name="resetToken">New hashed reset authority bound to the challenge owner.</param>
    /// <param name="providerApprovedAt">UTC provider-approval time.</param>
    /// <param name="completedAt">UTC local finalization time.</param>
    /// <param name="cancellationToken">Cancels the finalization transaction.</param>
    /// <returns>Whether proof completion and reset-token persistence committed together.</returns>
    Task<bool> TryFinalizeAsync(
        Guid challengeId,
        PasswordResetToken resetToken,
        DateTimeOffset providerApprovedAt,
        DateTimeOffset completedAt,
        CancellationToken cancellationToken);
}

/// <summary>Application-client metadata used to format a phone recovery message.</summary>
/// <param name="ApplicationClientId">Durable application-client identifier; grants no authority.</param>
/// <param name="ApplicationClientKey">Stable public key returned for diagnostics.</param>
/// <param name="SmsRetrieverAppHash">Optional Android SMS Retriever message suffix.</param>
public sealed record PhonePasswordRecoveryApplicationClient(
    Guid ApplicationClientId,
    string ApplicationClientKey,
    string? SmsRetrieverAppHash);

/// <summary>Identity eligible for phone-based password recovery.</summary>
/// <param name="IdentityId">Preliminary candidate that reservation must revalidate.</param>
public sealed record PhonePasswordRecoveryCandidate(Guid IdentityId);

/// <summary>Transactional outcomes of challenge reservation and rate enforcement.</summary>
public enum PhonePasswordRecoveryReservationStatus
{
    /// <summary>The pending-delivery challenge committed.</summary>
    Reserved,

    /// <summary>Identity, phone ownership, realm, or environment lost eligibility.</summary>
    IdentityIneligible,

    /// <summary>The per-identity hourly durable-reservation limit was reached.</summary>
    RateLimited,

    /// <summary>The latest durable request still owns its resend cooldown.</summary>
    ResendTooSoon,
}

/// <summary>Previous challenge that may require provider cancellation after replacement.</summary>
/// <param name="ChallengeId">Durable predecessor identifier.</param>
/// <param name="ProviderReference">Opaque provider operation identifier, when present.</param>
/// <param name="ProviderApprovedAt">UTC provider-approval time, when already approved.</param>
public sealed record PhonePasswordRecoverySupersededChallenge(
    Guid ChallengeId,
    string? ProviderReference,
    DateTimeOffset? ProviderApprovedAt);

/// <summary>Reservation outcome and the challenge it safely superseded, when any.</summary>
/// <param name="Status">Authoritative transactional reservation outcome.</param>
/// <param name="SupersededChallenge">Predecessor metadata used only for bounded cleanup.</param>
public sealed record PhonePasswordRecoveryReservation(
    PhonePasswordRecoveryReservationStatus Status,
    PhonePasswordRecoverySupersededChallenge? SupersededChallenge = null);

/// <summary>Collapsed result of validating and reserving a phone recovery code.</summary>
public enum PhonePasswordRecoveryCodeCheckStatus
{
    /// <summary>Local proof matched and one confirmer owns the challenge.</summary>
    Ready,

    /// <summary>Every absent, inactive, wrong, exhausted, or ineligible state.</summary>
    InvalidCode,
}

/// <summary>
/// Confirmation reservation state including provider cleanup instructions.
/// </summary>
/// <param name="Status">Collapsed application-layer readiness class.</param>
/// <param name="ChallengeId">Durable challenge selector when cleanup or finalization applies.</param>
/// <param name="IdentityId">Authoritative proof owner only when status is ready.</param>
/// <param name="ProviderReference">Opaque provider operation identifier.</param>
/// <param name="ProviderApprovedAt">Existing provider approval, when present.</param>
/// <param name="CancelProvider">Whether an unapproved provider operation should be canceled.</param>
public sealed record PhonePasswordRecoveryCodeCheck(
    PhonePasswordRecoveryCodeCheckStatus Status,
    Guid ChallengeId = default,
    Guid IdentityId = default,
    string? ProviderReference = null,
    DateTimeOffset? ProviderApprovedAt = null,
    bool CancelProvider = false);
