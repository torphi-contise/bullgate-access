using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.Application.Flows;

/// <summary>
/// Transactional persistence boundary for the AccessFlow state machine.
/// </summary>
/// <remarks>
/// Implementations arbitrate request idempotency, optimistic revisions, source
/// session validity, identity ownership, and external-effect reservations in
/// PostgreSQL. Service-layer prechecks must not replace these commit-time guards.
/// </remarks>
public interface IAccessFlowStore
{
    /// <summary>
    /// Finds a previous request in integration-client scope so an exact replay can
    /// reproduce its stored result or reject a mismatched payload hash.
    /// </summary>
    /// <param name="integrationClientId">Authenticated idempotency namespace owner.</param>
    /// <param name="requestId">Caller-generated request selector within that namespace.</param>
    /// <param name="cancellationToken">Cancels the persistence read.</param>
    /// <returns>
    /// Durable replay state including the original hash and exact result, or
    /// <see langword="null"/> when this integration client has not used the id.
    /// </returns>
    Task<StoredAccessFlowRequest?> FindRequestAsync(
        Guid integrationClientId,
        Guid requestId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Performs a preliminary lookup of the active registration session and open
    /// registration context required by <see cref="AccessFlowIntent.ContinueRegistration"/>.
    /// </summary>
    Task<ContinueRegistrationCandidate?> FindContinueRegistrationCandidateAsync(
        AccessFlowScope scope,
        byte[] sessionTokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Performs a preliminary lookup of the active product session required by
    /// <see cref="AccessFlowIntent.ManagePhone"/>.
    /// </summary>
    Task<ManagePhoneCandidate?> FindManagePhoneCandidateAsync(
        AccessFlowScope scope,
        byte[] sessionTokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>Finds active public-client delivery metadata by its stable public key.</summary>
    Task<ApplicationClientVerificationMetadata?> FindApplicationClientAsync(
        Guid appEnvironmentId,
        string applicationClientKey,
        CancellationToken cancellationToken);

    /// <summary>Re-resolves active public-client delivery metadata by internal id.</summary>
    Task<ApplicationClientVerificationMetadata?> FindApplicationClientAsync(
        Guid appEnvironmentId,
        Guid applicationClientId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads the current active phone challenge and unresolved ownership conflict used
    /// to construct a flow snapshot.
    /// </summary>
    Task<PhoneJourneyState> FindPhoneJourneyAsync(
        Guid flowId,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Counts recent non-delivery-failed challenges for per-identity rate enforcement.
    /// </summary>
    /// <remarks>
    /// A provider delivery failure does not spend the AccessFlow challenge quota because
    /// no usable proof attempt reached the person.
    /// </remarks>
    Task<int> CountRecentChallengesAsync(
        Guid identityId,
        ProofChallengeType type,
        DateTimeOffset since,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads the current realm-scoped phone owner as an expected-state input for a later
    /// transactional ownership guard.
    /// </summary>
    Task<PhoneIdentifierOwner?> FindPhoneOwnerAsync(
        Guid realmId,
        string normalizedPhone,
        CancellationToken cancellationToken);

    /// <summary>Reads the current realm owner of one normalized identifier value.</summary>
    Task<Guid?> FindIdentifierOwnerAsync(
        Guid realmId,
        string scheme,
        string normalizedValue,
        CancellationToken cancellationToken);

    /// <summary>
    /// Performs the advisory read used to plan resume or exact stale-flow expiration.
    /// <see cref="TryCreateAsync"/> remains authoritative for active-slot ownership.
    /// </summary>
    Task<StoredAccessFlow?> FindActiveFlowBySourceAsync(
        Guid sourceSessionId,
        AccessFlowIntent intent,
        CancellationToken cancellationToken);

    /// <summary>
    /// Creates, resumes, expires-and-replaces, or rejects a flow atomically after
    /// revalidating identity, source session, registration context, request uniqueness,
    /// and active-slot ownership under locks.
    /// </summary>
    Task<AccessFlowCreateResult> TryCreateAsync(
        AccessFlow flow,
        AccessFlowRevision revision,
        AccessFlowRequest request,
        ExpireActiveAccessFlowCommand? expiredFlow,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads a flow and its current immutable snapshot only when every authenticated
    /// scope component matches.
    /// </summary>
    Task<StoredAccessFlow?> FindFlowAsync(
        AccessFlowScope scope,
        Guid flowId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Completes an open registration context, commits its terminal snapshot and
    /// product session, and revokes the registration authority used by the flow.
    /// </summary>
    Task<AccessFlowCommitStatus> TryCompleteRegistrationAsync(
        CompleteRegistrationFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the identity's selected phone, invalidates stale recovery artifacts,
    /// completes the flow, and rotates its source product session atomically.
    /// </summary>
    Task<AccessFlowCommitStatus> TryCompletePhoneManagementAsync(
        CompletePhoneManagementFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically validates request uniqueness and expected revision, advances the
    /// state machine, and stores the resulting immutable snapshot.
    /// </summary>
    Task<AccessFlowCommitStatus> TryAdvanceAsync(
        AdvanceAccessFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Stores phone, or CPF and birth date together, while advancing an unfinished registration.
    /// </summary>
    Task<AccessFlowCommitStatus> TryAdvanceRegistrationWithIdentifierAsync(
        AdvanceRegistrationWithIdentifierFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically reserves a pending-delivery proof challenge and its idempotency
    /// request after revalidating flow revision, phone ownership, cooldown, and quota.
    /// </summary>
    Task<AccessFlowCommitStatus> TryCreateProofChallengeAsync(
        CreateProofChallengeFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Activates a successfully delivered challenge, supersedes older active challenges,
    /// and commits the exact resulting flow snapshot.
    /// </summary>
    Task<AccessFlowCommitStatus> TryFinalizeProofChallengeDeliveryAsync(
        FinalizeProofChallengeDeliveryFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Marks both the pending challenge and its reserved request failed when delivery
    /// does not complete.
    /// </summary>
    Task<AccessFlowCommitStatus> TryFailProofChallengeDeliveryAsync(
        FailProofChallengeDeliveryFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically records a failed local proof attempt at the expected challenge count,
    /// advances the flow, and stores the exact feedback snapshot.
    /// </summary>
    Task<AccessFlowCommitStatus> TryRecordFailedProofAttemptAsync(
        RecordFailedProofAttemptFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reserves an active phone challenge for one finalizer after revalidating revision,
    /// attempt count, and expected phone ownership under locks.
    /// </summary>
    Task<AccessFlowCommitStatus> TryBeginPhoneConfirmationAsync(
        BeginPhoneConfirmationFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Releases an exclusive phone-confirmation reservation when final persistence
    /// cannot commit, and closes the failed idempotency request.
    /// </summary>
    Task<AccessFlowCommitStatus> TryReleasePhoneConfirmationAsync(
        ReleasePhoneConfirmationFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically commits local phone proof, ownership or conflict state, immutable
    /// snapshot, and any resulting product session.
    /// </summary>
    Task<AccessFlowCommitStatus> TryConfirmPhoneAsync(
        ConfirmPhoneFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically records a failed previous-e-mail knowledge check at the expected
    /// attempt count and stores the resulting conflict snapshot.
    /// </summary>
    Task<AccessFlowCommitStatus> TryRecordPhoneConflictEmailFailureAsync(
        RecordPhoneConflictEmailFailureFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Transfers a phone already proven by the current flow after revalidating the
    /// previous owner, exact e-mail match, attempt budget, and source session.
    /// </summary>
    Task<AccessFlowCommitStatus> TryTransferPhoneAsync(
        TransferPhoneFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Abandons the current phone-conflict branch, closes its active challenges, and
    /// returns the flow to phone collection at a new revision.
    /// </summary>
    Task<AccessFlowCommitStatus> TryChangePhoneAsync(
        ChangePhoneFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Revalidates the previous-identity recovery invariants under locks and persists
    /// a pending external request before a password-reset e-mail is attempted.
    /// </summary>
    /// <remarks>
    /// The previous identity and phone ids are expected values captured from trusted
    /// state, not client authority or a client-selected delivery destination.
    /// </remarks>
    Task<AccessFlowCommitStatus> TryReservePreviousIdentityRecoveryAsync(
        ReservePreviousIdentityRecoveryFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Revalidates a pending recovery request after e-mail acceptance, abandons the
    /// provisional registration identity, and commits the terminal flow snapshot.
    /// </summary>
    /// <remarks>
    /// Success retains the previous identity and phone but does not issue a product
    /// session or prove that the recovery e-mail reached an inbox.
    /// </remarks>
    Task<AccessFlowCommitStatus> TryFinalizePreviousIdentityRecoveryAsync(
        RecoverPreviousIdentityFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Marks the matching pending external request as failed when delivery or later
    /// finalization cannot complete. It does not undo an external provider effect.
    /// </summary>
    Task<AccessFlowCommitStatus> TryFailPreviousIdentityRecoveryAsync(
        FailPreviousIdentityRecoveryFlowCommand command,
        CancellationToken cancellationToken);

    /// <summary>
    /// Expires an active flow at an expected revision and closes any pending external
    /// reservation in the same transaction. Expiration does not revoke the source
    /// identity session or undo an effect already accepted by an external provider.
    /// </summary>
    Task<AccessFlowCommitStatus> TryExpireAsync(
        ExpireAccessFlowCommand command,
        CancellationToken cancellationToken);
}

/// <summary>Resolved registration context and source session authorized to start a flow.</summary>
public sealed record ContinueRegistrationCandidate(
    Guid IdentityId,
    Guid RegistrationContextId,
    Guid SessionId);

/// <summary>Resolved product identity and source session authorized to manage its phone.</summary>
public sealed record ManagePhoneCandidate(Guid IdentityId, Guid SessionId);

/// <summary>Public build metadata required to format phone verification delivery.</summary>
public sealed record ApplicationClientVerificationMetadata(
    Guid ApplicationClientId,
    string ApplicationClientKey,
    string? SmsRetrieverAppHash);

/// <summary>Persistence projection of the current proof challenge and its attempt limits.</summary>
public sealed record StoredProofChallenge(
    Guid ChallengeId,
    ProofChallengeType Type,
    string DestinationValue,
    byte[] SecretHash,
    string? ProviderReference,
    int Attempts,
    int MaxAttempts,
    DateTimeOffset ExpiresAt,
    DateTimeOffset ResendAvailableAt);

/// <summary>Persistence projection of an unresolved phone owner conflict.</summary>
/// <param name="PreviousIdentityId">Expected active owner of the verified phone.</param>
/// <param name="ConflictingIdentifierId">Exact phone identifier proven by the flow.</param>
/// <param name="PreviousEmailIdentifierId">Optional current e-mail identifier selector.</param>
/// <param name="PreviousEmail">Optional canonical e-mail used only for masked hints.</param>
/// <param name="FailedEmailAttempts">Committed incorrect e-mail attempts for phone transfer.</param>
/// <param name="EmailResolutionExhaustedAt">UTC time e-mail-based transfer was exhausted.</param>
/// <param name="ExpiresAt">UTC exclusive conflict-resolution boundary.</param>
public sealed record StoredPhoneRegistrationConflict(
    Guid PreviousIdentityId,
    Guid ConflictingIdentifierId,
    Guid? PreviousEmailIdentifierId,
    string? PreviousEmail,
    int FailedEmailAttempts,
    DateTimeOffset? EmailResolutionExhaustedAt,
    DateTimeOffset ExpiresAt);

/// <summary>Current phone challenge and ownership-conflict state for snapshot construction.</summary>
public sealed record PhoneJourneyState(
    StoredProofChallenge? ActivePhoneChallenge,
    StoredPhoneRegistrationConflict? PhoneConflict);

/// <summary>Expected owner used as a commit-time guard against phone ownership races.</summary>
public sealed record PhoneIdentifierOwner(
    Guid IdentifierId,
    Guid IdentityId,
    string? Email,
    bool IsVerified);

/// <summary>Current durable flow projection including its latest serialized snapshot.</summary>
/// <param name="FlowId">Flow selector used for capability derivation.</param>
/// <param name="IdentityId">Identity executing the journey.</param>
/// <param name="RegistrationContextId">Registration context when intent requires one.</param>
/// <param name="SourceSessionId">Session that originally authorized the flow.</param>
/// <param name="ApplicationClientId">Resolved public application-client record.</param>
/// <param name="Status">Current active or terminal lifecycle state.</param>
/// <param name="ProtocolVersion">Negotiated protocol fixed at creation.</param>
/// <param name="Intent">Journey type fixed at creation.</param>
/// <param name="CurrentRevision">Latest committed revision, not necessarily a replay result.</param>
/// <param name="ExpiresAt">UTC exclusive flow lifetime boundary.</param>
/// <param name="SnapshotJson">Latest current snapshot, not necessarily the request snapshot.</param>
public sealed record StoredAccessFlow(
    Guid FlowId,
    Guid IdentityId,
    Guid? RegistrationContextId,
    Guid SourceSessionId,
    Guid ApplicationClientId,
    AccessFlowStatus Status,
    int ProtocolVersion,
    AccessFlowIntent Intent,
    int CurrentRevision,
    DateTimeOffset ExpiresAt,
    string SnapshotJson);

/// <summary>
/// Durable session scope and token hash used to reproduce and verify the clear terminal
/// token for an exact committed-request replay.
/// </summary>
/// <param name="IdentityId">Owner encoded into deterministic session derivation.</param>
/// <param name="SessionId">Persisted session selected by the committed request.</param>
/// <param name="TokenHash">Verifier for the deterministically rederived clear token.</param>
/// <param name="ExpiresAt">UTC session expiration returned by replay.</param>
/// <param name="Purpose">Registration or product authority class.</param>
public sealed record StoredAccessFlowIssuedSession(
    Guid IdentityId,
    Guid SessionId,
    byte[] TokenHash,
    DateTimeOffset ExpiresAt,
    IdentitySessionPurpose Purpose);

/// <summary>
/// Durable idempotency projection containing the original payload hash, current flow,
/// immutable result snapshot, and optional issued-session verifier.
/// </summary>
/// <param name="PayloadHash">Original canonical-input hash compared during replay.</param>
/// <param name="Status">Committed, pending-external, or external-failed state.</param>
/// <param name="Flow">Current flow state used for scope and capability derivation.</param>
/// <param name="SnapshotJson">Exact result-revision JSON only when committed.</param>
/// <param name="IssuedSession">Optional committed session verifier for clear-token replay.</param>
public sealed record StoredAccessFlowRequest(
    byte[] PayloadHash,
    AccessFlowRequestStatus Status,
    StoredAccessFlow Flow,
    string? SnapshotJson,
    StoredAccessFlowIssuedSession? IssuedSession);

/// <summary>Transactional outcomes of starting, resuming, or replacing a flow.</summary>
public enum AccessFlowCreateStatus
{
    /// <summary>A new flow, initial revision, and start request were committed.</summary>
    Created,

    /// <summary>The compatible active flow was returned and the new start request recorded.</summary>
    Resumed,

    /// <summary>The integration-scoped request id already names a durable request.</summary>
    RequestAlreadyExists,

    /// <summary>
    /// An expired or concurrently created flow owns the active source/intent slot and
    /// the caller must refresh its expiration proposal before retrying.
    /// </summary>
    ExistingFlowExpired,

    /// <summary>Registration authority or its open context no longer qualifies.</summary>
    RegistrationNotPending,

    /// <summary>The product source session no longer qualifies for phone management.</summary>
    SourceSessionInactive,

    /// <summary>The active flow belongs to a different public application client.</summary>
    ApplicationClientInvalid,

    /// <summary>The active flow belongs to a different integration client.</summary>
    IntegrationClientConflict,
}

/// <summary>
/// Returns the creation outcome and, when reconciliation needs it, the authoritative
/// existing flow snapshot observed under the creation transaction.
/// </summary>
public sealed record AccessFlowCreateResult(
    AccessFlowCreateStatus Status,
    StoredAccessFlow? Flow = null);

/// <summary>
/// Describes the exact stale flow revision that creation may expire before inserting
/// its replacement under the same source-session and intent slot.
/// </summary>
public sealed record ExpireActiveAccessFlowCommand(
    Guid FlowId,
    int ExpectedRevision,
    string SnapshotJson,
    DateTimeOffset ExpiredAt);

/// <summary>
/// Transactional outcomes shared by flow transitions and external-effect reservations.
/// </summary>
public enum AccessFlowCommitStatus
{
    /// <summary>The requested transition and its durable result were committed.</summary>
    Committed,

    /// <summary>The integration-scoped request id already names another durable attempt.</summary>
    RequestAlreadyExists,

    /// <summary>No flow exists inside the complete authenticated scope.</summary>
    FlowNotFound,

    /// <summary>The flow is no longer active at the expected revision and time.</summary>
    RevisionConflict,

    /// <summary>The registration session or context required by the intent is unavailable.</summary>
    RegistrationNotPending,

    /// <summary>The product session that authorized the flow is no longer active.</summary>
    SourceSessionInactive,

    /// <summary>The expected proof challenge cannot accept the requested transition.</summary>
    ProofChallengeNotActive,

    /// <summary>The identity has exhausted the configured recent-challenge quota.</summary>
    ChallengeRateLimited,

    /// <summary>The active challenge has not reached its resend-available time.</summary>
    ChallengeResendTooSoon,

    /// <summary>This request durably owns the next external provider effect.</summary>
    ExternalOperationReserved,

    /// <summary>Another live request currently owns an external provider effect.</summary>
    ExternalOperationPending,

    /// <summary>The reserved external effect or its later finalization failed.</summary>
    ExternalOperationFailed,

    /// <summary>The phone no longer has the ownership state expected by the caller.</summary>
    PhoneOwnershipChanged,

    /// <summary>The expected unresolved phone conflict is absent, expired, or changed.</summary>
    PhoneConflictNotPending,

    /// <summary>The relevant proof or conflict-resolution attempt budget is exhausted.</summary>
    TooManyAttempts,
}

/// <summary>
/// Carries all server-created state required to complete registration and replace its
/// registration authority with a product session in one transaction.
/// </summary>
public sealed record CompleteRegistrationFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    IdentityIdentifier? Identifier,
    IdentitySession ProductSession,
    DateTimeOffset CompletedAt,
    DateOnly? BirthDate = null);

/// <summary>
/// Carries the selected normalized phone and server-issued product session required to
/// finish phone management while rotating the source product session.
/// </summary>
public sealed record CompletePhoneManagementFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    string NormalizedPhone,
    IdentitySession ProductSession,
    DateTimeOffset CompletedAt);

/// <summary>Persists a purely internal transition and its next immutable snapshot.</summary>
public sealed record AdvanceAccessFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    DateTimeOffset AdvancedAt);

/// <summary>Persists a collected identifier and accompanying birth date before the next step.</summary>
public sealed record AdvanceRegistrationWithIdentifierFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    IdentityIdentifier Identifier,
    DateOnly? BirthDate,
    DateTimeOffset AdvancedAt);

/// <summary>Reserves a new proof challenge before the external delivery effect.</summary>
public sealed record CreateProofChallengeFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    ProofChallenge Challenge,
    DateTimeOffset RateWindowStartsAt,
    int MaxRequestsInRateWindow,
    DateTimeOffset CreatedAt);

/// <summary>Commits delivery metadata and the snapshot that exposes the active challenge.</summary>
public sealed record FinalizeProofChallengeDeliveryFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    Guid ChallengeId,
    string? ProviderReference,
    DateTimeOffset FinalizedAt);

/// <summary>Closes a reserved proof challenge whose external delivery did not complete.</summary>
public sealed record FailProofChallengeDeliveryFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    Guid ChallengeId,
    DateTimeOffset FailedAt);

/// <summary>Atomically increments proof attempts and stores the resulting feedback.</summary>
public sealed record RecordFailedProofAttemptFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    Guid ChallengeId,
    int ExpectedChallengeAttempts,
    ProofAttempt Attempt,
    DateTimeOffset AttemptedAt);

/// <summary>Reserves one confirmation attempt with expected challenge and owner state.</summary>
public sealed record BeginPhoneConfirmationFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    Guid ChallengeId,
    int ExpectedChallengeAttempts,
    string NormalizedPhone,
    PhoneIdentifierOwner? ExpectedOwner,
    DateTimeOffset BeganAt);

/// <summary>Releases a confirmation reservation after final persistence cannot commit.</summary>
public sealed record ReleasePhoneConfirmationFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    Guid ChallengeId,
    DateTimeOffset ReleasedAt);

/// <summary>
/// Atomically records phone proof and either assigns the identifier or opens a conflict.
/// </summary>
public sealed record ConfirmPhoneFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    Guid ChallengeId,
    int ExpectedChallengeAttempts,
    string NormalizedPhone,
    PhoneIdentifierOwner? ExpectedOwner,
    IdentityIdentifier? NewPhoneIdentifier,
    ProofAttempt Attempt,
    IdentityProof Proof,
    PhoneRegistrationConflict? PhoneConflict,
    IdentitySession? ProductSession,
    DateTimeOffset ConfirmedAt,
    bool ContinueRegistration = false);

/// <summary>Records one failed previous-e-mail knowledge check during conflict resolution.</summary>
public sealed record RecordPhoneConflictEmailFailureFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    int ExpectedAttempts,
    int MaxAttempts,
    DateTimeOffset AttemptedAt);

/// <summary>
/// Transfers a phone proven by the current flow after an exact previous-e-mail
/// knowledge check. The e-mail comparison is not possession proof of that mailbox.
/// </summary>
public sealed record TransferPhoneFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    int ExpectedAttempts,
    int MaxAttempts,
    Guid ExpectedPreviousIdentityId,
    string NormalizedPreviousEmail,
    IdentitySession? ProductSession,
    DateTimeOffset CompletedAt,
    bool ContinueRegistration = false);

/// <summary>Returns an unresolved conflict journey to phone collection.</summary>
public sealed record ChangePhoneFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    DateTimeOffset ChangedAt);

/// <summary>
/// Finalizes the flow after password recovery was requested for the previous identity
/// that still owns the phone proven by the provisional registration identity.
/// </summary>
/// <param name="Scope">Authenticated integration client, environment, and realm.</param>
/// <param name="FlowId">Flow selected inside that scope.</param>
/// <param name="RequestId">Idempotency key that owns the pending external request.</param>
/// <param name="PayloadHash">Hash required to match the reserved action payload exactly.</param>
/// <param name="ExpectedRevision">Revision on which the action was advertised.</param>
/// <param name="SnapshotJson">Terminal snapshot persisted only if finalization commits.</param>
/// <param name="ExpectedPreviousIdentityId">Server-derived retained identity guard.</param>
/// <param name="ExpectedPhoneIdentifierId">Server-derived verified phone ownership guard.</param>
/// <param name="CompletedAt">UTC finalization time.</param>
public sealed record RecoverPreviousIdentityFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    string SnapshotJson,
    Guid ExpectedPreviousIdentityId,
    Guid ExpectedPhoneIdentifierId,
    DateTimeOffset CompletedAt);

/// <summary>
/// Reserves the idempotent action before requesting password-recovery delivery for the
/// previous identity.
/// </summary>
/// <param name="Scope">Authenticated integration client, environment, and realm.</param>
/// <param name="FlowId">Flow selected inside that scope.</param>
/// <param name="RequestId">New integration-client-scoped idempotency key.</param>
/// <param name="PayloadHash">Hash binding the request id to this exact action payload.</param>
/// <param name="ExpectedRevision">Revision on which the action was advertised.</param>
/// <param name="ExpectedPreviousIdentityId">Server-derived candidate identity guard.</param>
/// <param name="ExpectedPhoneIdentifierId">Server-derived phone ownership guard.</param>
/// <param name="ReservedAt">UTC reservation time.</param>
public sealed record ReservePreviousIdentityRecoveryFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash,
    int ExpectedRevision,
    Guid ExpectedPreviousIdentityId,
    Guid ExpectedPhoneIdentifierId,
    DateTimeOffset ReservedAt);

/// <summary>
/// Closes a matching recovery reservation after delivery or finalization failure.
/// </summary>
/// <remarks>This command changes local request state and cannot undo provider delivery.</remarks>
/// <param name="Scope">Authenticated integration client, environment, and realm.</param>
/// <param name="FlowId">Flow that owns the pending request.</param>
/// <param name="RequestId">Exact reserved request id.</param>
/// <param name="PayloadHash">Hash required to match the reserved payload.</param>
public sealed record FailPreviousIdentityRecoveryFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    Guid RequestId,
    byte[] PayloadHash);

/// <summary>
/// Commits a terminal expired snapshot and closes pending local external-operation
/// state without revoking the source identity session.
/// </summary>
public sealed record ExpireAccessFlowCommand(
    AccessFlowScope Scope,
    Guid FlowId,
    int ExpectedRevision,
    string SnapshotJson,
    DateTimeOffset ExpiredAt);
