using System.Text.Json;

namespace Bullgate.Access.Application.Flows;

/// <summary>
/// Stable wire vocabulary for supported AccessFlow protocol versions.
/// </summary>
/// <remarks>
/// Consumers must compare these values exactly and execute only actions present in
/// the latest snapshot. Adding a constant does not make an action available in a
/// particular flow revision.
/// </remarks>
public static class AccessFlowProtocol
{
    /// <summary>Initial phone-registration and phone-management protocol revision.</summary>
    public const int Version1 = 1;

    /// <summary>Adds required CPF and birth-date collection during registration.</summary>
    public const int Version2 = 2;

    /// <summary>Intent that finishes an already authenticated registration journey.</summary>
    public const string ContinueRegistrationIntent = "continueRegistration";

    /// <summary>Intent that changes phone state for an authenticated product identity.</summary>
    public const string ManagePhoneIntent = "managePhone";

    /// <summary>Step in which required CPF and birth-date data are collected together.</summary>
    public const string CollectCpfStep = "collectCpf";

    /// <summary>Step in which the server permits phone collection or an offered skip.</summary>
    public const string CollectPhoneStep = "collectPhone";

    /// <summary>Step in which a delivered phone-possession challenge may be completed.</summary>
    public const string VerifyPhoneStep = "verifyPhone";

    /// <summary>Step requiring an explicit decision about a phone owned elsewhere.</summary>
    public const string ResolvePhoneConflictStep = "resolvePhoneConflict";

    /// <summary>Action that validates a phone and reserves external OTP delivery.</summary>
    public const string RequestPhoneVerificationAction = "requestPhoneVerification";

    /// <summary>Action that validates and stores required CPF and birth-date data.</summary>
    public const string SubmitCpfAction = "submitCpf";

    /// <summary>Action used when policy permits phone collection without verification.</summary>
    public const string SubmitPhoneAction = "submitPhone";

    /// <summary>Action that submits the locally verified phone-possession code.</summary>
    public const string ConfirmPhoneVerificationAction = "confirmPhoneVerification";

    /// <summary>Action that reserves delivery of a replacement phone challenge.</summary>
    public const string ResendPhoneVerificationAction = "resendPhoneVerification";

    /// <summary>Action that explicitly moves only the proven conflicting phone.</summary>
    public const string TransferPhoneAction = "transferPhoneToCurrentIdentity";

    /// <summary>
    /// Registration-only action that requests password recovery for the stored previous
    /// identity; it does not merge identities or issue a product session.
    /// </summary>
    public const string RecoverPreviousIdentityAction = "recoverPreviousIdentity";

    /// <summary>Action that abandons the selected phone and returns to collection.</summary>
    public const string ChangePhoneAction = "changePhone";

    /// <summary>Registration-only action offered when phone collection is optional.</summary>
    public const string SkipRegistrationAction = "skipRegistration";
}

/// <summary>
/// Authenticated server scope for a flow operation. The realm and environment come
/// from the integration credential, never from an untrusted application client.
/// </summary>
/// <param name="IntegrationClientId">Authenticated caller and request-id namespace.</param>
/// <param name="AppEnvironmentId">Environment selected by the integration credential.</param>
/// <param name="RealmId">Identity ownership boundary fixed by authenticated topology.</param>
public sealed record AccessFlowScope(
    Guid IntegrationClientId,
    Guid AppEnvironmentId,
    Guid RealmId);

/// <summary>Command used to start or idempotently resume an access flow.</summary>
/// <param name="RequestId">Caller-generated idempotency key in integration-client scope.</param>
/// <param name="ProtocolVersions">Protocol revisions understood by the consumer.</param>
/// <param name="Intent">Requested stable intent from <see cref="AccessFlowProtocol"/>.</param>
/// <param name="ApplicationClientKey">Public selector for build-specific metadata.</param>
/// <param name="SessionToken">Server-held registration or product bearer for the intent.</param>
public sealed record AccessFlowStartCommand(
    Guid RequestId,
    IReadOnlyList<int>? ProtocolVersions,
    string? Intent,
    string? ApplicationClientKey,
    string? SessionToken);

/// <summary>
/// Command for one server-advertised action at an expected optimistic revision.
/// </summary>
/// <param name="RequestId">Caller-generated idempotency key for this exact action payload.</param>
/// <param name="ExpectedRevision">Revision from the snapshot that offered the action.</param>
/// <param name="ActionId">Opaque action id copied from that snapshot.</param>
/// <param name="ActionType">Semantic action type copied from the same action.</param>
/// <param name="Input">Optional action-specific JSON; it does not replace action authority.</param>
public sealed record AccessFlowActionCommand(
    Guid RequestId,
    int ExpectedRevision,
    Guid ActionId,
    string? ActionType,
    JsonElement? Input = null);

/// <summary>Client-safe semantic step data for the current flow revision.</summary>
/// <param name="Type">Stable step vocabulary understood by the consumer.</param>
/// <param name="Destination">Optional masked delivery destination, never a clear OTP.</param>
/// <param name="ExpiresAt">Optional expiry of the active proof opportunity.</param>
/// <param name="ResendAvailableAt">Optional earliest server time for a resend action.</param>
/// <param name="PreviousEmailHint">Optional masked hint for conflict resolution.</param>
public sealed record AccessFlowStepSnapshot(
    string Type,
    string? Destination = null,
    DateTimeOffset? ExpiresAt = null,
    DateTimeOffset? ResendAvailableAt = null,
    string? PreviousEmailHint = null);

/// <summary>One action authorized only for the snapshot that advertises it.</summary>
/// <param name="Id">Opaque, revision-specific action identifier.</param>
/// <param name="Type">Stable semantic action name; it is not authority without <paramref name="Id"/>.</param>
public sealed record AccessFlowActionSnapshot(Guid Id, string Type);

/// <summary>Machine-readable non-terminal feedback and optional retry timing.</summary>
/// <param name="Code">Stable semantic feedback code, not display text.</param>
/// <param name="Field">Optional input field associated with the feedback.</param>
/// <param name="RetryAt">Optional server time before which retry should not occur.</param>
public sealed record AccessFlowFeedbackSnapshot(
    string Code,
    string? Field = null,
    DateTimeOffset? RetryAt = null);

/// <summary>Client-safe terminal outcome for a completed flow.</summary>
/// <remarks>
/// Identity ids describe a continuity result and are never bearer authority. In
/// previous-identity recovery they name the retained and abandoned identities; they do
/// not imply a merge, completed password reset, or authenticated product session.
/// </remarks>
/// <param name="Type">Terminal result category.</param>
/// <param name="Outcome">Optional stable outcome within that category.</param>
/// <param name="PreviousIdentityId">Optional identity retained by an explicit recovery path.</param>
/// <param name="CurrentIdentityId">Optional provisional identity abandoned by that path.</param>
public sealed record AccessFlowResultSnapshot(
    string Type,
    string? Outcome = null,
    Guid? PreviousIdentityId = null,
    Guid? CurrentIdentityId = null);

/// <summary>
/// Client-safe representation of the current flow state and available actions.
/// </summary>
/// <remarks>
/// Each instance is the immutable wire contract for one persisted revision. Consumers
/// render it semantically and must submit only actions contained in its <see cref="Actions"/>.
/// </remarks>
/// <param name="ProtocolVersion">Wire-contract revision for every nested value.</param>
/// <param name="FlowId">Opaque flow selector; it is not authorization.</param>
/// <param name="Revision">Optimistic revision required by the advertised actions.</param>
/// <param name="Intent">Stable journey intent.</param>
/// <param name="Status">Stable active or terminal status.</param>
/// <param name="ExpiresAt">Absolute server time after which an active flow expires.</param>
/// <param name="Step">Current non-terminal semantic step, when active.</param>
/// <param name="Actions">Closed allowlist for this exact revision.</param>
/// <param name="Result">Terminal semantic result, when the flow has ended.</param>
/// <param name="Feedback">Optional non-terminal validation or retry feedback.</param>
public sealed record AccessFlowSnapshot(
    int ProtocolVersion,
    Guid FlowId,
    int Revision,
    string Intent,
    string Status,
    DateTimeOffset ExpiresAt,
    AccessFlowStepSnapshot? Step,
    IReadOnlyList<AccessFlowActionSnapshot> Actions,
    AccessFlowResultSnapshot? Result = null,
    AccessFlowFeedbackSnapshot? Feedback = null);

/// <summary>
/// Session material emitted by a terminal transition for server-side consumption.
/// It must not be forwarded as application JavaScript state.
/// </summary>
/// <remarks>
/// <see cref="SessionToken"/> is clear product bearer authority. The containing BFF
/// exchanges or stores it before projecting an application-specific response.
/// </remarks>
/// <param name="IdentityId">Access identity authorized by the product session.</param>
/// <param name="SessionId">Opaque durable session identifier, not the bearer token.</param>
/// <param name="SessionToken">Clear bearer retained by trusted server orchestration.</param>
/// <param name="ExpiresAt">Absolute expiry of the issued session.</param>
/// <param name="Purpose">Stable lower-case session purpose.</param>
public sealed record AccessFlowIssuedSession(
    Guid IdentityId,
    Guid SessionId,
    string SessionToken,
    DateTimeOffset ExpiresAt,
    string Purpose);

/// <summary>Stable application-level failure categories for flow operations.</summary>
public enum AccessFlowError
{
    /// <summary>The command is structurally incomplete or malformed.</summary>
    InvalidRequest,

    /// <summary>No protocol revision offered by the consumer is supported.</summary>
    ProtocolVersionUnsupported,

    /// <summary>The requested intent is unknown or disabled by policy.</summary>
    IntentUnsupported,

    /// <summary>The product session is absent, malformed, expired, or revoked.</summary>
    SessionInactive,

    /// <summary>The registration session or open registration context no longer qualifies.</summary>
    RegistrationNotPending,

    /// <summary>The public application-client selector is malformed, absent, or incompatible.</summary>
    ApplicationClientInvalid,

    /// <summary>An active flow for the source belongs to another integration client.</summary>
    IntegrationClientConflict,

    /// <summary>The request id is missing after commit or names a different payload.</summary>
    RequestIdConflict,

    /// <summary>The capability and authenticated scope do not resolve the requested flow.</summary>
    FlowNotFound,

    /// <summary>The caller acted on a revision that is no longer current.</summary>
    RevisionConflict,

    /// <summary>The exact action is not offered by the current persisted snapshot.</summary>
    ActionNotAvailable,

    /// <summary>A verification delivery is pending, failed, or currently unavailable.</summary>
    DeliveryUnavailable,

    /// <summary>Password recovery exceeded its configured per-identity issuance rate.</summary>
    PasswordRecoveryRateLimited,

    /// <summary>Password recovery delivery or environment configuration is unavailable.</summary>
    PasswordRecoveryUnavailable,

    /// <summary>Bounded start reconciliation could not settle a concurrent active slot.</summary>
    FlowCreationUnavailable,
}

/// <summary>
/// Result envelope that carries either a snapshot and optional terminal artifacts,
/// or one stable error category.
/// </summary>
/// <param name="Snapshot">Current or exactly replayed semantic flow revision.</param>
/// <param name="FlowCapability">Server bearer required for later reads and actions.</param>
/// <param name="IssuedSession">Optional terminal product authority retained by the BFF.</param>
/// <param name="Error">Stable failure category when the operation did not succeed.</param>
public sealed record AccessFlowResult(
    AccessFlowSnapshot? Snapshot,
    string? FlowCapability,
    AccessFlowIssuedSession? IssuedSession,
    AccessFlowError? Error)
{
    /// <summary>Indicates that no error category was recorded for the operation.</summary>
    public bool Succeeded => Error is null;

    /// <summary>Creates an error-only envelope without bearer material or snapshot data.</summary>
    public static AccessFlowResult Failure(AccessFlowError error) =>
        new(null, null, null, error);
}
