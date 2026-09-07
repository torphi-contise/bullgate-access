namespace Bullgate.Access.Domain.Flows;

/// <summary>Distinguishes flow creation requests from action requests.</summary>
public enum AccessFlowRequestKind
{
    /// <summary>Creates or idempotently resumes a flow from source-session authority.</summary>
    Start,

    /// <summary>Executes one advertised action against an existing flow revision.</summary>
    Action,
}

/// <summary>
/// Tracks whether a request is waiting for an external effect, committed, or known
/// to have failed outside the database transaction.
/// </summary>
public enum AccessFlowRequestStatus
{
    /// <summary>An external effect is reserved but has no committed response revision.</summary>
    PendingExternal,

    /// <summary>The request permanently names one result revision and optional session.</summary>
    Committed,

    /// <summary>The reservation produced no committed Access result revision.</summary>
    ExternalFailed,
}

/// <summary>
/// Idempotency record scoped by integration client and caller request id.
/// </summary>
/// <remarks>
/// The payload hash prevents a caller from reusing the same id for different work.
/// A committed request points to the exact revision and optional session that must
/// be reproduced during replay.
/// </remarks>
public sealed class AccessFlowRequest
{
    private AccessFlowRequest()
    {
    }

    /// <summary>Creates an already committed start or action request.</summary>
    /// <remarks>
    /// Ordinary database-only transitions use this constructor in the transaction that
    /// creates the result revision. Operations that cross a provider boundary must use
    /// <see cref="ReserveExternal"/> before executing the external effect.
    /// </remarks>
    /// <param name="integrationClientId">Authenticated client that owns the idempotency key.</param>
    /// <param name="requestId">Caller-generated id identifying one canonical payload.</param>
    /// <param name="flowId">Flow whose result was produced.</param>
    /// <param name="kind">Whether the request started/resumed a flow or executed an action.</param>
    /// <param name="payloadHash">Fixed-length hash of canonical security-relevant input.</param>
    /// <param name="resultRevision">Exact immutable revision returned by replay.</param>
    /// <param name="createdAt">UTC time the request result committed.</param>
    /// <param name="issuedSessionId">Optional session whose clear token replay may rederive.</param>
    /// <exception cref="ArgumentException">An id, hash, or timestamp is invalid.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="kind"/> is unknown or <paramref name="resultRevision"/> is not positive.
    /// </exception>
    public AccessFlowRequest(
        Guid integrationClientId,
        Guid requestId,
        Guid flowId,
        AccessFlowRequestKind kind,
        byte[] payloadHash,
        int resultRevision,
        DateTimeOffset createdAt,
        Guid? issuedSessionId = null)
    {
        IntegrationClientId = RequireId(
            integrationClientId,
            nameof(integrationClientId));
        RequestId = RequireId(requestId, nameof(requestId));
        FlowId = RequireId(flowId, nameof(flowId));

        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        ArgumentNullException.ThrowIfNull(payloadHash);
        if (payloadHash.Length != AccessFlowLimits.PayloadHashLength)
        {
            throw new ArgumentException(
                $"Payload hash must contain {AccessFlowLimits.PayloadHashLength} bytes.",
                nameof(payloadHash));
        }

        Kind = kind;
        PayloadHash = payloadHash.ToArray();
        Status = AccessFlowRequestStatus.PendingExternal;
        Commit(resultRevision, issuedSessionId);
        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
    }

    private AccessFlowRequest(
        Guid integrationClientId,
        Guid requestId,
        Guid flowId,
        AccessFlowRequestKind kind,
        byte[] payloadHash,
        DateTimeOffset createdAt)
    {
        IntegrationClientId = RequireId(
            integrationClientId,
            nameof(integrationClientId));
        RequestId = RequireId(requestId, nameof(requestId));
        FlowId = RequireId(flowId, nameof(flowId));
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }
        ArgumentNullException.ThrowIfNull(payloadHash);
        if (payloadHash.Length != AccessFlowLimits.PayloadHashLength)
        {
            throw new ArgumentException(
                $"Payload hash must contain {AccessFlowLimits.PayloadHashLength} bytes.",
                nameof(payloadHash));
        }

        Kind = kind;
        PayloadHash = payloadHash.ToArray();
        Status = AccessFlowRequestStatus.PendingExternal;
        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
    }

    /// <summary>Authenticated integration client that scopes <see cref="RequestId"/>.</summary>
    public Guid IntegrationClientId { get; private set; }

    /// <summary>Caller idempotency key; it has meaning only with integration-client scope.</summary>
    public Guid RequestId { get; private set; }

    /// <summary>Flow that owns the request and any referenced result revision.</summary>
    public Guid FlowId { get; private set; }

    /// <summary>Whether the canonical payload represents flow start or an action.</summary>
    public AccessFlowRequestKind Kind { get; private set; }

    /// <summary>External-effect or committed-result lifecycle state.</summary>
    public AccessFlowRequestStatus Status { get; private set; }

    /// <summary>Hash binding this idempotency key to one canonical input.</summary>
    public byte[] PayloadHash { get; private set; } = null!;

    /// <summary>Exact response revision for a committed request; otherwise <see langword="null"/>.</summary>
    public int? ResultRevision { get; private set; }

    /// <summary>UTC time the durable request record was first created.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Optional committed session used to verify deterministic clear-token replay.</summary>
    public Guid? IssuedSessionId { get; private set; }

    /// <summary>
    /// Creates a pending record before an email or SMS effect leaves PostgreSQL.
    /// </summary>
    /// <remarks>
    /// A pending record has no result revision or issued session. The same request may
    /// later finalize it; a different action must not bypass its ownership by choosing
    /// another request id.
    /// </remarks>
    /// <param name="integrationClientId">Authenticated owner of the request id.</param>
    /// <param name="requestId">Caller-generated id for the exact external operation.</param>
    /// <param name="flowId">Flow temporarily blocked by this reservation.</param>
    /// <param name="payloadHash">Hash binding the reservation to canonical input.</param>
    /// <param name="createdAt">UTC reservation time.</param>
    /// <returns>An action request in <see cref="AccessFlowRequestStatus.PendingExternal"/>.</returns>
    public static AccessFlowRequest ReserveExternal(
        Guid integrationClientId,
        Guid requestId,
        Guid flowId,
        byte[] payloadHash,
        DateTimeOffset createdAt) =>
        new(
            integrationClientId,
            requestId,
            flowId,
            AccessFlowRequestKind.Action,
            payloadHash,
            createdAt);

    /// <summary>Attaches the durable result that exact request replay must return.</summary>
    /// <remarks>
    /// Persistence orchestration calls this only while creating a database-only request
    /// or finalizing the exact pending reservation. An already failed request is terminal
    /// and cannot later acquire a successful history.
    /// </remarks>
    /// <param name="resultRevision">Positive immutable revision produced by the request.</param>
    /// <param name="issuedSessionId">Optional session created by the same transaction.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="resultRevision"/> is not positive.</exception>
    /// <exception cref="ArgumentException"><paramref name="issuedSessionId"/> is empty.</exception>
    /// <exception cref="InvalidOperationException">External failure was already recorded.</exception>
    public void Commit(int resultRevision, Guid? issuedSessionId = null)
    {
        if (resultRevision <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(resultRevision));
        }
        if (issuedSessionId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(issuedSessionId));
        }
        // A failed delivery is final for this request id. Allowing it to commit later
        // would make one id describe two externally observable histories.
        if (Status == AccessFlowRequestStatus.ExternalFailed)
        {
            throw new InvalidOperationException("A failed external request cannot commit.");
        }

        Status = AccessFlowRequestStatus.Committed;
        ResultRevision = resultRevision;
        IssuedSessionId = issuedSessionId;
    }

    /// <summary>
    /// Marks a reserved external effect as failed. Repeated failure reporting is
    /// intentionally idempotent.
    /// </summary>
    /// <remarks>
    /// Committed requests are never rewritten as failed. Failure removes no provider
    /// effect; it records that this request id has no replayable success revision.
    /// </remarks>
    public void FailExternal()
    {
        if (Status != AccessFlowRequestStatus.PendingExternal)
        {
            return;
        }

        Status = AccessFlowRequestStatus.ExternalFailed;
        ResultRevision = null;
        IssuedSessionId = null;
    }

    private static Guid RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }

        return value;
    }

    private static DateTimeOffset RequireUtc(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Timestamp must use the UTC offset.",
                parameterName);
        }
        return value;
    }
}
