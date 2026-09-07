namespace Bullgate.Access.Domain.Flows;

/// <summary>
/// Identifies the business journey executed by a persistent access flow.
/// The intent determines which source session and registration-context rules apply.
/// </summary>
public enum AccessFlowIntent
{
    /// <summary>Continues an open registration using registration-purpose authority.</summary>
    ContinueRegistration,

    /// <summary>Changes phone state using an established product-purpose session.</summary>
    ManagePhone,
}

/// <summary>
/// Represents the lifecycle of a flow. Terminal flows never return to
/// <see cref="Active"/>; a caller starts or resumes another flow instead.
/// </summary>
public enum AccessFlowStatus
{
    /// <summary>The flow may accept an action from its current persisted revision.</summary>
    Active,

    /// <summary>A successful terminal transition committed.</summary>
    Completed,

    /// <summary>The flow crossed its lifetime and committed an expiration revision.</summary>
    Expired,

    /// <summary>An explicit cancellation committed.</summary>
    Cancelled,
}

/// <summary>
/// Aggregate root for a versioned, capability-protected identity journey.
/// </summary>
/// <remarks>
/// The aggregate enforces intent-specific context rules, UTC timestamps, optimistic
/// revisions, and terminal state transitions. Request idempotency and persisted
/// snapshots are represented by <see cref="AccessFlowRequest"/> and
/// <see cref="AccessFlowRevision"/>.
/// </remarks>
public sealed class AccessFlow
{
    private AccessFlow()
    {
    }

    /// <summary>Creates revision one of a scoped active identity journey.</summary>
    /// <remarks>
    /// Construction fixes every scope and authority selector for the flow lifetime.
    /// The caller must persist the matching initial <see cref="AccessFlowRevision"/>
    /// and start <see cref="AccessFlowRequest"/> in the same transaction.
    /// </remarks>
    /// <param name="id">Durable flow id; it is a selector rather than bearer authority.</param>
    /// <param name="realmId">Realm containing the identity and identifier uniqueness boundary.</param>
    /// <param name="appEnvironmentId">Environment selected by authenticated integration scope.</param>
    /// <param name="integrationClientId">Server client that created and may address the flow.</param>
    /// <param name="applicationClientId">Public application build metadata selected at start.</param>
    /// <param name="identityId">Identity whose journey the flow executes.</param>
    /// <param name="registrationContextId">Required only for <see cref="AccessFlowIntent.ContinueRegistration"/>.</param>
    /// <param name="sourceSessionId">Exact session whose authority created the flow.</param>
    /// <param name="protocolVersion">Positive negotiated protocol version fixed for the flow.</param>
    /// <param name="intent">Journey type and source-authority class.</param>
    /// <param name="createdAt">UTC creation time.</param>
    /// <param name="expiresAt">UTC exclusive flow lifetime boundary.</param>
    /// <exception cref="ArgumentException">
    /// An id, intent/context combination, or timestamp relationship is invalid.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="protocolVersion"/> is not positive or <paramref name="intent"/> is unknown.
    /// </exception>
    public AccessFlow(
        Guid id,
        Guid realmId,
        Guid appEnvironmentId,
        Guid integrationClientId,
        Guid applicationClientId,
        Guid identityId,
        Guid? registrationContextId,
        Guid sourceSessionId,
        int protocolVersion,
        AccessFlowIntent intent,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        Id = RequireId(id, nameof(id));
        RealmId = RequireId(realmId, nameof(realmId));
        AppEnvironmentId = RequireId(appEnvironmentId, nameof(appEnvironmentId));
        IntegrationClientId = RequireId(integrationClientId, nameof(integrationClientId));
        ApplicationClientId = RequireId(applicationClientId, nameof(applicationClientId));
        IdentityId = RequireId(identityId, nameof(identityId));
        if (registrationContextId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(registrationContextId));
        }
        if (intent == AccessFlowIntent.ContinueRegistration
            && registrationContextId is null)
        {
            throw new ArgumentException(
                "A registration flow requires a registration context.",
                nameof(registrationContextId));
        }
        if (intent == AccessFlowIntent.ManagePhone
            && registrationContextId is not null)
        {
            throw new ArgumentException(
                "A phone-management flow cannot use a registration context.",
                nameof(registrationContextId));
        }
        RegistrationContextId = registrationContextId;
        SourceSessionId = RequireId(sourceSessionId, nameof(sourceSessionId));

        if (protocolVersion <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(protocolVersion));
        }

        if (!Enum.IsDefined(intent))
        {
            throw new ArgumentOutOfRangeException(nameof(intent));
        }

        createdAt = RequireUtc(createdAt, nameof(createdAt));
        expiresAt = RequireUtc(expiresAt, nameof(expiresAt));
        if (expiresAt <= createdAt)
        {
            throw new ArgumentException(
                "Expiration must be later than creation.",
                nameof(expiresAt));
        }

        ProtocolVersion = protocolVersion;
        Intent = intent;
        Status = AccessFlowStatus.Active;
        CurrentRevision = 1;
        CreatedAt = createdAt;
        UpdatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>Durable flow selector; capability and integration scope provide authority.</summary>
    public Guid Id { get; private set; }

    /// <summary>Realm permanently constraining identity and identifier operations.</summary>
    public Guid RealmId { get; private set; }

    /// <summary>Environment permanently constraining policy, providers, and sessions.</summary>
    public Guid AppEnvironmentId { get; private set; }

    /// <summary>Integration client that owns this flow's request-id namespace.</summary>
    public Guid IntegrationClientId { get; private set; }

    /// <summary>Public application build selection resolved to its internal id.</summary>
    public Guid ApplicationClientId { get; private set; }

    /// <summary>Identity whose authority and lifecycle are revalidated at every commit.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Open registration context for registration intent; otherwise <see langword="null"/>.</summary>
    public Guid? RegistrationContextId { get; private set; }

    /// <summary>Exact registration or product session that authorized flow creation.</summary>
    public Guid SourceSessionId { get; private set; }

    /// <summary>Negotiated protocol version retained for every snapshot.</summary>
    public int ProtocolVersion { get; private set; }

    /// <summary>Fixed journey type controlling valid context, session, and actions.</summary>
    public AccessFlowIntent Intent { get; private set; }

    /// <summary>Current active or terminal lifecycle state.</summary>
    public AccessFlowStatus Status { get; private set; }

    /// <summary>Latest persisted snapshot revision and optimistic concurrency value.</summary>
    public int CurrentRevision { get; private set; }

    /// <summary>UTC time revision one was created.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC time the current revision committed.</summary>
    public DateTimeOffset UpdatedAt { get; private set; }

    /// <summary>UTC exclusive boundary after which active work may not commit.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    /// <summary>UTC terminal-transition time, or <see langword="null"/> while active.</summary>
    public DateTimeOffset? CompletedAt { get; private set; }

    /// <summary>Moves the exact active revision to successful terminal state.</summary>
    /// <param name="expectedRevision">Revision on which the caller based its decision.</param>
    /// <param name="completedAt">UTC completion time.</param>
    /// <returns>The new terminal revision number.</returns>
    /// <exception cref="InvalidOperationException">The flow is terminal or revision is stale.</exception>
    /// <exception cref="ArgumentException"><paramref name="completedAt"/> is invalid.</exception>
    public int Complete(int expectedRevision, DateTimeOffset completedAt) =>
        Finish(AccessFlowStatus.Completed, expectedRevision, completedAt);

    /// <summary>
    /// Advances the optimistic revision while keeping the flow active.
    /// </summary>
    /// <param name="expectedRevision">Revision on which the caller based its decision.</param>
    /// <param name="updatedAt">UTC time not earlier than the current flow state.</param>
    /// <returns>The new active revision number.</returns>
    /// <exception cref="InvalidOperationException">The flow is terminal or revision is stale.</exception>
    /// <exception cref="ArgumentException"><paramref name="updatedAt"/> is invalid.</exception>
    public int Advance(int expectedRevision, DateTimeOffset updatedAt)
    {
        if (Status != AccessFlowStatus.Active)
        {
            throw new InvalidOperationException("Only an active flow can advance.");
        }

        if (CurrentRevision != expectedRevision)
        {
            throw new InvalidOperationException("The flow revision has changed.");
        }

        updatedAt = RequireUtc(updatedAt, nameof(updatedAt));
        if (updatedAt < UpdatedAt)
        {
            throw new ArgumentException(
                "Update cannot precede the current flow state.",
                nameof(updatedAt));
        }

        CurrentRevision = checked(CurrentRevision + 1);
        UpdatedAt = updatedAt;
        return CurrentRevision;
    }

    /// <summary>Commits expiration as a new terminal revision.</summary>
    /// <param name="expectedRevision">Revision observed before expiration arbitration.</param>
    /// <param name="expiredAt">UTC expiration-transition time.</param>
    /// <returns>The new terminal revision number.</returns>
    /// <exception cref="InvalidOperationException">The flow is terminal or revision is stale.</exception>
    /// <exception cref="ArgumentException"><paramref name="expiredAt"/> is invalid.</exception>
    public int Expire(int expectedRevision, DateTimeOffset expiredAt) =>
        Finish(AccessFlowStatus.Expired, expectedRevision, expiredAt);

    /// <summary>Commits explicit cancellation as a new terminal revision.</summary>
    /// <param name="expectedRevision">Revision observed by the cancelling operation.</param>
    /// <param name="cancelledAt">UTC cancellation time.</param>
    /// <returns>The new terminal revision number.</returns>
    /// <exception cref="InvalidOperationException">The flow is terminal or revision is stale.</exception>
    /// <exception cref="ArgumentException"><paramref name="cancelledAt"/> is invalid.</exception>
    public int Cancel(int expectedRevision, DateTimeOffset cancelledAt) =>
        Finish(AccessFlowStatus.Cancelled, expectedRevision, cancelledAt);

    private int Finish(
        AccessFlowStatus terminalStatus,
        int expectedRevision,
        DateTimeOffset completedAt)
    {
        if (Status != AccessFlowStatus.Active)
        {
            throw new InvalidOperationException("Only an active flow can finish.");
        }

        if (CurrentRevision != expectedRevision)
        {
            throw new InvalidOperationException("The flow revision has changed.");
        }

        completedAt = RequireUtc(completedAt, nameof(completedAt));
        if (completedAt < CreatedAt)
        {
            throw new ArgumentException(
                "Completion cannot precede creation.",
                nameof(completedAt));
        }

        CurrentRevision = checked(CurrentRevision + 1);
        Status = terminalStatus;
        UpdatedAt = completedAt;
        CompletedAt = completedAt;
        return CurrentRevision;
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
            throw new ArgumentException("Timestamp must use the UTC offset.", parameterName);
        }

        return value;
    }
}
