namespace Bullgate.Access.Domain.Flows;

/// <summary>
/// Append-only reachability link from a flow to an identity whose personal data the
/// flow retains.
/// </summary>
/// <remarks>
/// A flow can retain data about an identity other than <c>AccessFlow.IdentityId</c>.
/// Phone-conflict and previous-identity-recovery journeys are examples: the flow is
/// driven by a provisional identity while its revisions, proofs, and conflict state
/// also describe an earlier identity. Identity erasure therefore follows this
/// relation and deletes the entire related flow.
///
/// The relation is deliberately append-only. A later phone transfer, conflict
/// resolution, or terminal flow transition does not make an earlier snapshot stop
/// containing personal data. Keeping the durable link also avoids unreliable searches
/// through serialized JSON and current identifier ownership, both of which may change
/// after the data was captured.
/// </remarks>
public sealed class AccessFlowDataSubject
{
    /// <summary>Required by persistence materialization.</summary>
    private AccessFlowDataSubject()
    {
    }

    /// <summary>
    /// Creates durable erasure reachability from one flow to one identity.
    /// </summary>
    /// <param name="realmId">
    /// Realm shared by the flow and identity; it prevents a selector from becoming a
    /// cross-tenant erasure link.
    /// </param>
    /// <param name="flowId">Flow whose complete historical graph may retain the data.</param>
    /// <param name="identityId">Identity to which retained personal data is attributable.</param>
    /// <param name="createdAt">
    /// UTC time at which the flow first became attributable to the identity.
    /// </param>
    public AccessFlowDataSubject(
        Guid realmId,
        Guid flowId,
        Guid identityId,
        DateTimeOffset createdAt)
    {
        RealmId = RequireId(realmId, nameof(realmId));
        FlowId = RequireId(flowId, nameof(flowId));
        IdentityId = RequireId(identityId, nameof(identityId));
        if (createdAt.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Timestamp must use the UTC offset.",
                nameof(createdAt));
        }

        CreatedAt = createdAt;
    }

    /// <summary>Gets the tenant realm that owns both sides of the link.</summary>
    public Guid RealmId { get; private set; }

    /// <summary>Gets the flow deleted when the linked identity is erased.</summary>
    public Guid FlowId { get; private set; }

    /// <summary>Gets the identity whose personal data is reachable through the flow.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Gets the UTC time when this attribution first became durable.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Rejects an absent selector before it can become an unusable erasure link.</summary>
    private static Guid RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }

        return value;
    }
}
