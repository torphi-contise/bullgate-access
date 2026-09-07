using System.Text.Json;

namespace Bullgate.Access.Domain.Flows;

/// <summary>
/// Immutable persisted representation of the client-visible snapshot produced at
/// one AccessFlow revision.
/// </summary>
/// <remarks>
/// The domain validates JSON shape and size here so replay never depends on
/// reconstructing an old response with newer application code.
/// </remarks>
public sealed class AccessFlowRevision
{
    private AccessFlowRevision()
    {
    }

    /// <summary>Creates one immutable client-visible snapshot revision.</summary>
    /// <remarks>
    /// Snapshot JSON is validated as an object and retained verbatim. Exact replay reads
    /// this stored representation instead of rebuilding an older answer with newer code
    /// or current policy.
    /// </remarks>
    /// <param name="flowId">Flow that owns the revision.</param>
    /// <param name="revision">Positive monotonic revision number within the flow.</param>
    /// <param name="snapshotJson">Serialized client-visible snapshot object.</param>
    /// <param name="createdAt">UTC time the revision committed.</param>
    /// <exception cref="ArgumentException">
    /// The flow id is empty, JSON is invalid or not an object, the snapshot is too large,
    /// or the timestamp is not UTC.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="revision"/> is not positive.</exception>
    public AccessFlowRevision(
        Guid flowId,
        int revision,
        string snapshotJson,
        DateTimeOffset createdAt)
    {
        if (flowId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(flowId));
        }

        if (revision <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        ArgumentNullException.ThrowIfNull(snapshotJson);
        if (snapshotJson.Length > AccessFlowLimits.SnapshotMaxLength)
        {
            throw new ArgumentException("Snapshot is too large.", nameof(snapshotJson));
        }

        try
        {
            using var document = JsonDocument.Parse(snapshotJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException(
                    "Snapshot must be a JSON object.",
                    nameof(snapshotJson));
            }
        }
        catch (JsonException exception)
        {
            throw new ArgumentException(
                "Snapshot must contain valid JSON.",
                nameof(snapshotJson),
                exception);
        }

        if (createdAt.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Timestamp must use the UTC offset.",
                nameof(createdAt));
        }

        FlowId = flowId;
        Revision = revision;
        SnapshotJson = snapshotJson;
        CreatedAt = createdAt;
    }

    /// <summary>Flow component of the revision's composite identity.</summary>
    public Guid FlowId { get; private set; }

    /// <summary>Positive monotonic revision number and optimistic client version.</summary>
    public int Revision { get; private set; }

    /// <summary>Verbatim JSON object returned when this exact result is replayed.</summary>
    public string SnapshotJson { get; private set; } = null!;

    /// <summary>UTC time at which this immutable snapshot committed.</summary>
    public DateTimeOffset CreatedAt { get; private set; }
}
