namespace Bullgate.Access.Domain.Identities;

/// <summary>Outcome of one persisted attempt against a proof challenge.</summary>
public enum ProofAttemptOutcome
{
    /// <summary>The submitted secret did not match and consumed one bounded attempt.</summary>
    Failed,

    /// <summary>The submitted secret matched and final proof creation committed.</summary>
    Succeeded,
}

/// <summary>Immutable audit fact for one committed comparison against a challenge.</summary>
/// <remarks>
/// An attempt does not itself grant authority. A successful row accompanies the
/// challenge transition and <see cref="IdentityProof"/> creation in the same
/// transaction; a failed row accompanies the attempt counter and feedback revision.
/// </remarks>
public sealed class ProofAttempt
{
    private ProofAttempt()
    {
    }

    /// <summary>Creates one append-only proof-attempt fact.</summary>
    /// <param name="id">Durable attempt id.</param>
    /// <param name="challengeId">Challenge whose secret was compared.</param>
    /// <param name="outcome">Committed comparison outcome.</param>
    /// <param name="attemptedAt">UTC comparison time.</param>
    /// <exception cref="ArgumentException">An id is empty or the timestamp is not UTC.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="outcome"/> is unknown.</exception>
    public ProofAttempt(
        Guid id,
        Guid challengeId,
        ProofAttemptOutcome outcome,
        DateTimeOffset attemptedAt)
    {
        Id = RequireId(id, nameof(id));
        ChallengeId = RequireId(challengeId, nameof(challengeId));
        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }
        if (attemptedAt.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Timestamp must use the UTC offset.",
                nameof(attemptedAt));
        }

        Outcome = outcome;
        AttemptedAt = attemptedAt;
    }

    /// <summary>Durable attempt selector.</summary>
    public Guid Id { get; private set; }

    /// <summary>Challenge that owned the compared secret and attempt budget.</summary>
    public Guid ChallengeId { get; private set; }

    /// <summary>Whether the committed comparison failed or succeeded.</summary>
    public ProofAttemptOutcome Outcome { get; private set; }

    /// <summary>UTC time at which the comparison was committed.</summary>
    public DateTimeOffset AttemptedAt { get; private set; }

    private static Guid RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }
        return value;
    }
}

/// <summary>
/// Durable evidence that an identity completed a proof in a specific flow.
/// </summary>
/// <remarks>
/// A proof records the completed fact and its source challenge. It is distinct from
/// the identifier ownership mutation that may follow from that fact. The flow identity
/// records who performed the proof; <see cref="SubjectIdentifierId"/> records the exact
/// identifier value that was proven, even when another identity currently owns it.
/// </remarks>
public sealed class IdentityProof
{
    private IdentityProof()
    {
    }

    /// <summary>Creates immutable evidence materialized from one completed challenge.</summary>
    /// <param name="id">Durable proof id.</param>
    /// <param name="accessFlowId">Flow that authorized and completed the proof.</param>
    /// <param name="identityId">Identity that demonstrated the proof.</param>
    /// <param name="challengeId">One source challenge; it may materialize at most one proof.</param>
    /// <param name="type">Fact established by the completed challenge.</param>
    /// <param name="subjectIdentifierId">Optional exact identifier whose possession was proven.</param>
    /// <param name="createdAt">UTC proof-materialization time.</param>
    /// <exception cref="ArgumentException">
    /// A required id is empty, the optional subject id is empty, or the timestamp is not UTC.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="type"/> is unknown.</exception>
    public IdentityProof(
        Guid id,
        Guid accessFlowId,
        Guid identityId,
        Guid challengeId,
        ProofChallengeType type,
        Guid? subjectIdentifierId,
        DateTimeOffset createdAt)
    {
        Id = RequireId(id, nameof(id));
        AccessFlowId = RequireId(accessFlowId, nameof(accessFlowId));
        IdentityId = RequireId(identityId, nameof(identityId));
        ChallengeId = RequireId(challengeId, nameof(challengeId));
        if (!Enum.IsDefined(type))
        {
            throw new ArgumentOutOfRangeException(nameof(type));
        }
        if (subjectIdentifierId == Guid.Empty)
        {
            throw new ArgumentException(
                "Id cannot be empty.",
                nameof(subjectIdentifierId));
        }
        if (createdAt.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Timestamp must use the UTC offset.",
                nameof(createdAt));
        }

        Type = type;
        SubjectIdentifierId = subjectIdentifierId;
        CreatedAt = createdAt;
    }

    /// <summary>Durable proof selector.</summary>
    public Guid Id { get; private set; }

    /// <summary>Flow that owns the proof and its lifecycle reachability.</summary>
    public Guid AccessFlowId { get; private set; }

    /// <summary>Identity that completed the challenge, not necessarily the identifier owner.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Source challenge; database uniqueness permits one proof per challenge.</summary>
    public Guid ChallengeId { get; private set; }

    /// <summary>Fact established by this evidence.</summary>
    public ProofChallengeType Type { get; private set; }

    /// <summary>Exact identifier proven by the challenge, when the proof has one.</summary>
    public Guid? SubjectIdentifierId { get; private set; }

    /// <summary>UTC time at which successful confirmation materialized the proof.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    private static Guid RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }
        return value;
    }
}
