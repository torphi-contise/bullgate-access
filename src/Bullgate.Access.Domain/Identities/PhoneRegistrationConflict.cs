namespace Bullgate.Access.Domain.Identities;

/// <summary>
/// Records that a phone proven by the current flow belongs to another identity.
/// </summary>
/// <remarks>
/// The conflict captures the expected previous owner and bounded email-knowledge
/// attempts for explicit phone transfer. It grants no implicit permission to merge
/// identities. Phone-possession evidence remains in the related proof records; this
/// entity fixes the ownership conflict that later transactions must revalidate.
/// </remarks>
public sealed class PhoneRegistrationConflict
{
    private PhoneRegistrationConflict()
    {
    }

    /// <summary>Creates unresolved ownership state for one proven phone and flow.</summary>
    /// <param name="accessFlowId">Flow that produced the current phone proof.</param>
    /// <param name="previousIdentityId">Active identity that owned the verified phone.</param>
    /// <param name="conflictingPhoneIdentifierId">Exact verified phone identifier.</param>
    /// <param name="createdAt">UTC conflict creation time.</param>
    /// <param name="expiresAt">UTC exclusive conflict-resolution boundary.</param>
    /// <exception cref="ArgumentException">
    /// An id is empty, a timestamp is not UTC, or expiration does not follow creation.
    /// </exception>
    public PhoneRegistrationConflict(
        Guid accessFlowId,
        Guid previousIdentityId,
        Guid conflictingPhoneIdentifierId,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        AccessFlowId = RequireId(accessFlowId, nameof(accessFlowId));
        PreviousIdentityId = RequireId(
            previousIdentityId,
            nameof(previousIdentityId));
        ConflictingPhoneIdentifierId = RequireId(
            conflictingPhoneIdentifierId,
            nameof(conflictingPhoneIdentifierId));
        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
        ExpiresAt = RequireUtc(expiresAt, nameof(expiresAt));
        if (ExpiresAt <= CreatedAt)
        {
            throw new ArgumentException(
                "Conflict expiration must follow creation.",
                nameof(expiresAt));
        }
    }

    /// <summary>Owning flow and unique conflict selector; it is not flow authority.</summary>
    public Guid AccessFlowId { get; private set; }

    /// <summary>Expected previous identity revalidated during transfer or recovery.</summary>
    public Guid PreviousIdentityId { get; private set; }

    /// <summary>Expected verified phone identifier revalidated under lock.</summary>
    public Guid ConflictingPhoneIdentifierId { get; private set; }

    /// <summary>Committed number of incorrect previous-e-mail transfer attempts.</summary>
    public int FailedEmailAttempts { get; private set; }

    /// <summary>UTC time the final mismatch disabled e-mail-based transfer, when present.</summary>
    public DateTimeOffset? EmailResolutionExhaustedAt { get; private set; }

    /// <summary>UTC time at which the current flow committed this conflict.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC exclusive boundary for conflict-resolution operations.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    /// <summary>Records one incorrect previous-e-mail attempt for explicit phone transfer.</summary>
    /// <remarks>
    /// This domain mutation is not an idempotency boundary. The calling transaction
    /// must ensure an exact request replay cannot increment the counter twice.
    /// </remarks>
    /// <param name="maxAttempts">Positive configured limit for this conflict.</param>
    /// <param name="attemptedAt">UTC attempt time strictly before expiry.</param>
    /// <returns>
    /// <see langword="true"/> when this attempt reaches the limit and stamps exhaustion;
    /// otherwise <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maxAttempts"/> is not positive.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="attemptedAt"/> is not UTC.</exception>
    /// <exception cref="InvalidOperationException">
    /// The conflict is expired or its attempt budget was already exhausted.
    /// </exception>
    public bool RecordEmailMismatch(int maxAttempts, DateTimeOffset attemptedAt)
    {
        if (maxAttempts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAttempts));
        }

        attemptedAt = RequireUtc(attemptedAt, nameof(attemptedAt));
        if (attemptedAt < CreatedAt || attemptedAt >= ExpiresAt)
        {
            throw new InvalidOperationException("The phone conflict is not active.");
        }

        if (EmailResolutionExhaustedAt is not null
            || FailedEmailAttempts >= maxAttempts)
        {
            throw new InvalidOperationException(
                "The phone conflict has exhausted its email attempts.");
        }

        FailedEmailAttempts = checked(FailedEmailAttempts + 1);
        if (FailedEmailAttempts < maxAttempts)
        {
            return false;
        }

        EmailResolutionExhaustedAt = attemptedAt;
        return true;
    }

    private static Guid RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }

        return value;
    }

    private static DateTimeOffset RequireUtc(
        DateTimeOffset value,
        string parameterName)
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
