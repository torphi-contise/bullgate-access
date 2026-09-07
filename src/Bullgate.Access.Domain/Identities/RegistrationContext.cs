namespace Bullgate.Access.Domain.Identities;

/// <summary>Lifecycle of registration for one identity in one environment.</summary>
public enum RegistrationContextStatus
{
    /// <summary>Registration work remains and may be continued by an authorized flow.</summary>
    Open,

    /// <summary>Registration reached its successful terminal outcome.</summary>
    Completed,

    /// <summary>
    /// Registration ended because continuity returned to a previous identity.
    /// </summary>
    Abandoned,
}

/// <summary>
/// Persisted registration progress used by registration-purpose sessions and
/// ContinueRegistration flows.
/// </summary>
/// <remarks>
/// A context is environment-specific registration state, not bearer authority and not
/// an AccessFlow. Closing it is monotonic: exact terminal repetition is idempotent, but
/// one terminal outcome cannot be replaced by the other.
/// </remarks>
public sealed class RegistrationContext
{
    private RegistrationContext()
    {
    }

    /// <summary>Creates open registration state for one identity and environment.</summary>
    /// <param name="id">Durable registration-context id.</param>
    /// <param name="realmId">Realm that owns the identity and context.</param>
    /// <param name="appEnvironmentId">Environment whose registration policy is pending.</param>
    /// <param name="identityId">Identity completing registration.</param>
    /// <param name="createdAt">UTC creation time.</param>
    /// <exception cref="ArgumentException">
    /// An id is empty or <paramref name="createdAt"/> does not use the UTC offset.
    /// </exception>
    public RegistrationContext(
        Guid id,
        Guid realmId,
        Guid appEnvironmentId,
        Guid identityId,
        DateTimeOffset createdAt)
    {
        Id = RequireId(id, nameof(id));
        RealmId = RequireId(realmId, nameof(realmId));
        AppEnvironmentId = RequireId(appEnvironmentId, nameof(appEnvironmentId));
        IdentityId = RequireId(identityId, nameof(identityId));
        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
        Status = RegistrationContextStatus.Open;
    }

    /// <summary>Durable context id; it does not authorize continuation by itself.</summary>
    public Guid Id { get; private set; }

    /// <summary>Realm isolation boundary inherited from the identity.</summary>
    public Guid RealmId { get; private set; }

    /// <summary>Environment in which registration is open or was closed.</summary>
    public Guid AppEnvironmentId { get; private set; }

    /// <summary>Identity whose registration progress this context records.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Current open or immutable terminal registration outcome.</summary>
    public RegistrationContextStatus Status { get; private set; }

    /// <summary>UTC time at which the context was created open.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Original UTC terminal time, or <see langword="null"/> while open.</summary>
    public DateTimeOffset? ClosedAt { get; private set; }

    /// <summary>Closes registration successfully, preserving an existing completion.</summary>
    /// <param name="closedAt">UTC completion time not earlier than creation.</param>
    /// <exception cref="ArgumentException">
    /// The timestamp is not UTC or predates context creation.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The context was already abandoned.
    /// </exception>
    public void Complete(DateTimeOffset closedAt) =>
        Close(RegistrationContextStatus.Completed, closedAt);

    /// <summary>Closes provisional registration after recovery of a previous identity.</summary>
    /// <param name="closedAt">UTC abandonment time not earlier than creation.</param>
    /// <exception cref="ArgumentException">
    /// The timestamp is not UTC or predates context creation.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The context was already completed.
    /// </exception>
    public void Abandon(DateTimeOffset closedAt) =>
        Close(RegistrationContextStatus.Abandoned, closedAt);

    private void Close(RegistrationContextStatus terminalStatus, DateTimeOffset closedAt)
    {
        closedAt = RequireUtc(closedAt, nameof(closedAt));
        if (closedAt < CreatedAt)
        {
            throw new ArgumentException(
                "Closure cannot precede creation.",
                nameof(closedAt));
        }

        // Exact terminal repetition is an idempotent retry. Keep the original closure
        // time rather than making transport timing rewrite persisted history.
        if (Status == terminalStatus)
        {
            return;
        }

        // Terminal outcomes are immutable. Completion and abandonment represent
        // different identity-continuity results and cannot be corrected by overwriting.
        if (Status != RegistrationContextStatus.Open)
        {
            throw new InvalidOperationException(
                "A closed registration context cannot change its outcome.");
        }

        Status = terminalStatus;
        ClosedAt = closedAt;
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
