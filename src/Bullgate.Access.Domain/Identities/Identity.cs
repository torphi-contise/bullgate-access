namespace Bullgate.Access.Domain.Identities;

/// <summary>Defines whether an identity can participate in access operations.</summary>
public enum IdentityLifecycleState
{
    /// <summary>The identity may participate in access operations, subject to policy.</summary>
    Active,

    /// <summary>
    /// A provisional identity retained as closed lifecycle history after recovery
    /// returned continuity to a previous identity.
    /// </summary>
    Abandoned,
}

/// <summary>
/// Represents a person recognized inside one realm.
/// </summary>
/// <remarks>
/// This id is independent from every consumer product profile id. Abandonment closes
/// a provisional identity during recovery; user-requested erasure is a hard delete,
/// not another lifecycle state.
/// </remarks>
public sealed class Identity
{
    private Identity()
    {
    }

    /// <summary>Creates an active identity inside one realm.</summary>
    /// <param name="id">Durable Access identity id, independent of consumer profile ids.</param>
    /// <param name="realmId">Realm that permanently owns the identity.</param>
    /// <param name="createdAt">UTC creation time.</param>
    /// <exception cref="ArgumentException">
    /// An id is empty or <paramref name="createdAt"/> does not use the UTC offset.
    /// </exception>
    public Identity(Guid id, Guid realmId, DateTimeOffset createdAt)
    {
        Id = RequireId(id, nameof(id));
        RealmId = RequireId(realmId, nameof(realmId));
        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
        LifecycleState = IdentityLifecycleState.Active;
    }

    /// <summary>Durable Access identity id; it is not a consumer profile id.</summary>
    public Guid Id { get; private set; }

    /// <summary>Realm isolation boundary that owns this identity.</summary>
    public Guid RealmId { get; private set; }

    /// <summary>Current participation state for access operations.</summary>
    public IdentityLifecycleState LifecycleState { get; private set; }

    /// <summary>Birth date collected with the identity CPF, when configured.</summary>
    public DateOnly? BirthDate { get; private set; }

    /// <summary>UTC time at which Access created this identity.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>
    /// Permanently marks a provisional identity as abandoned after continuity has
    /// returned to a previous identity.
    /// </summary>
    /// <remarks>
    /// This idempotent lifecycle transition does not erase the identity row and must
    /// not be used as a substitute for user-requested hard deletion.
    /// </remarks>
    public void Abandon()
    {
        LifecycleState = IdentityLifecycleState.Abandoned;
    }

    /// <summary>Records the birth date collected with the identity CPF.</summary>
    /// <remarks>
    /// Repeating the same value is idempotent. Registration cannot silently replace a
    /// different date already associated with the identity.
    /// </remarks>
    public void RecordBirthDate(DateOnly birthDate)
    {
        if (BirthDate is not null && BirthDate != birthDate)
        {
            throw new InvalidOperationException("The identity birth date is already set.");
        }

        BirthDate = birthDate;
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
