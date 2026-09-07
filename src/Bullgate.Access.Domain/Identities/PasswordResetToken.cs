namespace Bullgate.Access.Domain.Identities;

/// <summary>
/// Single-use password reset capability persisted only as a token hash.
/// </summary>
/// <remarks>
/// Email and phone recovery converge on this entity so password replacement has one
/// consumption and expiration contract regardless of the proof channel. A populated
/// <see cref="UsedAt"/> means only that reset authority ended; it may represent a
/// successful reset or invalidation by a coordinating operation.
/// </remarks>
public sealed class PasswordResetToken
{
    private PasswordResetToken()
    {
    }

    /// <summary>Creates lifecycle state for one hashed password-reset bearer.</summary>
    /// <param name="id">Durable token selector; it is not reset authority.</param>
    /// <param name="identityId">Identity whose password may be replaced.</param>
    /// <param name="appEnvironmentId">Environment to which the bearer is confined.</param>
    /// <param name="tokenHash">Fixed-size hash of the clear single-use bearer.</param>
    /// <param name="createdAt">UTC issuance time.</param>
    /// <param name="expiresAt">UTC exclusive inactivity boundary.</param>
    /// <exception cref="ArgumentException">
    /// An identifier is empty, the hash has the wrong length, a timestamp is not UTC,
    /// or expiration is not later than issuance.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="tokenHash"/> is null.</exception>
    public PasswordResetToken(
        Guid id,
        Guid identityId,
        Guid appEnvironmentId,
        byte[] tokenHash,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        Id = RequireId(id, nameof(id));
        IdentityId = RequireId(identityId, nameof(identityId));
        AppEnvironmentId = RequireId(appEnvironmentId, nameof(appEnvironmentId));

        ArgumentNullException.ThrowIfNull(tokenHash);
        if (tokenHash.Length != IdentityLimits.PasswordResetTokenHashLength)
        {
            throw new ArgumentException(
                $"Token hash must contain {IdentityLimits.PasswordResetTokenHashLength} bytes.",
                nameof(tokenHash));
        }

        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
        ExpiresAt = RequireUtc(expiresAt, nameof(expiresAt));
        if (ExpiresAt <= CreatedAt)
        {
            throw new ArgumentException(
                "Expiration must be later than creation.",
                nameof(expiresAt));
        }

        TokenHash = tokenHash.ToArray();
    }

    /// <summary>Durable selector used for compensation and relationships, never as a bearer.</summary>
    public Guid Id { get; private set; }

    /// <summary>Identity whose password the active bearer may replace.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Environment boundary enforced during token consumption.</summary>
    public Guid AppEnvironmentId { get; private set; }

    /// <summary>Non-reversible lookup material; the clear bearer is never persisted.</summary>
    public byte[] TokenHash { get; private set; } = null!;

    /// <summary>UTC issuance time.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC exclusive inactivity boundary.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    /// <summary>
    /// UTC first-consumption or invalidation time; it does not prove a password changed.
    /// </summary>
    public DateTimeOffset? UsedAt { get; private set; }

    /// <summary>Determines whether this token is unused and strictly before expiration.</summary>
    /// <param name="now">Current UTC time.</param>
    /// <returns><see langword="true"/> only while the bearer remains consumable.</returns>
    /// <exception cref="ArgumentException"><paramref name="now"/> is not UTC.</exception>
    public bool IsActive(DateTimeOffset now)
    {
        now = RequireUtc(now, nameof(now));
        return UsedAt is null && now < ExpiresAt;
    }

    /// <summary>Consumes or invalidates this token exactly once.</summary>
    /// <remarks>
    /// The entity transition is intentionally strict and throws on repetition. Store
    /// operations that expose retry-safe invalidation implement idempotency with a
    /// conditional update before invoking or bypassing this method.
    /// </remarks>
    /// <param name="usedAt">UTC consumption time before expiration.</param>
    /// <exception cref="ArgumentException">The timestamp is not UTC or predates issuance.</exception>
    /// <exception cref="InvalidOperationException">The token is expired or already used.</exception>
    public void MarkUsed(DateTimeOffset usedAt)
    {
        usedAt = RequireUtc(usedAt, nameof(usedAt));
        if (usedAt < CreatedAt)
        {
            throw new ArgumentException(
                "Timestamp cannot precede creation.",
                nameof(usedAt));
        }
        if (!IsActive(usedAt))
        {
            throw new InvalidOperationException("The password reset token is not active.");
        }

        UsedAt = usedAt;
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
