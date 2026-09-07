namespace Bullgate.Access.Domain.Identities;

/// <summary>
/// Defines what an active opaque session is allowed to authenticate.
/// </summary>
public enum IdentitySessionPurpose
{
    /// <summary>May be resolved by a consumer BFF into product identity authority.</summary>
    Product,

    /// <summary>May continue registration but cannot authenticate product endpoints.</summary>
    Registration,
}

/// <summary>
/// Opaque, revocable session bound to one identity and app environment.
/// </summary>
/// <remarks>
/// Only the token hash is persisted. Registration purpose is deliberately distinct
/// from product purpose so an unfinished registration cannot authenticate consumer
/// business endpoints. Row existence alone does not make a session active: resolution
/// must also enforce environment scope, identity lifecycle, revocation, and the
/// exclusive expiration boundary. Purpose is a separate authorization decision.
/// </remarks>
public sealed class IdentitySession
{
    private IdentitySession()
    {
    }

    /// <summary>Creates a session from server-issued hashed bearer material.</summary>
    /// <param name="id">Durable session identifier; it is not bearer authority.</param>
    /// <param name="identityId">Identity authenticated by the session.</param>
    /// <param name="appEnvironmentId">Environment to which the bearer is confined.</param>
    /// <param name="purpose">Registration or product authorization class.</param>
    /// <param name="tokenHash">Fixed-size hash of the clear bearer.</param>
    /// <param name="createdAt">UTC issuance time.</param>
    /// <param name="expiresAt">UTC time after which the session is inactive.</param>
    /// <exception cref="ArgumentException">
    /// An identifier is empty, the hash has the wrong length, a timestamp is not UTC,
    /// or expiration is not later than issuance.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="tokenHash"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="purpose"/> is unknown.</exception>
    public IdentitySession(
        Guid id,
        Guid identityId,
        Guid appEnvironmentId,
        IdentitySessionPurpose purpose,
        byte[] tokenHash,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(id));
        }

        if (identityId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(identityId));
        }

        if (appEnvironmentId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(appEnvironmentId));
        }

        if (!Enum.IsDefined(purpose))
        {
            throw new ArgumentOutOfRangeException(nameof(purpose));
        }

        ArgumentNullException.ThrowIfNull(tokenHash);
        if (tokenHash.Length != IdentityLimits.SessionTokenHashLength)
        {
            throw new ArgumentException(
                $"Token hash must contain {IdentityLimits.SessionTokenHashLength} bytes.",
                nameof(tokenHash));
        }

        if (createdAt.Offset != TimeSpan.Zero || expiresAt.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Timestamps must use the UTC offset.");
        }

        if (expiresAt <= createdAt)
        {
            throw new ArgumentException("Expiration must be later than creation.", nameof(expiresAt));
        }

        Id = id;
        IdentityId = identityId;
        AppEnvironmentId = appEnvironmentId;
        Purpose = purpose;
        TokenHash = tokenHash.ToArray();
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>Durable selector used for relationships and audit, never as a bearer.</summary>
    public Guid Id { get; private set; }

    /// <summary>Identity authenticated when this session is active and correctly scoped.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Environment boundary enforced during lookup.</summary>
    public Guid AppEnvironmentId { get; private set; }

    /// <summary>Authority class that consumers must enforce after introspection.</summary>
    public IdentitySessionPurpose Purpose { get; private set; }

    /// <summary>Non-reversible lookup material; the clear bearer is never persisted.</summary>
    public byte[] TokenHash { get; private set; } = null!;

    /// <summary>UTC issuance time.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC inactivity boundary; equality with the current time is expired.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    /// <summary>UTC first-revocation time, or <see langword="null"/> while unrevoked.</summary>
    public DateTimeOffset? RevokedAt { get; private set; }
}
