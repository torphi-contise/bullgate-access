namespace Bullgate.Access.Domain.Topology;

/// <summary>
/// Lifecycle metadata and SHA-256 hash for an issued integration credential.
/// </summary>
/// <remarks>The raw credential is returned once and must remain in server secret storage.</remarks>
public sealed class IntegrationClientSecret
{
    /// <summary>Current algorithm contract for 32-byte SHA-256 secret hashes.</summary>
    public const string Sha256V1 = "sha256-v1";

    private IntegrationClientSecret()
    {
    }

    /// <summary>Creates lifecycle metadata for one non-recoverable credential hash.</summary>
    public IntegrationClientSecret(
        Guid id,
        Guid integrationClientId,
        byte[] secretHash,
        string hashAlgorithm,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt = null)
    {
        ArgumentNullException.ThrowIfNull(secretHash);

        if (secretHash.Length == 0)
        {
            throw new ArgumentException("Secret hash cannot be empty.", nameof(secretHash));
        }

        if (hashAlgorithm == Sha256V1 && secretHash.Length != 32)
        {
            throw new ArgumentException(
                "A sha256-v1 secret hash must contain exactly 32 bytes.",
                nameof(secretHash));
        }

        Id = TopologyValue.Id(id, nameof(id));
        IntegrationClientId = TopologyValue.Id(integrationClientId, nameof(integrationClientId));
        SecretHash = secretHash.ToArray();
        HashAlgorithm = TopologyValue.HashAlgorithm(hashAlgorithm, nameof(hashAlgorithm));
        CreatedAt = TopologyValue.UtcTimestamp(createdAt, nameof(createdAt));
        ExpiresAt = expiresAt is null
            ? null
            : TopologyValue.UtcTimestamp(expiresAt.Value, nameof(expiresAt));

        if (ExpiresAt <= CreatedAt)
        {
            throw new ArgumentException("Expiration must be later than creation.", nameof(expiresAt));
        }
    }

    /// <summary>Public lookup id encoded in the clear credential; not authority alone.</summary>
    public Guid Id { get; private set; }

    /// <summary>Integration client that owns the fixed topology and permissions.</summary>
    public Guid IntegrationClientId { get; private set; }

    /// <summary>Non-recoverable hash compared during authentication.</summary>
    public byte[] SecretHash { get; private set; } = null!;

    /// <summary>Versioned hash contract required to interpret <see cref="SecretHash"/>.</summary>
    public string HashAlgorithm { get; private set; } = null!;

    /// <summary>UTC lifecycle creation time.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Optional exclusive upper bound for credential validity.</summary>
    public DateTimeOffset? ExpiresAt { get; private set; }

    /// <summary>Optional time at which authentication authority was explicitly revoked.</summary>
    public DateTimeOffset? RevokedAt { get; private set; }
}
