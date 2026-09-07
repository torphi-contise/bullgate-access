namespace Bullgate.Access.Domain.Identities;

/// <summary>Current provider-encoded password hash and rotation timestamps for one identity.</summary>
/// <remarks>
/// This entity never receives a clear password and does not decide whether rotation is
/// authorized. Application services establish that authority and supply the encoded hash.
/// </remarks>
public sealed class PasswordCredential
{
    private PasswordCredential()
    {
    }

    /// <summary>Creates the first persisted password credential for an identity.</summary>
    /// <param name="identityId">Identity that owns this one-to-one credential.</param>
    /// <param name="passwordHash">Non-empty provider-encoded hash, never a clear password.</param>
    /// <param name="createdAt">UTC credential creation time.</param>
    /// <exception cref="ArgumentNullException"><paramref name="passwordHash"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// The identity id is empty, the hash is blank or too long, or the timestamp is not UTC.
    /// </exception>
    public PasswordCredential(Guid identityId, string passwordHash, DateTimeOffset createdAt)
    {
        if (identityId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(identityId));
        }

        ArgumentNullException.ThrowIfNull(passwordHash);
        if (string.IsNullOrWhiteSpace(passwordHash)
            || passwordHash.Length > IdentityLimits.PasswordHashMaxLength)
        {
            throw new ArgumentException("Password hash is invalid.", nameof(passwordHash));
        }

        if (createdAt.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Timestamp must use the UTC offset.", nameof(createdAt));
        }

        IdentityId = identityId;
        PasswordHash = passwordHash;
        CreatedAt = createdAt;
        UpdatedAt = createdAt;
    }

    /// <summary>Identity that exclusively owns this credential.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Opaque provider-encoded hash used only by the password hash service.</summary>
    public string PasswordHash { get; private set; } = null!;

    /// <summary>UTC time at which the first password credential was created.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC time attached to the currently persisted hash.</summary>
    public DateTimeOffset UpdatedAt { get; private set; }

    /// <summary>Replaces the persisted encoded hash after authority was established upstream.</summary>
    /// <remarks>
    /// This method performs domain-shape validation only. It neither checks the previous
    /// password nor consumes reset authority; the calling use case owns those decisions.
    /// </remarks>
    /// <param name="passwordHash">New non-empty provider-encoded hash.</param>
    /// <param name="updatedAt">UTC replacement time not earlier than credential creation.</param>
    /// <exception cref="ArgumentNullException"><paramref name="passwordHash"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// The hash is blank or too long, or the timestamp is not UTC or predates creation.
    /// </exception>
    public void Replace(string passwordHash, DateTimeOffset updatedAt)
    {
        ArgumentNullException.ThrowIfNull(passwordHash);
        if (string.IsNullOrWhiteSpace(passwordHash)
            || passwordHash.Length > IdentityLimits.PasswordHashMaxLength)
        {
            throw new ArgumentException("Password hash is invalid.", nameof(passwordHash));
        }

        if (updatedAt.Offset != TimeSpan.Zero || updatedAt < CreatedAt)
        {
            throw new ArgumentException(
                "Update timestamp is invalid.",
                nameof(updatedAt));
        }

        PasswordHash = passwordHash;
        UpdatedAt = updatedAt;
    }
}
