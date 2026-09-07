namespace Bullgate.Access.Domain.Identities;

/// <summary>
/// Server-validated social-provider subject associated with an identity in a realm.
/// </summary>
/// <remarks>
/// The provider email is descriptive authenticator metadata. Equal email text does
/// not authorize identity merging or ownership transfer.
/// </remarks>
public sealed class SocialCredential
{
    private SocialCredential()
    {
    }

    /// <summary>Creates one realm-scoped provider credential owned by an identity.</summary>
    /// <param name="id">Durable credential identifier.</param>
    /// <param name="identityId">Identity that owns the provider subject.</param>
    /// <param name="realmId">Realm inside which subject ownership is unique.</param>
    /// <param name="provider">Canonical supported provider name.</param>
    /// <param name="subject">Stable provider account identifier.</param>
    /// <param name="email">Provider e-mail retained as mutable metadata.</param>
    /// <param name="createdAt">UTC ownership-establishment time.</param>
    /// <exception cref="ArgumentException">
    /// An identifier is empty, text is blank, padded, or too long, or the timestamp is
    /// not UTC.
    /// </exception>
    public SocialCredential(
        Guid id,
        Guid identityId,
        Guid realmId,
        string provider,
        string subject,
        string email,
        DateTimeOffset createdAt)
    {
        Id = RequireId(id, nameof(id));
        IdentityId = RequireId(identityId, nameof(identityId));
        RealmId = RequireId(realmId, nameof(realmId));
        Provider = RequireText(
            provider,
            IdentityLimits.SocialProviderMaxLength,
            nameof(provider));
        Subject = RequireText(
            subject,
            IdentityLimits.SocialSubjectMaxLength,
            nameof(subject));
        Email = RequireText(email, IdentityLimits.IdentifierValueMaxLength, nameof(email));
        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
        UpdatedAt = CreatedAt;
    }

    /// <summary>Durable credential identifier; it does not grant provider authority.</summary>
    public Guid Id { get; private set; }

    /// <summary>Identity that owns this provider credential.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Realm boundary for provider-subject uniqueness.</summary>
    public Guid RealmId { get; private set; }

    /// <summary>Canonical provider name, currently Google or Apple.</summary>
    public string Provider { get; private set; } = null!;

    /// <summary>Immutable provider account key used for identity ownership.</summary>
    public string Subject { get; private set; } = null!;

    /// <summary>Latest provider e-mail metadata; never an identity merge key.</summary>
    public string Email { get; private set; } = null!;

    /// <summary>UTC time at which subject ownership was established.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC time of the latest provider metadata refresh.</summary>
    public DateTimeOffset UpdatedAt { get; private set; }

    /// <summary>Refreshes provider e-mail metadata without changing subject ownership.</summary>
    /// <param name="email">New normalized provider e-mail metadata.</param>
    /// <param name="updatedAt">UTC refresh time not earlier than creation.</param>
    /// <exception cref="ArgumentException">
    /// The e-mail is blank, padded, or too long, the timestamp is not UTC, or it
    /// predates credential creation.
    /// </exception>
    public void UpdateEmail(string email, DateTimeOffset updatedAt)
    {
        Email = RequireText(email, IdentityLimits.IdentifierValueMaxLength, nameof(email));
        UpdatedAt = RequireUtc(updatedAt, nameof(updatedAt));
        if (UpdatedAt < CreatedAt)
        {
            throw new ArgumentException(
                "Update cannot precede creation.",
                nameof(updatedAt));
        }
    }

    private static Guid RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }

        return value;
    }

    private static string RequireText(string? value, int maxLength, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);

        if (string.IsNullOrWhiteSpace(value)
            || value.Length > maxLength
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException("Social credential value is invalid.", parameterName);
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

/// <summary>Stable social provider names accepted by the current domain.</summary>
public static class SocialProvider
{
    /// <summary>Canonical Google provider discriminator persisted by Access.</summary>
    public const string Google = "google";

    /// <summary>Canonical Apple provider discriminator persisted by Access.</summary>
    public const string Apple = "apple";
}
