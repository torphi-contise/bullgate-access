namespace Bullgate.Access.Domain.Identities;

/// <summary>
/// Associates one normalized email or phone value with an identity inside a realm.
/// </summary>
/// <remarks>
/// Realm, scheme, and normalized value form the uniqueness boundary. Verification
/// state describes a completed possession contract; it is not inferred from syntax
/// or from a social provider returning the same text.
/// </remarks>
public sealed class IdentityIdentifier
{
    private IdentityIdentifier()
    {
    }

    /// <summary>Creates one normalized realm-scoped identity identifier.</summary>
    /// <param name="id">Durable identifier id.</param>
    /// <param name="identityId">Identity that initially owns the value.</param>
    /// <param name="realmId">Realm inside which ownership is unique.</param>
    /// <param name="scheme">Canonical identifier scheme, such as e-mail or phone.</param>
    /// <param name="normalizedValue">Canonical value produced before construction.</param>
    /// <param name="createdAt">UTC creation time.</param>
    /// <param name="verifiedAt">Optional UTC time of completed possession proof.</param>
    /// <param name="verificationMethod">
    /// Required proof method when <paramref name="verifiedAt"/> is present; otherwise
    /// <see langword="null"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// An id is empty, text is blank, padded, or too long, a timestamp is not UTC,
    /// verification predates creation, or proof time and method are inconsistent.
    /// </exception>
    public IdentityIdentifier(
        Guid id,
        Guid identityId,
        Guid realmId,
        string scheme,
        string normalizedValue,
        DateTimeOffset createdAt,
        DateTimeOffset? verifiedAt = null,
        string? verificationMethod = null)
    {
        Id = RequireId(id, nameof(id));
        IdentityId = RequireId(identityId, nameof(identityId));
        RealmId = RequireId(realmId, nameof(realmId));
        Scheme = RequireText(
            scheme,
            IdentityLimits.IdentifierSchemeMaxLength,
            nameof(scheme));
        NormalizedValue = RequireText(
            normalizedValue,
            IdentityLimits.IdentifierValueMaxLength,
            nameof(normalizedValue));
        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
        if (verifiedAt is not null)
        {
            VerifiedAt = RequireUtc(verifiedAt.Value, nameof(verifiedAt));
            if (VerifiedAt < CreatedAt)
            {
                throw new ArgumentException(
                    "Verification cannot precede creation.",
                    nameof(verifiedAt));
            }

            VerificationMethod = RequireText(
                verificationMethod,
                IdentityLimits.VerificationMethodMaxLength,
                nameof(verificationMethod));
        }
        else if (verificationMethod is not null)
        {
            throw new ArgumentException(
                "A verification method requires a verification timestamp.",
                nameof(verificationMethod));
        }
    }

    /// <summary>Durable identifier id; it is not authentication authority.</summary>
    public Guid Id { get; private set; }

    /// <summary>Current identity owner of this normalized value.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Realm boundary within which the value has one owner.</summary>
    public Guid RealmId { get; private set; }

    /// <summary>Canonical identifier kind, currently e-mail or phone.</summary>
    public string Scheme { get; private set; } = null!;

    /// <summary>Canonical value used by realm-scoped uniqueness checks.</summary>
    public string NormalizedValue { get; private set; } = null!;

    /// <summary>UTC time at which Access stored the identifier.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC proof time, or <see langword="null"/> without possession proof.</summary>
    public DateTimeOffset? VerifiedAt { get; private set; }

    /// <summary>Proof method paired with <see cref="VerifiedAt"/>, when verified.</summary>
    public string? VerificationMethod { get; private set; }

    /// <summary>Moves this identifier to a different identity without merging histories.</summary>
    /// <remarks>
    /// The caller must authorize the conflict resolution and select an identity in the
    /// same realm. Normalized value and existing proof evidence are preserved.
    /// </remarks>
    /// <param name="identityId">New identity owner inside <see cref="RealmId"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="identityId"/> is empty.</exception>
    public void TransferTo(Guid identityId)
    {
        IdentityId = RequireId(identityId, nameof(identityId));
    }

    /// <summary>Records or replaces possession evidence for this identifier.</summary>
    /// <param name="verifiedAt">UTC proof time not earlier than creation.</param>
    /// <param name="verificationMethod">Server-controlled proof method.</param>
    /// <exception cref="ArgumentException">
    /// The timestamp is not UTC or predates creation, or the method is blank, padded,
    /// or too long.
    /// </exception>
    public void Verify(DateTimeOffset verifiedAt, string verificationMethod)
    {
        verifiedAt = RequireUtc(verifiedAt, nameof(verifiedAt));
        if (verifiedAt < CreatedAt)
        {
            throw new ArgumentException(
                "Verification cannot precede creation.",
                nameof(verifiedAt));
        }

        VerifiedAt = verifiedAt;
        VerificationMethod = RequireText(
            verificationMethod,
            IdentityLimits.VerificationMethodMaxLength,
            nameof(verificationMethod));
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
            throw new ArgumentException("Identifier value is invalid.", parameterName);
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
