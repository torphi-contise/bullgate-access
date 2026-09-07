namespace Bullgate.Access.Domain.Topology;

/// <summary>
/// Central validation and normalization rules for persisted topology values.
/// </summary>
/// <remarks>
/// Keeping these rules shared prevents CLI bootstrap, EF materialization helpers,
/// and future topology entry points from assigning different meanings to a key.
/// </remarks>
public static class TopologyValue
{
    /// <summary>Maximum length of a stable natural key.</summary>
    public const int KeyMaxLength = 63;
    /// <summary>Maximum length of a human-readable topology name.</summary>
    public const int NameMaxLength = 120;
    /// <summary>Maximum length of a permission vocabulary value.</summary>
    public const int PermissionMaxLength = 100;
    /// <summary>Maximum length of a versioned credential-hash algorithm name.</summary>
    public const int HashAlgorithmMaxLength = 32;
    /// <summary>Maximum length of a native application or bundle id.</summary>
    public const int ApplicationIdMaxLength = 255;
    /// <summary>Maximum length of public signing-identity metadata.</summary>
    public const int SigningIdentityMaxLength = 512;
    /// <summary>Exact encoded length defined by Android SMS Retriever.</summary>
    public const int SmsRetrieverAppHashLength = 11;
    /// <summary>Maximum length of the HTTPS password-recovery base URL.</summary>
    public const int PasswordRecoveryUrlMaxLength = 2048;

    /// <summary>Rejects an empty durable identifier.</summary>
    public static Guid Id(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }

        return value;
    }

    /// <summary>
    /// Validates a lower-case ASCII natural key that begins with a letter and otherwise
    /// contains only letters, digits, or hyphens.
    /// </summary>
    public static string Key(string value, string parameterName)
    {
        var key = Required(value, KeyMaxLength, parameterName);

        if (!IsAsciiLowercaseLetter(key[0]))
        {
            throw new ArgumentException(
                "Key must start with an ASCII lowercase letter.",
                parameterName);
        }

        for (var index = 1; index < key.Length; index++)
        {
            var character = key[index];
            if (!IsAsciiLowercaseLetter(character)
                && !char.IsAsciiDigit(character)
                && character != '-')
            {
                throw new ArgumentException(
                    "Key may contain only ASCII lowercase letters, digits, and hyphens.",
                    parameterName);
            }
        }

        return key;
    }

    /// <summary>Validates a required, trimmed topology display name.</summary>
    public static string Name(string value, string parameterName) =>
        Required(value, NameMaxLength, parameterName);

    /// <summary>Validates the storage shape of a permission value.</summary>
    public static string Permission(string value, string parameterName) =>
        Required(value, PermissionMaxLength, parameterName);

    /// <summary>Validates a versioned credential-hash algorithm name.</summary>
    public static string HashAlgorithm(string value, string parameterName) =>
        Required(value, HashAlgorithmMaxLength, parameterName);

    /// <summary>Validates a required native application identifier.</summary>
    public static string ApplicationId(string value, string parameterName) =>
        Required(value, ApplicationIdMaxLength, parameterName);

    /// <summary>Validates optional native application metadata without inventing it.</summary>
    public static string? OptionalApplicationId(string? value, string parameterName) =>
        Optional(value, ApplicationIdMaxLength, parameterName);

    /// <summary>Validates required signing-identity metadata.</summary>
    public static string SigningIdentity(string value, string parameterName) =>
        Required(value, SigningIdentityMaxLength, parameterName);

    /// <summary>Validates optional signing-identity metadata.</summary>
    public static string? OptionalSigningIdentity(string? value, string parameterName) =>
        Optional(value, SigningIdentityMaxLength, parameterName);

    /// <summary>Validates the exact unpadded base64 shape of an optional SMS app hash.</summary>
    public static string? SmsRetrieverAppHash(string? value, string parameterName)
    {
        if (value is null)
        {
            return null;
        }

        if (value.Length != SmsRetrieverAppHashLength
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '+' and not '/'))
        {
            throw new ArgumentException(
                "SMS Retriever app hash must contain 11 base64 characters.",
                parameterName);
        }

        return value;
    }

    /// <summary>
    /// Validates an optional absolute HTTPS recovery URL without credentials, query, or
    /// fragment, leaving token construction to the delivery use case.
    /// </summary>
    public static string? PasswordRecoveryUrl(string? value, string parameterName)
    {
        if (value is null)
        {
            return null;
        }

        var validated = Required(value, PasswordRecoveryUrlMaxLength, parameterName);
        if (!Uri.TryCreate(validated, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(uri.Host)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException(
                "Password recovery URL must be an absolute HTTPS URL without credentials, query, or fragment.",
                parameterName);
        }

        return validated;
    }

    /// <summary>Rejects timestamps whose explicit offset is not UTC.</summary>
    public static DateTimeOffset UtcTimestamp(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Timestamp must use the UTC offset.", parameterName);
        }

        return value;
    }

    private static string Required(string value, int maxLength, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be empty or whitespace.", parameterName);
        }

        if (value.Length > maxLength)
        {
            throw new ArgumentException(
                $"Value cannot be longer than {maxLength} characters.",
                parameterName);
        }

        if (!string.Equals(value, value.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException("Value cannot have surrounding whitespace.", parameterName);
        }

        return value;
    }

    private static string? Optional(string? value, int maxLength, string parameterName) =>
        value is null ? null : Required(value, maxLength, parameterName);

    private static bool IsAsciiLowercaseLetter(char value) => value is >= 'a' and <= 'z';
}
