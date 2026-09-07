using System.Security.Cryptography;

namespace Bullgate.Access.Application.IntegrationClients;

/// <summary>
/// Creates and strictly parses canonical opaque integration credentials.
/// </summary>
/// <remarks>
/// A token carries a lookup id and random secret. It carries no caller-controlled scope
/// or permission claims; those are loaded from persistent topology after verification.
/// </remarks>
public static class IntegrationClientCredentialToken
{
    /// <summary>Canonical prefix for server-to-server integration credentials.</summary>
    public const string Prefix = "bgic_";

    /// <summary>Entropy length of the randomly generated secret portion.</summary>
    public const int SecretByteCount = 32;

    private const int CredentialIdTextLength = 36;
    private const int EncodedSecretLength = 43;
    private const string CanonicalFinalCharacters = "AEIMQUYcgkosw048";
    private static readonly int TokenLength = Prefix.Length
        + CredentialIdTextLength
        + 1
        + EncodedSecretLength;

    /// <summary>Encodes one UUIDv7 lookup id and exact-length random secret.</summary>
    /// <param name="credentialId">Canonical UUIDv7 identifying the hash record.</param>
    /// <param name="secret">Exactly 32 random bytes; callers retain secret ownership.</param>
    /// <returns>The canonical `bgic_&lt;uuid&gt;.&lt;base64url&gt;` bearer token.</returns>
    public static string Create(Guid credentialId, ReadOnlySpan<byte> secret)
    {
        if (credentialId == Guid.Empty || credentialId.Version != 7)
        {
            throw new ArgumentException("Credential id must be a UUIDv7.", nameof(credentialId));
        }

        if (secret.Length != SecretByteCount)
        {
            throw new ArgumentException(
                $"Credential secret must contain exactly {SecretByteCount} bytes.",
                nameof(secret));
        }

        return $"{Prefix}{credentialId:D}.{EncodeSecret(secret)}";
    }

    /// <summary>
    /// Strictly parses canonical token shape into its lookup id and raw secret without
    /// authenticating either value.
    /// </summary>
    /// <remarks>
    /// A successful caller owns the returned secret buffer and must clear it after
    /// hashing. Scope and permissions are never read from token text.
    /// </remarks>
    internal static bool TryParse(
        string? token,
        out Guid credentialId,
        out byte[] secret)
    {
        credentialId = default;
        secret = [];

        if (token is null
            || token.Length != TokenLength
            || !token.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var credentialIdStart = Prefix.Length;
        var separatorIndex = credentialIdStart + CredentialIdTextLength;
        if (token[separatorIndex] != '.')
        {
            return false;
        }

        var credentialIdText = token.AsSpan(credentialIdStart, CredentialIdTextLength);
        // Accept only the lower-case canonical "D" rendering of UUIDv7. Guid parsing
        // alone would accept aliases that create multiple textual forms for one lookup id.
        if (credentialIdText[14] != '7'
            || !Guid.TryParseExact(credentialIdText, "D", out credentialId)
            || !credentialIdText.SequenceEqual(credentialId.ToString("D")))
        {
            credentialId = default;
            return false;
        }

        var encodedSecret = token.AsSpan(separatorIndex + 1, EncodedSecretLength);
        // Only a subset of final characters is canonical for a 32-byte unpadded Base64url
        // value. Rejecting aliases prevents multiple text forms for the same credential.
        if (!CanonicalFinalCharacters.Contains(encodedSecret[^1], StringComparison.Ordinal))
        {
            credentialId = default;
            return false;
        }

        Span<char> paddedBase64 = stackalloc char[EncodedSecretLength + 1];
        for (var index = 0; index < encodedSecret.Length; index++)
        {
            var character = encodedSecret[index];
            if (!IsBase64UrlCharacter(character))
            {
                credentialId = default;
                return false;
            }

            paddedBase64[index] = character switch
            {
                '-' => '+',
                '_' => '/',
                _ => character,
            };
        }

        paddedBase64[^1] = '=';
        var decoded = new byte[SecretByteCount];
        if (!Convert.TryFromBase64Chars(paddedBase64, decoded, out var bytesWritten)
            || bytesWritten != SecretByteCount)
        {
            CryptographicOperations.ZeroMemory(decoded);
            credentialId = default;
            return false;
        }

        secret = decoded;
        return true;
    }

    // Encoding is unpadded canonical Base64url; token parsing admits no standard-Base64
    // aliases, whitespace, or alternate padding for the same secret bytes.
    private static string EncodeSecret(ReadOnlySpan<byte> secret) =>
        Convert.ToBase64String(secret)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static bool IsBase64UrlCharacter(char value) =>
        value is >= 'A' and <= 'Z'
        or >= 'a' and <= 'z'
        or >= '0' and <= '9'
        or '-'
        or '_';
}
