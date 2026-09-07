using System.Security.Cryptography;
using System.Text;
using Bullgate.Access.Application.EmailPassword;

namespace Bullgate.Access.Infrastructure.EmailPassword;

/// <summary>
/// Issues random opaque product or registration session tokens and derives the
/// SHA-256 hashes retained by Access.
/// </summary>
/// <remarks>
/// The `bgs_` prefix identifies token purpose but grants no authority by itself. Parsing
/// accepts one canonical base64url shape so alternative textual encodings cannot name
/// the same logical bearer value.
/// </remarks>
internal sealed class OpaqueSessionTokenService : ISessionTokenService
{
    private const string Prefix = "bgs_";
    private const int SecretByteCount = 32;
    private const int EncodedSecretLength = 43;
    private static readonly int TokenLength = Prefix.Length + EncodedSecretLength;

    /// <inheritdoc />
    public IssuedSessionToken Issue()
    {
        Span<byte> secret = stackalloc byte[SecretByteCount];
        RandomNumberGenerator.Fill(secret);

        try
        {
            var encoded = Convert.ToBase64String(secret)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            var token = Prefix + encoded;
            return new IssuedSessionToken(token, HashToken(token));
        }
        finally
        {
            // The clear token has already been materialized for the response. Remove
            // the temporary random bytes immediately after deriving token and hash.
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <inheritdoc />
    public bool TryHash(string? token, out byte[] tokenHash)
    {
        tokenHash = [];
        if (token is null
            || token.Length != TokenLength
            || !token.StartsWith(Prefix, StringComparison.Ordinal))
        {
            // Reject malformed input before hashing. This is format validation only;
            // ownership and activity are decided by the constant-size stored hash.
            return false;
        }

        for (var index = Prefix.Length; index < token.Length; index++)
        {
            var value = token[index];
            if (value is not (>= 'A' and <= 'Z')
                and not (>= 'a' and <= 'z')
                and not (>= '0' and <= '9')
                and not '-'
                and not '_')
            {
                return false;
            }
        }

        tokenHash = HashToken(token);
        return true;
    }

    private static byte[] HashToken(string token)
    {
        var bytes = Encoding.ASCII.GetBytes(token);
        try
        {
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
