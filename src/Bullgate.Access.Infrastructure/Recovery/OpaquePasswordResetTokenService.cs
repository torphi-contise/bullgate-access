using System.Security.Cryptography;
using System.Text;
using Bullgate.Access.Application.Recovery;

namespace Bullgate.Access.Infrastructure.Recovery;

/// <summary>
/// Issues random, single-use password-reset bearer tokens and derives their persistent
/// SHA-256 hashes.
/// </summary>
/// <remarks>
/// Only the clear base64url token enters the recovery channel. Access stores its hash
/// with lifecycle metadata and cannot reconstruct the delivered value.
/// </remarks>
internal sealed class OpaquePasswordResetTokenService : IPasswordResetTokenService
{
    private const int SecretByteCount = 32;
    private const int EncodedTokenLength = 43;

    /// <inheritdoc />
    public IssuedPasswordResetToken Issue()
    {
        Span<byte> secret = stackalloc byte[SecretByteCount];
        RandomNumberGenerator.Fill(secret);

        try
        {
            var token = Convert.ToBase64String(secret)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            return new IssuedPasswordResetToken(token, HashToken(token));
        }
        finally
        {
            // Clear the raw entropy after the clear token and its storage hash have
            // been produced.
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <inheritdoc />
    public bool TryHash(string? token, out byte[] tokenHash)
    {
        tokenHash = [];
        if (token is null || token.Length != EncodedTokenLength)
        {
            // Fixed length and alphabet define one canonical transport representation;
            // malformed values never reach a persistence lookup.
            return false;
        }

        foreach (var value in token)
        {
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
