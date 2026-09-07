using System.Security.Cryptography;
using System.Text;
using Bullgate.Access.Application.Cryptography;
using Microsoft.Extensions.Configuration;

namespace Bullgate.Access.Infrastructure.Cryptography;

/// <summary>
/// Holds the installation master key in memory and derives independent 256-bit keys
/// for named cryptographic purposes.
/// </summary>
/// <remarks>
/// Callers receive a new key buffer and must clear it after use. Disposing this service
/// clears the decoded master-key buffer retained for the process lifetime.
/// </remarks>
internal sealed class InstallationKeyDeriver : IInstallationKeyDeriver, IDisposable
{
    internal const string ConfigurationKey = "Bullgate:MasterKey";
    private const int KeyLength = 32;
    private static readonly byte[] DomainSalt =
        SHA256.HashData(Encoding.UTF8.GetBytes("Bullgate.Access.InstallationKeyDeriver.v1"));

    private readonly byte[] masterKey;

    public InstallationKeyDeriver(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        // Decode once so every derivation uses the same installation identity. This
        // service intentionally does not retain the base64 text supplied by configuration.
        masterKey = DecodeMasterKey(configuration[ConfigurationKey]);
    }

    public byte[] DeriveKey(string purpose)
    {
        if (string.IsNullOrWhiteSpace(purpose))
        {
            throw new ArgumentException("A key-derivation purpose is required.", nameof(purpose));
        }

        var purposeBytes = Encoding.UTF8.GetBytes($"bullgate-access/{purpose.Trim()}");
        var expandInput = new byte[purposeBytes.Length + 1];
        purposeBytes.CopyTo(expandInput, 0);
        expandInput[^1] = 1;

        try
        {
            // The first HMAC extracts fixed-size key material under a domain-specific
            // salt; the second expands it for exactly one named Bullgate Access use.
            var pseudoRandomKey = HMACSHA256.HashData(DomainSalt, masterKey);
            try
            {
                return HMACSHA256.HashData(pseudoRandomKey, expandInput);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pseudoRandomKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(purposeBytes);
            CryptographicOperations.ZeroMemory(expandInput);
        }
    }

    /// <summary>Clears the decoded installation key retained by this service.</summary>
    public void Dispose() => CryptographicOperations.ZeroMemory(masterKey);

    private static byte[] DecodeMasterKey(string? encodedKey)
    {
        if (string.IsNullOrWhiteSpace(encodedKey))
        {
            throw new InvalidOperationException(
                $"{ConfigurationKey} must contain a base64-encoded {KeyLength}-byte key.");
        }

        try
        {
            var decoded = Convert.FromBase64String(encodedKey);
            if (decoded.Length != KeyLength)
            {
                // Reject rather than stretching a short operator-supplied secret. The
                // installation key must already contain 256 bits of random material.
                CryptographicOperations.ZeroMemory(decoded);
                throw new InvalidOperationException(
                    $"{ConfigurationKey} must decode to exactly {KeyLength} bytes.");
            }

            return decoded;
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                $"{ConfigurationKey} must contain valid base64.",
                exception);
        }
    }
}
