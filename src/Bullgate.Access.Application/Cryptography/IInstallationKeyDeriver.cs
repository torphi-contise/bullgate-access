namespace Bullgate.Access.Application.Cryptography;

/// <summary>
/// Derives purpose-separated cryptographic keys from the external installation key.
/// </summary>
public interface IInstallationKeyDeriver
{
    /// <summary>
    /// Derives a new 256-bit key for one named cryptographic purpose.
    /// </summary>
    /// <param name="purpose">
    /// Stable, non-secret domain-separation label owned by the calling protocol.
    /// </param>
    /// <returns>A caller-owned key buffer that must be cleared after use.</returns>
    /// <remarks>
    /// The installation master key is never returned. Two distinct purpose labels must
    /// not produce interchangeable keys, so callers must not reuse another component's
    /// label for convenience.
    /// </remarks>
    byte[] DeriveKey(string purpose);
}
