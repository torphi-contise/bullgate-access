using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bullgate.Access.Application.Cryptography;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Infrastructure.Configuration;

/// <summary>
/// Database representation of one authenticated-encryption envelope.
/// </summary>
internal sealed record ProtectedAppEnvironmentConfiguration(
    int FormatVersion,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] Tag);

/// <summary>
/// Protects and restores the complete secret-bearing configuration owned by one app
/// environment.
/// </summary>
internal interface IAppEnvironmentConfigurationProtector
{
    /// <summary>
    /// Creates a fresh authenticated envelope bound to the owning environment.
    /// </summary>
    ProtectedAppEnvironmentConfiguration Protect(
        Guid appEnvironmentId,
        AppEnvironmentConfiguration configuration);

    /// <summary>
    /// Authenticates and deserializes an envelope only for its owning environment and
    /// supported format.
    /// </summary>
    AppEnvironmentConfiguration Unprotect(
        Guid appEnvironmentId,
        ProtectedAppEnvironmentConfiguration protectedConfiguration);
}

/// <summary>
/// Serializes environment configuration using a strict schema and protects it with a
/// purpose-derived AES-256-GCM key.
/// </summary>
/// <remarks>
/// The environment id and format version are authenticated as associated data. Moving
/// a valid envelope to another environment or interpreting it as another version fails
/// authentication instead of silently changing its security scope.
/// </remarks>
internal sealed class AppEnvironmentConfigurationProtector(
    IInstallationKeyDeriver keyDeriver)
    : IAppEnvironmentConfigurationProtector
{
    internal const int CurrentFormatVersion = 2;
    internal const string KeyPurpose = "app-environment-configuration-v2";
    private const int NonceLength = 12;
    private const int TagLength = 16;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        // Configuration is a security contract. Rejecting unknown members prevents a
        // misspelled policy or provider property from being accepted but ignored.
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() },
    };

    public ProtectedAppEnvironmentConfiguration Protect(
        Guid appEnvironmentId,
        AppEnvironmentConfiguration configuration)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(appEnvironmentId, Guid.Empty);
        ArgumentNullException.ThrowIfNull(configuration);

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(configuration, SerializerOptions);
        // A new nonce is mandatory even when bootstrap reapplies byte-for-byte identical
        // configuration. GCM security depends on never reusing a nonce with the same key.
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];
        var key = keyDeriver.DeriveKey(KeyPurpose);
        var associatedData = CreateAssociatedData(appEnvironmentId, CurrentFormatVersion);

        try
        {
            using var aes = new AesGcm(key, TagLength);
            // Associated data binds the ciphertext to both its owner and wire format;
            // it is authenticated but intentionally not stored inside the ciphertext.
            aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            return new ProtectedAppEnvironmentConfiguration(
                CurrentFormatVersion,
                nonce,
                ciphertext,
                tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(associatedData);
        }
    }

    public AppEnvironmentConfiguration Unprotect(
        Guid appEnvironmentId,
        ProtectedAppEnvironmentConfiguration protectedConfiguration)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(appEnvironmentId, Guid.Empty);
        ArgumentNullException.ThrowIfNull(protectedConfiguration);
        if (protectedConfiguration.FormatVersion != CurrentFormatVersion)
        {
            // Never guess how an older or newer envelope was serialized. A future
            // format needs an explicit reader or migration path.
            throw new InvalidOperationException(
                $"Unsupported app-environment configuration format version " +
                $"'{protectedConfiguration.FormatVersion}'.");
        }
        if (protectedConfiguration.Nonce.Length != NonceLength
            || protectedConfiguration.Tag.Length != TagLength
            || protectedConfiguration.Ciphertext.Length == 0)
        {
            // Reject malformed envelopes before allocating authority from their content.
            // Shape validation is not authentication; the GCM tag remains authoritative.
            throw new InvalidOperationException(
                "The protected app-environment configuration has an invalid shape.");
        }

        var plaintext = new byte[protectedConfiguration.Ciphertext.Length];
        var key = keyDeriver.DeriveKey(KeyPurpose);
        var associatedData = CreateAssociatedData(
            appEnvironmentId,
            protectedConfiguration.FormatVersion);

        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(
                protectedConfiguration.Nonce,
                protectedConfiguration.Ciphertext,
                protectedConfiguration.Tag,
                plaintext,
                associatedData);
            return JsonSerializer.Deserialize<AppEnvironmentConfiguration>(
                plaintext,
                SerializerOptions)
                ?? throw new InvalidOperationException(
                    "The decrypted app-environment configuration is empty.");
        }
        catch (AuthenticationTagMismatchException exception)
        {
            // Use one failure for a wrong installation key, changed associated data,
            // and tampered ciphertext; none of those cases should yield partial data.
            throw new InvalidOperationException(
                "The app-environment configuration could not be authenticated.",
                exception);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                "The decrypted app-environment configuration is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(associatedData);
        }
    }

    private static byte[] CreateAssociatedData(Guid appEnvironmentId, int formatVersion) =>
        Encoding.UTF8.GetBytes(
            $"bullgate-access/app-environment-configuration/{formatVersion}/" +
            appEnvironmentId.ToString("D"));
}
