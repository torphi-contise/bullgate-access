using System.Security.Cryptography;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.IntegrationClients;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Infrastructure.Bootstrap;

/// <summary>
/// Creates a one-time integration-client credential and the SHA-256 hash retained by
/// Access for later constant-time authentication.
/// </summary>
/// <remarks>
/// The clear token is returned to the bootstrap caller exactly once. This component
/// cannot recover an issued secret from its stored hash.
/// </remarks>
internal sealed class IntegrationClientCredentialIssuer : IIntegrationClientCredentialIssuer
{
    public GeneratedIntegrationClientCredential Issue(DateTimeOffset createdAt)
    {
        var credentialId = Guid.CreateVersion7();
        var secretBytes = RandomNumberGenerator.GetBytes(
            IntegrationClientCredentialToken.SecretByteCount);

        try
        {
            var secretHash = SHA256.HashData(secretBytes);
            var token = IntegrationClientCredentialToken.Create(credentialId, secretBytes);

            return new GeneratedIntegrationClientCredential(
                credentialId,
                secretHash,
                IntegrationClientSecret.Sha256V1,
                createdAt,
                token);
        }
        finally
        {
            // The encoded token is already materialized for the caller; remove the
            // temporary raw secret as soon as both token and hash have been produced.
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }
}
