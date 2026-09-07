namespace Bullgate.Access.Application.Bootstrap;

/// <summary>
/// Generates an opaque integration credential and its hash for one-time issuance.
/// </summary>
public interface IIntegrationClientCredentialIssuer
{
    /// <summary>
    /// Creates fresh credential material whose clear token is returned once and whose
    /// hash metadata is suitable for durable storage.
    /// </summary>
    GeneratedIntegrationClientCredential Issue(DateTimeOffset createdAt);
}

/// <summary>One-time clear integration credential plus its persistent hash metadata.</summary>
/// <remarks><see cref="Token"/> is server bearer authority and is not safe for logs.</remarks>
/// <param name="CredentialId">UUIDv7 lookup id encoded into the clear token.</param>
/// <param name="SecretHash">Only secret representation retained by Access.</param>
/// <param name="HashAlgorithm">Versioned algorithm name required during authentication.</param>
/// <param name="CreatedAt">Authoritative lifecycle creation time.</param>
/// <param name="Token">One-time clear credential for secure caller storage.</param>
public sealed record GeneratedIntegrationClientCredential(
    Guid CredentialId,
    byte[] SecretHash,
    string HashAlgorithm,
    DateTimeOffset CreatedAt,
    string Token);
