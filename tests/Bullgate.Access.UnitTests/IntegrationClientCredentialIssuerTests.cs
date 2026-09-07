using System.Security.Cryptography;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Bootstrap;

namespace Bullgate.Access.UnitTests;

public sealed class IntegrationClientCredentialIssuerTests
{
    [Fact]
    public void Issue_CreatesVersionedBearerTokenWhoseSecretMatchesStoredHash()
    {
        var issuer = new IntegrationClientCredentialIssuer();
        var createdAt = DateTimeOffset.Parse("2026-08-31T20:00:00Z");

        var credential = issuer.Issue(createdAt);

        var prefix = $"bgic_{credential.CredentialId:D}.";
        Assert.StartsWith(prefix, credential.Token, StringComparison.Ordinal);

        var encodedSecret = credential.Token[prefix.Length..];
        var secret = DecodeBase64Url(encodedSecret);

        Assert.Equal(32, secret.Length);
        Assert.Equal(SHA256.HashData(secret), credential.SecretHash);
        Assert.Equal(IntegrationClientSecret.Sha256V1, credential.HashAlgorithm);
        Assert.Equal(createdAt, credential.CreatedAt);
        Assert.Equal(7, credential.CredentialId.Version);
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        var paddingLength = (4 - (base64.Length % 4)) % 4;
        return Convert.FromBase64String(base64 + new string('=', paddingLength));
    }
}
