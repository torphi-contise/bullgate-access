using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Recovery;

namespace Bullgate.Access.UnitTests;

public sealed class PasswordResetTokenServiceTests
{
    [Fact]
    public void Issue_GeneratesCanonicalBase64UrlTokenThatCanBeRehashed()
    {
        var service = new OpaquePasswordResetTokenService();

        var issued = service.Issue();

        Assert.Equal(43, issued.Token.Length);
        Assert.DoesNotContain("=", issued.Token, StringComparison.Ordinal);
        Assert.Equal(
            IdentityLimits.PasswordResetTokenHashLength,
            issued.TokenHash.Length);
        Assert.True(service.TryHash(issued.Token, out var rehashed));
        Assert.Equal(issued.TokenHash, rehashed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("bgr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!")]
    public void TryHash_RejectsMalformedTokens(string? token)
    {
        var service = new OpaquePasswordResetTokenService();

        var valid = service.TryHash(token, out var tokenHash);

        Assert.False(valid);
        Assert.Empty(tokenHash);
    }
}
