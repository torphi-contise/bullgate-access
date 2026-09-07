using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.UnitTests;

public sealed class AppEnvironmentRecoveryTests
{
    [Fact]
    public void Constructor_AcceptsTrustedHttpsPasswordRecoveryUrl()
    {
        var environment = Create("https://baybo.app/reset-password");

        Assert.Equal(
            "https://baybo.app/reset-password",
            environment.PasswordRecoveryUrl);
    }

    [Theory]
    [InlineData("http://baybo.app/reset-password")]
    [InlineData("https://user:secret@baybo.app/reset-password")]
    [InlineData("https://baybo.app/reset-password?source=request")]
    [InlineData("https://baybo.app/reset-password#fragment")]
    [InlineData("/reset-password")]
    public void Constructor_RejectsUntrustedPasswordRecoveryUrl(string url)
    {
        Assert.Throws<ArgumentException>(() => Create(url));
    }

    private static AppEnvironment Create(string? passwordRecoveryUrl) =>
        new(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            "development",
            "Development",
            new AppAccessPolicy(
                new IdentifierAccessPolicy(
                    true,
                    true,
                    IdentifierVerificationPolicy.Disabled),
                new IdentifierAccessPolicy(
                    false,
                    false,
                    IdentifierVerificationPolicy.Disabled),
                new AuthenticatorAccessPolicy(true, false, false)),
            DateTimeOffset.Parse("2026-09-02T15:00:00Z"),
            passwordRecoveryUrl);
}
