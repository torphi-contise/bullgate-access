using Bullgate.Access.Application.EmailPassword;

namespace Bullgate.Access.UnitTests;

public sealed class EmailPasswordAccessServiceTests
{
    [Theory]
    [InlineData(" Person@Example.COM ", "person@example.com")]
    [InlineData("user+tag@example.com", "user+tag@example.com")]
    public void TryNormalizeEmail_StoresTheQueryableCanonicalValue(
        string input,
        string expected)
    {
        var valid = EmailPasswordAccessService.TryNormalizeEmail(input, out var normalized);

        Assert.True(valid);
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-an-email")]
    [InlineData("Display Name <person@example.com>")]
    public void TryNormalizeEmail_RejectsValuesThatAreNotPlainAddresses(string input)
    {
        var valid = EmailPasswordAccessService.TryNormalizeEmail(input, out _);

        Assert.False(valid);
    }
}
