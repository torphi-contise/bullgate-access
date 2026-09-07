using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.UnitTests;

public sealed class PasswordResetTokenTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 2, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Constructor_CopiesTheHashAndCreatesAnActiveToken()
    {
        var hash = Enumerable.Repeat(
                (byte)7,
                IdentityLimits.PasswordResetTokenHashLength)
            .ToArray();
        var token = CreateToken(hash: hash);

        hash[0] = 9;

        Assert.True(token.IsActive(Now));
        Assert.Equal(7, token.TokenHash[0]);
        Assert.Null(token.UsedAt);
    }

    [Fact]
    public void MarkUsed_MakesTheTokenInactive()
    {
        var token = CreateToken();
        var usedAt = Now.AddMinutes(5);

        token.MarkUsed(usedAt);

        Assert.Equal(usedAt, token.UsedAt);
        Assert.False(token.IsActive(usedAt));
        Assert.Throws<InvalidOperationException>(() => token.MarkUsed(usedAt));
    }

    [Fact]
    public void MarkUsed_MustHappenAfterCreationAndBeforeExpiration()
    {
        Assert.Throws<ArgumentException>(
            () => CreateToken().MarkUsed(Now.AddTicks(-1)));
        Assert.Throws<InvalidOperationException>(
            () => CreateToken().MarkUsed(Now.AddMinutes(10)));
    }

    [Fact]
    public void Constructor_RejectsInvalidScopeHashAndTimestamps()
    {
        Assert.Throws<ArgumentException>(() => CreateToken(identityId: Guid.Empty));
        Assert.Throws<ArgumentException>(() => CreateToken(appEnvironmentId: Guid.Empty));
        Assert.Throws<ArgumentException>(() => CreateToken(hash: new byte[31]));
        Assert.Throws<ArgumentException>(
            () => CreateToken(createdAt: Now.ToOffset(TimeSpan.FromHours(-3))));
        Assert.Throws<ArgumentException>(() => CreateToken(expiresAt: Now));
    }

    private static PasswordResetToken CreateToken(
        Guid? identityId = null,
        Guid? appEnvironmentId = null,
        byte[]? hash = null,
        DateTimeOffset? createdAt = null,
        DateTimeOffset? expiresAt = null) =>
        new(
            Guid.NewGuid(),
            identityId ?? Guid.NewGuid(),
            appEnvironmentId ?? Guid.NewGuid(),
            hash ?? new byte[IdentityLimits.PasswordResetTokenHashLength],
            createdAt ?? Now,
            expiresAt ?? Now.AddMinutes(10));
}
