using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.UnitTests;

public sealed class IdentityLifecycleTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 1, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void NewIdentity_IsActive()
    {
        var identity = CreateIdentity();

        Assert.Equal(IdentityLifecycleState.Active, identity.LifecycleState);
    }

    [Fact]
    public void Abandonment_IsTerminalAndIdempotent()
    {
        var identity = CreateIdentity();

        identity.Abandon();
        identity.Abandon();

        Assert.Equal(IdentityLifecycleState.Abandoned, identity.LifecycleState);
    }

    private static Identity CreateIdentity() =>
        new(Guid.NewGuid(), Guid.NewGuid(), Now);
}
