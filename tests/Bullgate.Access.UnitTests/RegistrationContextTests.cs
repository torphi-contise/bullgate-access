using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.UnitTests;

public sealed class RegistrationContextTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 1, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void NewContext_RemainsOpenWithoutTimeBasedExpiration()
    {
        var context = CreateContext();

        Assert.Equal(RegistrationContextStatus.Open, context.Status);
        Assert.Null(context.ClosedAt);
    }

    [Theory]
    [InlineData(RegistrationContextStatus.Completed)]
    [InlineData(RegistrationContextStatus.Abandoned)]
    public void ClosingContext_IsTerminalAndIdempotent(
        RegistrationContextStatus terminalStatus)
    {
        var context = CreateContext();
        var closedAt = Now.AddMinutes(5);

        Close(context, terminalStatus, closedAt);
        Close(context, terminalStatus, closedAt.AddMinutes(1));

        Assert.Equal(terminalStatus, context.Status);
        Assert.Equal(closedAt, context.ClosedAt);
        Assert.Throws<InvalidOperationException>(
            () => Close(
                context,
                terminalStatus == RegistrationContextStatus.Completed
                    ? RegistrationContextStatus.Abandoned
                    : RegistrationContextStatus.Completed,
                closedAt));
    }

    [Fact]
    public void Context_CannotCloseBeforeCreation()
    {
        var context = CreateContext();

        Assert.Throws<ArgumentException>(() => context.Complete(Now.AddTicks(-1)));
    }

    private static RegistrationContext CreateContext() =>
        new(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Now);

    private static void Close(
        RegistrationContext context,
        RegistrationContextStatus status,
        DateTimeOffset closedAt)
    {
        if (status == RegistrationContextStatus.Completed)
        {
            context.Complete(closedAt);
            return;
        }

        context.Abandon(closedAt);
    }
}
