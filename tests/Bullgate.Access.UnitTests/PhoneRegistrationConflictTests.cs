using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.UnitTests;

public sealed class PhoneRegistrationConflictTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 2, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void NewConflict_HasNoFailedEmailAttempts()
    {
        var conflict = CreateConflict();

        Assert.Equal(0, conflict.FailedEmailAttempts);
        Assert.Null(conflict.EmailResolutionExhaustedAt);
    }

    [Fact]
    public void EmailMismatch_ReportsExhaustionAtConfiguredLimit()
    {
        var conflict = CreateConflict();

        Assert.False(conflict.RecordEmailMismatch(2, Now.AddMinutes(1)));
        Assert.True(conflict.RecordEmailMismatch(2, Now.AddMinutes(2)));
        Assert.Equal(2, conflict.FailedEmailAttempts);
        Assert.Equal(Now.AddMinutes(2), conflict.EmailResolutionExhaustedAt);
    }

    [Fact]
    public void EmailMismatch_CannotBeRecordedAfterExhaustion()
    {
        var conflict = CreateConflict();
        conflict.RecordEmailMismatch(1, Now.AddMinutes(1));

        Assert.Throws<InvalidOperationException>(
            () => conflict.RecordEmailMismatch(2, Now.AddMinutes(2)));
        Assert.Equal(1, conflict.FailedEmailAttempts);
        Assert.Equal(Now.AddMinutes(1), conflict.EmailResolutionExhaustedAt);
    }

    [Fact]
    public void EmailMismatch_CannotBeRecordedOutsideConflictLifetime()
    {
        var conflict = CreateConflict();

        Assert.Throws<InvalidOperationException>(
            () => conflict.RecordEmailMismatch(5, Now.AddTicks(-1)));
        Assert.Throws<InvalidOperationException>(
            () => conflict.RecordEmailMismatch(5, Now.AddMinutes(15)));
    }

    [Fact]
    public void Conflict_RequiresPositiveLifetime()
    {
        Assert.Throws<ArgumentException>(
            () => new PhoneRegistrationConflict(
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                Now,
                Now));
    }

    private static PhoneRegistrationConflict CreateConflict() =>
        new(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Now,
            Now.AddMinutes(15));
}
