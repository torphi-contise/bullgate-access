using Bullgate.Access.Application.Flows;

namespace Bullgate.Access.UnitTests;

public sealed class CpfValueTests
{
    [Theory]
    [InlineData("52998224725", "52998224725")]
    [InlineData("529.982.247-25", "52998224725")]
    [InlineData(" 529.982.247-25 ", "52998224725")]
    public void TryNormalize_AcceptsValidCpfPresentations(
        string input,
        string expected)
    {
        var valid = CpfValue.TryNormalize(input, out var normalized);

        Assert.True(valid);
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("11111111111")]
    [InlineData("52998224724")]
    [InlineData("529-982-247.25")]
    [InlineData("5299822472A")]
    public void TryNormalize_RejectsInvalidCpfValues(string input)
    {
        Assert.False(CpfValue.TryNormalize(input, out _));
    }

    [Fact]
    public void TryParseBirthDate_AcceptsAnIsoDateNotLaterThanToday()
    {
        var valid = CpfValue.TryParseBirthDate(
            "1990-05-21",
            new DateOnly(2026, 9, 8),
            out var birthDate);

        Assert.True(valid);
        Assert.Equal(new DateOnly(1990, 5, 21), birthDate);
    }

    [Theory]
    [InlineData("")]
    [InlineData("21/05/1990")]
    [InlineData("2026-02-29")]
    [InlineData("2026-09-09")]
    public void TryParseBirthDate_RejectsInvalidOrFutureDates(string input)
    {
        Assert.False(CpfValue.TryParseBirthDate(
            input,
            new DateOnly(2026, 9, 8),
            out _));
    }
}
