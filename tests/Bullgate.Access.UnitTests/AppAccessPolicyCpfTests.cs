using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.UnitTests;

public sealed class AppAccessPolicyCpfTests
{
    [Theory]
    [InlineData(null, true, true)]
    [InlineData(CpfCollectionPosition.AfterPhone, false, false)]
    [InlineData(CpfCollectionPosition.AfterPhone, true, false)]
    public void InvalidCpfPosition_IsRejected(
        CpfCollectionPosition? position, bool phoneEnabled, bool phoneRequired)
    {
        Assert.Throws<ArgumentException>(() => Create(position, phoneEnabled, phoneRequired));
    }

    [Theory]
    [InlineData(CpfCollectionPosition.BeforePhone, false, false)]
    [InlineData(CpfCollectionPosition.BeforePhone, true, false)]
    [InlineData(CpfCollectionPosition.BeforePhone, true, true)]
    [InlineData(CpfCollectionPosition.AfterPhone, true, true)]
    public void ValidCpfPosition_DoesNotRequirePhoneVerification(
        CpfCollectionPosition position, bool phoneEnabled, bool phoneRequired)
    {
        var policy = Create(position, phoneEnabled, phoneRequired);
        Assert.Equal(position, policy.CpfCollectionPosition);
        Assert.False(policy.Phone.Verification.Enabled);
    }

    private static AppAccessPolicy Create(
        CpfCollectionPosition? position, bool phoneEnabled, bool phoneRequired) => new(
        new IdentifierAccessPolicy(true, true, IdentifierVerificationPolicy.Disabled),
        new IdentifierAccessPolicy(phoneEnabled, phoneRequired, IdentifierVerificationPolicy.Disabled),
        new AuthenticatorAccessPolicy(true, false, false),
        new IdentifierAccessPolicy(true, true, IdentifierVerificationPolicy.Disabled),
        position);
}
