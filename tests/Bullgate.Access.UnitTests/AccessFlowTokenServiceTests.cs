using System.Security.Cryptography;
using Bullgate.Access.Application.Cryptography;
using Bullgate.Access.Infrastructure.EmailPassword;
using Bullgate.Access.Infrastructure.Flows;

namespace Bullgate.Access.UnitTests;

public sealed class AccessFlowTokenServiceTests
{
    [Fact]
    public void Capability_IsDeterministicAndBoundToItsScope()
    {
        var keys = new FixedKeyDeriver();
        using var tokens = new HmacAccessFlowTokenService(keys);
        var flowId = Guid.NewGuid();
        var integrationClientId = Guid.NewGuid();
        var appEnvironmentId = Guid.NewGuid();

        var first = tokens.IssueCapability(
            flowId,
            integrationClientId,
            appEnvironmentId);
        var second = tokens.IssueCapability(
            flowId,
            integrationClientId,
            appEnvironmentId);

        Assert.Equal(first, second);
        Assert.StartsWith("bgf_", first, StringComparison.Ordinal);
        Assert.True(tokens.IsValidCapability(
            first,
            flowId,
            integrationClientId,
            appEnvironmentId));
        Assert.False(tokens.IsValidCapability(
            first,
            Guid.NewGuid(),
            integrationClientId,
            appEnvironmentId));
        Assert.Equal(HmacAccessFlowTokenService.KeyPurpose, keys.LastPurpose);
    }

    [Fact]
    public void IdempotentSessionToken_UsesTheExistingOpaqueSessionFormat()
    {
        using var flowTokens = new HmacAccessFlowTokenService(
            new FixedKeyDeriver());
        var sessionTokens = new OpaqueSessionTokenService();
        var flowId = Guid.NewGuid();
        var requestId = Guid.NewGuid();
        var identityId = Guid.NewGuid();
        var appEnvironmentId = Guid.NewGuid();

        var first = flowTokens.IssueSession(
            flowId,
            requestId,
            identityId,
            appEnvironmentId);
        var second = flowTokens.IssueSession(
            flowId,
            requestId,
            identityId,
            appEnvironmentId);

        Assert.Equal(first.Token, second.Token);
        Assert.StartsWith("bgs_", first.Token, StringComparison.Ordinal);
        Assert.True(sessionTokens.TryHash(first.Token, out var parsedHash));
        Assert.True(CryptographicOperations.FixedTimeEquals(
            first.TokenHash,
            parsedHash));
    }

    private sealed class FixedKeyDeriver : IInstallationKeyDeriver
    {
        private static readonly byte[] Key = Enumerable.Range(1, 32)
            .Select(value => (byte)value)
            .ToArray();

        public string? LastPurpose { get; private set; }

        public byte[] DeriveKey(string purpose)
        {
            LastPurpose = purpose;
            return [.. Key];
        }
    }
}
