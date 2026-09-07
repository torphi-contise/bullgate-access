using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.UnitTests;

public sealed class PasswordResetServiceTests
{
    [Fact]
    public async Task Reset_RejectsWhitespaceOnlyPasswordBeforeAccessingTheStore()
    {
        var service = new PasswordResetService(
            new UnexpectedPasswordResetStore(),
            new PasswordEnabledConfigurationReader(),
            new UnexpectedPasswordHashService(),
            new ValidPasswordResetTokenService(),
            TimeProvider.System);

        var result = await service.ResetAsync(
            Guid.NewGuid(),
            new string('A', 43),
            "        ");

        Assert.Equal(PasswordResetError.MissingNewPassword, result.Error);
    }

    private sealed class PasswordEnabledConfigurationReader
        : IAppEnvironmentConfigurationReader
    {
        private static readonly AppAccessPolicy Policy = new(
            new IdentifierAccessPolicy(false, false, IdentifierVerificationPolicy.Disabled),
            new IdentifierAccessPolicy(false, false, IdentifierVerificationPolicy.Disabled),
            new AuthenticatorAccessPolicy(true, false, false));

        private static readonly AppEnvironmentConfiguration Configuration = new(
            Policy,
            new AppVerificationPolicy(10, 5, 5, 120, 15, 5),
            new AppRecoveryPolicy(null, 60, 5, 10, 5, 5, 120),
            new AppEnvironmentProviders(null, null, null, null),
            new DevelopmentBypassConfiguration(false, null, null),
            [],
            []);

        public Task<AppEnvironmentConfiguration?> FindAsync(
            Guid appEnvironmentId,
            CancellationToken cancellationToken) =>
            Task.FromResult<AppEnvironmentConfiguration?>(Configuration);
    }

    private sealed class ValidPasswordResetTokenService : IPasswordResetTokenService
    {
        public IssuedPasswordResetToken Issue() => throw new InvalidOperationException();

        public bool TryHash(string? token, out byte[] tokenHash)
        {
            tokenHash = new byte[IdentityLimits.PasswordResetTokenHashLength];
            return true;
        }
    }

    private sealed class UnexpectedPasswordHashService : IPasswordHashService
    {
        public string Hash(string password) => throw new InvalidOperationException();

        public bool Verify(string passwordHash, string password) =>
            throw new InvalidOperationException();
    }

    private sealed class UnexpectedPasswordResetStore : IPasswordResetStore
    {
        public Task<PasswordResetIssueStoreResult> TryIssueAsync(
            PasswordResetToken token,
            string? expectedNormalizedEmail,
            PasswordResetIssueConstraint? issueConstraint,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException();

        public Task<bool> TryInvalidateAsync(
            Guid tokenId,
            DateTimeOffset invalidatedAt,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException();

        public Task<PasswordResetEmailCandidate?> FindByEmailAsync(
            Guid realmId,
            Guid appEnvironmentId,
            string normalizedEmail,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException();

        public Task<PasswordResetEmailCandidate?> FindByIdentityAsync(
            Guid realmId,
            Guid appEnvironmentId,
            Guid identityId,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException();

        public Task<bool> IsActiveAsync(
            Guid appEnvironmentId,
            byte[] tokenHash,
            DateTimeOffset now,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException();

        public Task<Guid?> TryResetPasswordAsync(
            Guid appEnvironmentId,
            byte[] tokenHash,
            string passwordHash,
            DateTimeOffset resetAt,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException();
    }
}
