using System.Security.Cryptography;
using System.Text;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bullgate.Access.UnitTests;

public sealed class PhonePasswordRecoveryServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid RealmId = Guid.NewGuid();
    private static readonly Guid AppEnvironmentId = Guid.NewGuid();
    private static readonly Guid IdentityId = Guid.NewGuid();
    private const string BypassPhone = "+15555550123";
    private const string BypassCode = "123456";
    private const string ApplicationClientKey = "android-development";

    [Fact]
    public async Task DevelopmentBypass_RequestsAndConfirmsWithoutCallingProvider()
    {
        var store = new BypassStore();
        var sender = new UnexpectedPhoneSender();
        var service = new PhonePasswordRecoveryService(
            store,
            new ConfigurationReader(),
            sender,
            new ResetTokenService(),
            new FixedTimeProvider(Now),
            NullLogger<PhonePasswordRecoveryService>.Instance);

        var requested = await service.RequestAsync(
            RealmId,
            AppEnvironmentId,
            BypassPhone,
            ApplicationClientKey);
        var confirmed = await service.ConfirmAsync(
            RealmId,
            AppEnvironmentId,
            BypassPhone,
            BypassCode);

        Assert.True(requested.Succeeded);
        Assert.True(confirmed.Succeeded);
        Assert.Equal("reset-token", confirmed.Token);
        Assert.Equal(
            SHA256.HashData(Encoding.ASCII.GetBytes(BypassCode)),
            store.Challenge?.CodeHash);
        Assert.Equal(1, store.ApplicationClientLookups);
        Assert.Equal(0, sender.AvailabilityChecks);
        Assert.Equal(0, sender.SendCalls);
        Assert.Equal(0, sender.ApproveCalls);
        Assert.Equal(0, sender.CancelCalls);
        Assert.Null(store.ProviderReference);
    }

    private sealed class ConfigurationReader : IAppEnvironmentConfigurationReader
    {
        private static readonly AppEnvironmentConfiguration Configuration = new(
            new AppAccessPolicy(
                new IdentifierAccessPolicy(
                    false,
                    false,
                    IdentifierVerificationPolicy.Disabled),
                new IdentifierAccessPolicy(
                    true,
                    false,
                    new IdentifierVerificationPolicy(
                        true,
                        VerificationProviderKey.TwilioVerify)),
                new AuthenticatorAccessPolicy(true, false, false)),
            new AppVerificationPolicy(10, 5, 5, 120, 15, 5),
            new AppRecoveryPolicy(null, 60, 5, 10, 5, 5, 120),
            new AppEnvironmentProviders(
                null,
                new TwilioVerifyProviderConfiguration(
                    "SK11111111111111111111111111111111",
                    "secret",
                    "VA11111111111111111111111111111111",
                    "sms",
                    "pt-BR",
                    null),
                null,
                null),
            new DevelopmentBypassConfiguration(
                true,
                BypassPhone,
                BypassCode),
            [],
            []);

        public Task<AppEnvironmentConfiguration?> FindAsync(
            Guid appEnvironmentId,
            CancellationToken cancellationToken) =>
            Task.FromResult<AppEnvironmentConfiguration?>(
                appEnvironmentId == AppEnvironmentId ? Configuration : null);
    }

    private sealed class BypassStore : IPhonePasswordRecoveryStore
    {
        public PhonePasswordResetChallenge? Challenge { get; private set; }
        public string? ProviderReference { get; private set; }
        public int ApplicationClientLookups { get; private set; }

        public Task<PhonePasswordRecoveryApplicationClient?> FindApplicationClientAsync(
            Guid appEnvironmentId,
            string applicationClientKey,
            CancellationToken cancellationToken)
        {
            ApplicationClientLookups++;
            return Task.FromResult<PhonePasswordRecoveryApplicationClient?>(
                new(Guid.NewGuid(), ApplicationClientKey, "A6U92ovJLGE"));
        }

        public Task<PhonePasswordRecoveryCandidate?> FindCandidateAsync(
            Guid realmId,
            Guid appEnvironmentId,
            string normalizedPhone,
            CancellationToken cancellationToken) =>
            Task.FromResult<PhonePasswordRecoveryCandidate?>(
                new(IdentityId));

        public Task<PhonePasswordRecoveryReservation> TryReserveAsync(
            Guid realmId,
            PhonePasswordResetChallenge challenge,
            DateTimeOffset rateWindowStartsAt,
            int maximumRequests,
            DateTimeOffset reservedAt,
            CancellationToken cancellationToken)
        {
            Challenge = challenge;
            return Task.FromResult(new PhonePasswordRecoveryReservation(
                PhonePasswordRecoveryReservationStatus.Reserved));
        }

        public Task<bool> TryActivateAsync(
            Guid challengeId,
            string? providerReference,
            DateTimeOffset activatedAt,
            CancellationToken cancellationToken)
        {
            ProviderReference = providerReference;
            return Task.FromResult(true);
        }

        public Task<PhonePasswordRecoveryCodeCheck> TryBeginConfirmationAsync(
            Guid realmId,
            Guid appEnvironmentId,
            string normalizedPhone,
            byte[] codeHash,
            DateTimeOffset attemptedAt,
            CancellationToken cancellationToken)
        {
            var challenge = Assert.IsType<PhonePasswordResetChallenge>(Challenge);
            return Task.FromResult(new PhonePasswordRecoveryCodeCheck(
                CryptographicOperations.FixedTimeEquals(challenge.CodeHash, codeHash)
                    ? PhonePasswordRecoveryCodeCheckStatus.Ready
                    : PhonePasswordRecoveryCodeCheckStatus.InvalidCode,
                challenge.Id,
                IdentityId));
        }

        public Task<bool> TryFinalizeAsync(
            Guid challengeId,
            PasswordResetToken resetToken,
            DateTimeOffset providerApprovedAt,
            DateTimeOffset completedAt,
            CancellationToken cancellationToken) =>
            Task.FromResult(true);

        public Task<bool> TryRollbackReservationAsync(
            Guid challengeId,
            Guid? supersededChallengeId,
            DateTimeOffset rolledBackAt,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task FailDeliveryAsync(
            Guid challengeId,
            DateTimeOffset failedAt,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<bool> TryReleaseConfirmationAsync(
            Guid challengeId,
            DateTimeOffset releasedAt,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class UnexpectedPhoneSender : IPhoneVerificationSender
    {
        public int AvailabilityChecks { get; private set; }
        public int SendCalls { get; private set; }
        public int ApproveCalls { get; private set; }
        public int CancelCalls { get; private set; }

        public Task<bool> IsAvailableAsync(
            Guid appEnvironmentId,
            CancellationToken cancellationToken)
        {
            AvailabilityChecks++;
            return Task.FromResult(false);
        }

        public Task<string?> SendAsync(
            Guid appEnvironmentId,
            PhoneVerificationDelivery delivery,
            CancellationToken cancellationToken)
        {
            SendCalls++;
            throw new InvalidOperationException("Bypass must not send.");
        }

        public Task ApproveAsync(
            Guid appEnvironmentId,
            string? providerReference,
            CancellationToken cancellationToken)
        {
            ApproveCalls++;
            throw new InvalidOperationException("Bypass must not approve.");
        }

        public Task CancelAsync(
            Guid appEnvironmentId,
            string? providerReference,
            CancellationToken cancellationToken)
        {
            CancelCalls++;
            throw new InvalidOperationException("Bypass must not cancel.");
        }
    }

    private sealed class ResetTokenService : IPasswordResetTokenService
    {
        public IssuedPasswordResetToken Issue() =>
            new(
                "reset-token",
                new byte[IdentityLimits.PasswordResetTokenHashLength]);

        public bool TryHash(string? token, out byte[] tokenHash)
        {
            tokenHash = [];
            return false;
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
