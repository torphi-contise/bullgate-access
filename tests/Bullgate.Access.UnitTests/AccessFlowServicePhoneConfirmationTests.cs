using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Application.Policies;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bullgate.Access.UnitTests;

public sealed class AccessFlowServicePhoneConfirmationTests
{
    private static readonly JsonSerializerOptions WebJsonOptions =
        new(JsonSerializerDefaults.Web);
    private const string Code = "696056";
    private static readonly DateTimeOffset Now =
        new(2026, 9, 3, 22, 29, 56, TimeSpan.Zero);

    [Fact]
    public async Task ActAsync_ValidLocalPhoneCode_SucceedsWithoutProviderApproval()
    {
        var scope = new AccessFlowScope(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid());
        var flowId = Guid.NewGuid();
        var identityId = Guid.NewGuid();
        var actionId = Guid.NewGuid();
        var requestId = Guid.NewGuid();
        var snapshot = new AccessFlowSnapshot(
            AccessFlowProtocol.Version1,
            flowId,
            2,
            AccessFlowProtocol.ManagePhoneIntent,
            "active",
            Now.AddMinutes(30),
            new AccessFlowStepSnapshot(
                AccessFlowProtocol.VerifyPhoneStep,
                "+5511976695464",
                Now.AddMinutes(10),
                Now),
            [new AccessFlowActionSnapshot(
                actionId,
                AccessFlowProtocol.ConfirmPhoneVerificationAction)]);
        var storedFlow = new StoredAccessFlow(
            flowId,
            identityId,
            null,
            Guid.NewGuid(),
            Guid.NewGuid(),
            AccessFlowStatus.Active,
            AccessFlowProtocol.Version1,
            AccessFlowIntent.ManagePhone,
            snapshot.Revision,
            snapshot.ExpiresAt,
            JsonSerializer.Serialize(
                snapshot,
                WebJsonOptions));
        var challenge = new StoredProofChallenge(
            Guid.NewGuid(),
            ProofChallengeType.PhonePossession,
            "+5511976695464",
            SHA256.HashData(Encoding.UTF8.GetBytes(Code)),
            "VEf1cc4a3c82985fae58d7d8a9f4b15a17",
            0,
            5,
            Now.AddMinutes(10),
            Now);
        var store = new PhoneConfirmationStore(
            storedFlow,
            challenge,
            new PhoneIdentifierOwner(
                Guid.NewGuid(),
                identityId,
                "owner@example.com",
                true));
        var sender = new RejectingProviderApprovalSender();
        var timeProvider = new FixedTimeProvider(Now);
        var configurations = new ConfigurationReader();
        var service = new AccessFlowService(
            store,
            new FlowTokenService(),
            configurations,
            new SessionTokenService(),
            sender,
            new EmailPasswordRecoveryService(
                null!,
                null!,
                configurations,
                null!,
                timeProvider),
            timeProvider,
            NullLogger<AccessFlowService>.Instance);
        var command = new AccessFlowActionCommand(
            requestId,
            snapshot.Revision,
            actionId,
            AccessFlowProtocol.ConfirmPhoneVerificationAction,
            JsonSerializer.SerializeToElement(new { code = Code }));

        var result = await service.ActAsync(
            scope,
            flowId,
            "valid-capability",
            command);

        Assert.True(result.Succeeded);
        Assert.Equal("completed", result.Snapshot?.Status);
        Assert.Equal(0, sender.ApproveCalls);
        Assert.Equal(1, store.ConfirmCalls);
        Assert.Equal(0, store.ReleaseCalls);
    }

    private sealed class PhoneConfirmationStore(
        StoredAccessFlow flow,
        StoredProofChallenge challenge,
        PhoneIdentifierOwner owner) : IAccessFlowStore
    {
        private StoredAccessFlowRequest? committedRequest;

        public int ConfirmCalls { get; private set; }
        public int ReleaseCalls { get; private set; }

        public Task<StoredAccessFlowRequest?> FindRequestAsync(
            Guid integrationClientId,
            Guid requestId,
            CancellationToken cancellationToken) =>
            Task.FromResult(committedRequest);

        public Task<StoredAccessFlow?> FindFlowAsync(
            AccessFlowScope scope,
            Guid flowId,
            CancellationToken cancellationToken) =>
            Task.FromResult<StoredAccessFlow?>(flow);

        public Task<PhoneJourneyState> FindPhoneJourneyAsync(
            Guid flowId,
            DateTimeOffset now,
            CancellationToken cancellationToken) =>
            Task.FromResult(new PhoneJourneyState(challenge, null));

        public Task<PhoneIdentifierOwner?> FindPhoneOwnerAsync(
            Guid realmId,
            string normalizedPhone,
            CancellationToken cancellationToken) =>
            Task.FromResult<PhoneIdentifierOwner?>(owner);

        public Task<Guid?> FindIdentifierOwnerAsync(
            Guid realmId,
            string scheme,
            string normalizedValue,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryBeginPhoneConfirmationAsync(
            BeginPhoneConfirmationFlowCommand command,
            CancellationToken cancellationToken) =>
            Task.FromResult(AccessFlowCommitStatus.ExternalOperationReserved);

        public Task<AccessFlowCommitStatus> TryReleasePhoneConfirmationAsync(
            ReleasePhoneConfirmationFlowCommand command,
            CancellationToken cancellationToken)
        {
            ReleaseCalls++;
            return Task.FromResult(AccessFlowCommitStatus.Committed);
        }

        public Task<AccessFlowCommitStatus> TryConfirmPhoneAsync(
            ConfirmPhoneFlowCommand command,
            CancellationToken cancellationToken)
        {
            ConfirmCalls++;
            var completedFlow = flow with
            {
                Status = AccessFlowStatus.Completed,
                CurrentRevision = command.ExpectedRevision + 1,
                SnapshotJson = command.SnapshotJson,
            };
            var issuedSession = command.ProductSession is null
                ? null
                : new StoredAccessFlowIssuedSession(
                    command.ProductSession.IdentityId,
                    command.ProductSession.Id,
                    command.ProductSession.TokenHash,
                    command.ProductSession.ExpiresAt,
                    command.ProductSession.Purpose);
            committedRequest = new StoredAccessFlowRequest(
                command.PayloadHash,
                AccessFlowRequestStatus.Committed,
                completedFlow,
                command.SnapshotJson,
                issuedSession);
            return Task.FromResult(AccessFlowCommitStatus.Committed);
        }

        public Task<ContinueRegistrationCandidate?> FindContinueRegistrationCandidateAsync(
            AccessFlowScope scope,
            byte[] sessionTokenHash,
            DateTimeOffset now,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ManagePhoneCandidate?> FindManagePhoneCandidateAsync(
            AccessFlowScope scope,
            byte[] sessionTokenHash,
            DateTimeOffset now,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ApplicationClientVerificationMetadata?> FindApplicationClientAsync(
            Guid appEnvironmentId,
            string applicationClientKey,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ApplicationClientVerificationMetadata?> FindApplicationClientAsync(
            Guid appEnvironmentId,
            Guid applicationClientId,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<int> CountRecentChallengesAsync(
            Guid identityId,
            ProofChallengeType type,
            DateTimeOffset since,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<StoredAccessFlow?> FindActiveFlowBySourceAsync(
            Guid sourceSessionId,
            AccessFlowIntent intent,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCreateResult> TryCreateAsync(
            AccessFlow flow,
            AccessFlowRevision revision,
            AccessFlowRequest request,
            ExpireActiveAccessFlowCommand? expiredFlow,
            DateTimeOffset startedAt,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryCompleteRegistrationAsync(
            CompleteRegistrationFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryCompletePhoneManagementAsync(
            CompletePhoneManagementFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryAdvanceAsync(
            AdvanceAccessFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryAdvanceRegistrationWithIdentifierAsync(
            AdvanceRegistrationWithIdentifierFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryCreateProofChallengeAsync(
            CreateProofChallengeFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryFinalizeProofChallengeDeliveryAsync(
            FinalizeProofChallengeDeliveryFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryFailProofChallengeDeliveryAsync(
            FailProofChallengeDeliveryFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryRecordFailedProofAttemptAsync(
            RecordFailedProofAttemptFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryRecordPhoneConflictEmailFailureAsync(
            RecordPhoneConflictEmailFailureFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryTransferPhoneAsync(
            TransferPhoneFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryChangePhoneAsync(
            ChangePhoneFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryReservePreviousIdentityRecoveryAsync(
            ReservePreviousIdentityRecoveryFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryFinalizePreviousIdentityRecoveryAsync(
            RecoverPreviousIdentityFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryFailPreviousIdentityRecoveryAsync(
            FailPreviousIdentityRecoveryFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<AccessFlowCommitStatus> TryExpireAsync(
            ExpireAccessFlowCommand command,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class RejectingProviderApprovalSender : IPhoneVerificationSender
    {
        public int ApproveCalls { get; private set; }

        public Task<bool> IsAvailableAsync(
            Guid appEnvironmentId,
            CancellationToken cancellationToken) =>
            Task.FromResult(true);

        public Task<string?> SendAsync(
            Guid appEnvironmentId,
            PhoneVerificationDelivery delivery,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task ApproveAsync(
            Guid appEnvironmentId,
            string? providerReference,
            CancellationToken cancellationToken)
        {
            ApproveCalls++;
            throw new HttpRequestException(
                "Twilio Verify rejected the request (20404).");
        }

        public Task CancelAsync(
            Guid appEnvironmentId,
            string? providerReference,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FlowTokenService : IAccessFlowTokenService
    {
        private static readonly byte[] SessionTokenHash =
            Enumerable.Repeat((byte)7, IdentityLimits.SessionTokenHashLength).ToArray();

        public string IssueCapability(
            Guid flowId,
            Guid integrationClientId,
            Guid appEnvironmentId) =>
            "valid-capability";

        public bool IsValidCapability(
            string? capability,
            Guid flowId,
            Guid integrationClientId,
            Guid appEnvironmentId) =>
            capability == "valid-capability";

        public IssuedAccessFlowSessionToken IssueSession(
            Guid flowId,
            Guid requestId,
            Guid identityId,
            Guid appEnvironmentId) =>
            new("session-token", SessionTokenHash);
    }

    private sealed class ConfigurationReader : IAppEnvironmentConfigurationReader
    {
        private static readonly AppAccessPolicy Policy = new(
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
            new AuthenticatorAccessPolicy(false, false, false));

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

    private sealed class SessionTokenService : ISessionTokenService
    {
        public IssuedSessionToken Issue() => throw new NotSupportedException();

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
