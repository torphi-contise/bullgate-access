using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.Extensions.Logging;

namespace Bullgate.Access.Application.Flows;

/// <summary>
/// Orchestrates the versioned AccessFlow state machine, exact request replay, proof
/// challenges, external delivery compensation, and terminal session issuance.
/// </summary>
public sealed class AccessFlowService
{
    private static readonly TimeSpan FlowDuration = TimeSpan.FromMinutes(30);

    // Every traced creation path settles in two or three attempts. The bound only
    // keeps a request from spinning if the store kept reporting an expired flow.
    private const int MaxCreateAttempts = 5;
    private static readonly TimeSpan ProductSessionDuration = TimeSpan.FromDays(30);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly IAccessFlowStore store;
    private readonly IAccessFlowTokenService flowTokens;
    private readonly IAppEnvironmentConfigurationReader configurations;
    private readonly ISessionTokenService sessionTokens;
    private readonly IPhoneVerificationSender phoneSender;
    private readonly EmailPasswordRecoveryService passwordRecovery;
    private readonly TimeProvider timeProvider;
    private readonly ILogger<AccessFlowService> logger;

    public AccessFlowService(
        IAccessFlowStore store,
        IAccessFlowTokenService flowTokens,
        IAppEnvironmentConfigurationReader configurations,
        ISessionTokenService sessionTokens,
        IPhoneVerificationSender phoneSender,
        EmailPasswordRecoveryService passwordRecovery,
        TimeProvider timeProvider,
        ILogger<AccessFlowService> logger)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(flowTokens);
        ArgumentNullException.ThrowIfNull(configurations);
        ArgumentNullException.ThrowIfNull(sessionTokens);
        ArgumentNullException.ThrowIfNull(phoneSender);
        ArgumentNullException.ThrowIfNull(passwordRecovery);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);
        this.store = store;
        this.flowTokens = flowTokens;
        this.configurations = configurations;
        this.sessionTokens = sessionTokens;
        this.phoneSender = phoneSender;
        this.passwordRecovery = passwordRecovery;
        this.timeProvider = timeProvider;
        this.logger = logger;
    }

    /// <summary>
    /// Starts or resumes a flow for a validated registration or product session and
    /// returns the server-owned initial or current snapshot.
    /// </summary>
    /// <remarks>
    /// Exact request replay is resolved before current protocol negotiation. Creation
    /// eligibility is revalidated transactionally by the store after preliminary reads.
    /// </remarks>
    public async Task<AccessFlowResult> StartAsync(
        AccessFlowScope scope,
        AccessFlowStartCommand command,
        CancellationToken cancellationToken = default)
    {
        ValidateScope(scope);
        ArgumentNullException.ThrowIfNull(command);
        if (command.RequestId == Guid.Empty)
        {
            return AccessFlowResult.Failure(AccessFlowError.InvalidRequest);
        }

        var payloadHash = HashPayload(new StartPayload(
            command.ProtocolVersions,
            command.Intent,
            command.ApplicationClientKey,
            command.SessionToken));
        // Replay is checked before current protocol validation because an accepted request
        // is a durable fact and must retain its original result across compatible retries.
        var existing = await store.FindRequestAsync(
            scope.IntegrationClientId,
            command.RequestId,
            cancellationToken);
        if (existing is not null)
        {
            return Replay(existing, payloadHash, scope, command.RequestId);
        }

        if (command.ProtocolVersions is null
            || !command.ProtocolVersions.Contains(AccessFlowProtocol.Version1))
        {
            return AccessFlowResult.Failure(
                AccessFlowError.ProtocolVersionUnsupported);
        }
        var intent = command.Intent switch
        {
            AccessFlowProtocol.ContinueRegistrationIntent =>
                AccessFlowIntent.ContinueRegistration,
            AccessFlowProtocol.ManagePhoneIntent => AccessFlowIntent.ManagePhone,
            _ => (AccessFlowIntent?)null,
        };
        if (intent is null)
        {
            return AccessFlowResult.Failure(AccessFlowError.IntentUnsupported);
        }
        if (!TryValidateApplicationClientKey(
                command.ApplicationClientKey,
                out var applicationClientKey))
        {
            return AccessFlowResult.Failure(AccessFlowError.ApplicationClientInvalid);
        }
        if (!sessionTokens.TryHash(command.SessionToken, out var sessionTokenHash))
        {
            return AccessFlowResult.Failure(AccessFlowError.SessionInactive);
        }

        var now = timeProvider.GetUtcNow();
        var configuration = await RequireConfigurationAsync(
            scope.AppEnvironmentId,
            cancellationToken);
        var policy = configuration.AccessPolicy;
        if (!policy.Phone.Enabled)
        {
            return AccessFlowResult.Failure(AccessFlowError.IntentUnsupported);
        }
        var applicationClient = await store.FindApplicationClientAsync(
            scope.AppEnvironmentId,
            applicationClientKey,
            cancellationToken);
        if (applicationClient is null)
        {
            return AccessFlowResult.Failure(AccessFlowError.ApplicationClientInvalid);
        }

        Guid identityId;
        Guid sourceSessionId;
        Guid? registrationContextId;
        if (intent == AccessFlowIntent.ContinueRegistration)
        {
            // Candidate reads select the likely authority and shape the new flow. They
            // are not the commit guard: TryCreateAsync locks and revalidates the identity,
            // source session, and registration context before accepting creation.
            var candidate = await store.FindContinueRegistrationCandidateAsync(
                scope,
                sessionTokenHash,
                now,
                cancellationToken);
            if (candidate is null)
            {
                return AccessFlowResult.Failure(AccessFlowError.RegistrationNotPending);
            }
            identityId = candidate.IdentityId;
            sourceSessionId = candidate.SessionId;
            registrationContextId = candidate.RegistrationContextId;
        }
        else
        {
            var candidate = await store.FindManagePhoneCandidateAsync(
                scope,
                sessionTokenHash,
                now,
                cancellationToken);
            if (candidate is null)
            {
                return AccessFlowResult.Failure(AccessFlowError.SessionInactive);
            }
            identityId = candidate.IdentityId;
            sourceSessionId = candidate.SessionId;
            registrationContextId = null;
        }

        var flowId = Guid.CreateVersion7(now);
        var expiresAt = now.Add(FlowDuration);
        var snapshot = CreateCollectPhoneSnapshot(
            flowId,
            revision: 1,
            expiresAt,
            intent.Value,
            policy.Phone,
            now);
        var flow = new AccessFlow(
            flowId,
            scope.RealmId,
            scope.AppEnvironmentId,
            scope.IntegrationClientId,
            applicationClient.ApplicationClientId,
            identityId,
            registrationContextId,
            sourceSessionId,
            AccessFlowProtocol.Version1,
            intent.Value,
            now,
            expiresAt);
        var request = new AccessFlowRequest(
            scope.IntegrationClientId,
            command.RequestId,
            flowId,
            AccessFlowRequestKind.Start,
            payloadHash,
            1,
            now);

        var initialRevision = new AccessFlowRevision(
            flowId,
            1,
            SerializeSnapshot(snapshot),
            now);
        var active = await store.FindActiveFlowBySourceAsync(
            sourceSessionId,
            intent.Value,
            cancellationToken);
        // This read prepares an exact expiration proposal only. The store and its
        // partial unique index arbitrate whether the observed flow still owns the slot.
        ExpireActiveAccessFlowCommand? expiration = active is not null
            && active.ExpiresAt <= now
            ? CreateExpirationCommand(active, now)
            : null;

        // Creation may discover and expire one stale active flow. Retry is bounded because
        // an unsettled store response indicates contention or a persistence defect.
        for (var attempt = 1; ; attempt++)
        {
            var create = await store.TryCreateAsync(
                flow,
                initialRevision,
                request,
                expiration,
                now,
                cancellationToken);
            switch (create.Status)
            {
                case AccessFlowCreateStatus.Created:
                    return Success(snapshot, scope);
                case AccessFlowCreateStatus.Resumed:
                    // Resume returns the existing revision verbatim. Rebuilding from
                    // current policy here would silently change an in-progress contract.
                    return Success(
                        DeserializeSnapshot(create.Flow!.SnapshotJson),
                        scope);
                case AccessFlowCreateStatus.RequestAlreadyExists:
                    return await ReplayRequestAsync(
                        scope,
                        command.RequestId,
                        payloadHash,
                        cancellationToken);
                case AccessFlowCreateStatus.ExistingFlowExpired:
                    if (attempt >= MaxCreateAttempts)
                    {
                        logger.LogError(
                            "Flow creation for source session {SourceSessionId} ({Intent}) did not settle after {Attempts} attempts.",
                            sourceSessionId,
                            intent.Value,
                            attempt);
                        return AccessFlowResult.Failure(
                            AccessFlowError.FlowCreationUnavailable);
                    }
                    active = create.Flow
                        ?? await store.FindActiveFlowBySourceAsync(
                            sourceSessionId,
                            intent.Value,
                            cancellationToken);
                    expiration = active is not null && active.ExpiresAt <= now
                        ? CreateExpirationCommand(active, now)
                        : null;
                    continue;
                case AccessFlowCreateStatus.RegistrationNotPending:
                    return AccessFlowResult.Failure(
                        AccessFlowError.RegistrationNotPending);
                case AccessFlowCreateStatus.SourceSessionInactive:
                    return AccessFlowResult.Failure(AccessFlowError.SessionInactive);
                case AccessFlowCreateStatus.ApplicationClientInvalid:
                    return AccessFlowResult.Failure(
                        AccessFlowError.ApplicationClientInvalid);
                case AccessFlowCreateStatus.IntegrationClientConflict:
                    return AccessFlowResult.Failure(
                        AccessFlowError.IntegrationClientConflict);
                default:
                    throw new ArgumentOutOfRangeException(
                        nameof(create.Status),
                        create.Status,
                        null);
            }
        }
    }

    /// <summary>
    /// Executes one action advertised by the current flow revision after validating
    /// capability, exact request replay, scope, and optimistic revision.
    /// </summary>
    public async Task<AccessFlowResult> ActAsync(
        AccessFlowScope scope,
        Guid flowId,
        string? capability,
        AccessFlowActionCommand command,
        CancellationToken cancellationToken = default)
    {
        ValidateScope(scope);
        ArgumentNullException.ThrowIfNull(command);
        if (flowId == Guid.Empty
            || command.RequestId == Guid.Empty
            || command.ActionId == Guid.Empty
            || command.ExpectedRevision <= 0
            || string.IsNullOrWhiteSpace(command.ActionType))
        {
            return AccessFlowResult.Failure(AccessFlowError.InvalidRequest);
        }
        if (!flowTokens.IsValidCapability(
                capability,
                flowId,
                scope.IntegrationClientId,
                scope.AppEnvironmentId))
        {
            return AccessFlowResult.Failure(AccessFlowError.FlowNotFound);
        }

        var payloadHash = HashPayload(new ActionPayload(
            flowId,
            command.ExpectedRevision,
            command.ActionId,
            command.ActionType,
            command.Input));
        var existing = await store.FindRequestAsync(
            scope.IntegrationClientId,
            command.RequestId,
            cancellationToken);
        if (existing is not null)
        {
            return Replay(existing, payloadHash, scope, command.RequestId);
        }

        var stored = await store.FindFlowAsync(scope, flowId, cancellationToken);
        if (stored is null)
        {
            return AccessFlowResult.Failure(AccessFlowError.FlowNotFound);
        }

        var now = timeProvider.GetUtcNow();
        if (stored.Status == AccessFlowStatus.Active && stored.ExpiresAt <= now)
        {
            return await ExpireAsync(scope, stored, now, cancellationToken);
        }
        if (stored.Status != AccessFlowStatus.Active)
        {
            return AccessFlowResult.Failure(AccessFlowError.ActionNotAvailable);
        }
        if (stored.CurrentRevision != command.ExpectedRevision)
        {
            return AccessFlowResult.Failure(AccessFlowError.RevisionConflict);
        }

        var currentSnapshot = DeserializeSnapshot(stored.SnapshotJson);
        var offeredAction = currentSnapshot.Actions.SingleOrDefault(action =>
            action.Id == command.ActionId
            && string.Equals(action.Type, command.ActionType, StringComparison.Ordinal));
        // The current persisted snapshot is the action allowlist. In particular, a
        // client cannot manufacture skipRegistration when policy omitted it, reuse an
        // action id from an older revision, or substitute a different action type.
        if (offeredAction is null)
        {
            return AccessFlowResult.Failure(AccessFlowError.ActionNotAvailable);
        }

        var configuration = await RequireConfigurationAsync(
            scope.AppEnvironmentId,
            cancellationToken);
        var policy = configuration.AccessPolicy;

        return offeredAction.Type switch
        {
            AccessFlowProtocol.SkipRegistrationAction =>
                await CompleteRegistrationAsync(
                    scope,
                    stored,
                    command,
                    payloadHash,
                    "skipped",
                    null,
                    now,
                    cancellationToken),
            AccessFlowProtocol.RequestPhoneVerificationAction =>
                await RequestPhoneAsync(
                    scope,
                    stored,
                    command,
                    payloadHash,
                    requestedPhone: ReadInputString(command.Input, "phone"),
                    policy.Phone,
                    configuration.VerificationPolicy,
                    configuration.DevelopmentBypass,
                    now,
                    cancellationToken),
            AccessFlowProtocol.SubmitPhoneAction =>
                await SubmitPhoneAsync(
                    scope,
                    stored,
                    command,
                    payloadHash,
                    requestedPhone: ReadInputString(command.Input, "phone"),
                    policy.Phone,
                    now,
                    cancellationToken),
            AccessFlowProtocol.ResendPhoneVerificationAction =>
                await ResendPhoneAsync(
                    scope,
                    stored,
                    command,
                    payloadHash,
                    policy.Phone,
                    configuration.VerificationPolicy,
                    configuration.DevelopmentBypass,
                    now,
                    cancellationToken),
            AccessFlowProtocol.ConfirmPhoneVerificationAction =>
                await ConfirmPhoneAsync(
                    scope,
                    stored,
                    command,
                    payloadHash,
                    policy.Phone,
                    configuration.VerificationPolicy,
                    now,
                    cancellationToken),
            AccessFlowProtocol.TransferPhoneAction =>
                await TransferPhoneAsync(
                    scope,
                    stored,
                    command,
                    payloadHash,
                    policy.Phone,
                    configuration.VerificationPolicy,
                    now,
                    cancellationToken),
            AccessFlowProtocol.RecoverPreviousIdentityAction =>
                await RecoverPreviousIdentityAsync(
                    scope,
                    stored,
                    command,
                    payloadHash,
                    now,
                    cancellationToken),
            AccessFlowProtocol.ChangePhoneAction =>
                await ChangePhoneAsync(
                    scope,
                    stored,
                    command,
                    payloadHash,
                    policy.Phone,
                    now,
                    cancellationToken),
            _ => AccessFlowResult.Failure(AccessFlowError.ActionNotAvailable),
        };
    }

    /// <summary>
    /// Returns the current scoped flow snapshot and commits expiration first when an
    /// otherwise active flow has crossed its expiry time.
    /// </summary>
    public async Task<AccessFlowResult> GetAsync(
        AccessFlowScope scope,
        Guid flowId,
        string? capability,
        CancellationToken cancellationToken = default)
    {
        ValidateScope(scope);
        if (flowId == Guid.Empty
            || !flowTokens.IsValidCapability(
                capability,
                flowId,
                scope.IntegrationClientId,
                scope.AppEnvironmentId))
        {
            return AccessFlowResult.Failure(AccessFlowError.FlowNotFound);
        }

        var stored = await store.FindFlowAsync(scope, flowId, cancellationToken);
        if (stored is null)
        {
            return AccessFlowResult.Failure(AccessFlowError.FlowNotFound);
        }

        var now = timeProvider.GetUtcNow();
        if (stored.Status == AccessFlowStatus.Active && stored.ExpiresAt <= now)
        {
            return await ExpireAsync(scope, stored, now, cancellationToken);
        }

        return Success(DeserializeSnapshot(stored.SnapshotJson), scope);
    }

    private async Task<AccessFlowResult> ResendPhoneAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        IdentifierAccessPolicy phonePolicy,
        AppVerificationPolicy verificationPolicy,
        DevelopmentBypassConfiguration developmentBypass,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var journey = await store.FindPhoneJourneyAsync(
            stored.FlowId,
            now,
            cancellationToken);
        if (journey.ActivePhoneChallenge is null)
        {
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                CreateCollectPhoneSnapshot(
                    stored,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot(
                        "phone-verification-no-active-code",
                        "code")),
                now,
                cancellationToken);
        }

        return await RequestPhoneAsync(
            scope,
            stored,
            command,
            payloadHash,
            journey.ActivePhoneChallenge.DestinationValue,
            phonePolicy,
            verificationPolicy,
            developmentBypass,
            now,
            cancellationToken);
    }

    private async Task<AccessFlowResult> SubmitPhoneAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        string? requestedPhone,
        IdentifierAccessPolicy phonePolicy,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!phonePolicy.Enabled || phonePolicy.Verification.Enabled)
        {
            return AccessFlowResult.Failure(AccessFlowError.ActionNotAvailable);
        }

        if (!PhoneValue.TryNormalize(requestedPhone, out var normalizedPhone))
        {
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                CreateCollectPhoneSnapshot(
                    stored,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot("invalid-phone", "phone")),
                now,
                cancellationToken);
        }

        var owner = await store.FindPhoneOwnerAsync(
            scope.RealmId,
            normalizedPhone,
            cancellationToken);
        if (owner is not null && owner.IdentityId != stored.IdentityId)
        {
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                CreateCollectPhoneSnapshot(
                    stored,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot("phone-already-in-use", "phone")),
                now,
                cancellationToken);
        }

        var identifier = owner is null
            ? new IdentityIdentifier(
                Guid.CreateVersion7(now),
                stored.IdentityId,
                scope.RealmId,
                IdentifierScheme.Phone,
                normalizedPhone,
                now)
            : null;
        return stored.Intent == AccessFlowIntent.ManagePhone
            ? await CompletePhoneManagementAsync(
                scope,
                stored,
                command,
                payloadHash,
                normalizedPhone,
                "phoneChanged",
                now,
                cancellationToken)
            : await CompleteRegistrationAsync(
                scope,
                stored,
                command,
                payloadHash,
                "phoneCollected",
                identifier,
                now,
                cancellationToken);
    }

    private async Task<AccessFlowResult> RequestPhoneAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        string? requestedPhone,
        IdentifierAccessPolicy phonePolicy,
        AppVerificationPolicy verificationPolicy,
        DevelopmentBypassConfiguration developmentBypass,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!PhoneValue.TryNormalize(requestedPhone, out var normalizedPhone))
        {
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                CreateCollectPhoneSnapshot(
                    stored,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot("invalid-phone", "phone")),
                now,
                cancellationToken);
        }

        var journey = await store.FindPhoneJourneyAsync(
            stored.FlowId,
            now,
            cancellationToken);
        if (journey.ActivePhoneChallenge is { ResendAvailableAt: var retryAt }
            && retryAt > now)
        {
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                CreateVerifyPhoneSnapshot(
                    stored,
                    journey.ActivePhoneChallenge,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot(
                        "phone-verification-resend-too-soon",
                        RetryAt: retryAt)),
                now,
                cancellationToken);
        }

        var rateWindowStartsAt = now.AddHours(-1);
        var recent = await store.CountRecentChallengesAsync(
            stored.IdentityId,
            ProofChallengeType.PhonePossession,
            rateWindowStartsAt,
            cancellationToken);
        if (recent >= verificationPolicy.MaxRequestsPerHourPerIdentity)
        {
            var rateLimitedSnapshot = journey.ActivePhoneChallenge is null
                ? CreateCollectPhoneSnapshot(
                    stored,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot(
                        "phone-verification-rate-limited"))
                : CreateVerifyPhoneSnapshot(
                    stored,
                    journey.ActivePhoneChallenge,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot(
                        "phone-verification-rate-limited"));
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                rateLimitedSnapshot,
                now,
                cancellationToken);
        }

        var bypass = IsDevelopmentBypass(developmentBypass, normalizedPhone);
        var code = bypass ? developmentBypass.Code! : GenerateCode();
        ApplicationClientVerificationMetadata? applicationClient = null;
        if (!bypass)
        {
            applicationClient = await store.FindApplicationClientAsync(
                scope.AppEnvironmentId,
                stored.ApplicationClientId,
                cancellationToken);
            if (applicationClient is null)
            {
                return AccessFlowResult.Failure(
                    AccessFlowError.ApplicationClientInvalid);
            }

        }

        var challengeExpiresAt = Min(
            now.AddMinutes(verificationPolicy.CodeLifetimeMinutes),
            stored.ExpiresAt);
        var resendAvailableAt = now.AddSeconds(
            verificationPolicy.ResendCooldownSeconds);
        var challenge = ProofChallenge.ReserveDelivery(
            Guid.CreateVersion7(now),
            stored.FlowId,
            stored.IdentityId,
            ProofChallengeType.PhonePossession,
            ProofChallengeChannel.Sms,
            IdentifierScheme.Phone,
            normalizedPhone,
            HashSecret(code),
            verificationPolicy.MaxAttempts,
            now,
            challengeExpiresAt,
            resendAvailableAt);
        var reserveStatus = await store.TryCreateProofChallengeAsync(
            new CreateProofChallengeFlowCommand(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                command.ExpectedRevision,
                challenge,
                rateWindowStartsAt,
                verificationPolicy.MaxRequestsPerHourPerIdentity,
                now),
            cancellationToken);

        if (reserveStatus == AccessFlowCommitStatus.ChallengeRateLimited
            || reserveStatus == AccessFlowCommitStatus.ChallengeResendTooSoon)
        {
            var feedback = reserveStatus == AccessFlowCommitStatus.ChallengeRateLimited
                ? new AccessFlowFeedbackSnapshot("phone-verification-rate-limited")
                : new AccessFlowFeedbackSnapshot(
                    "phone-verification-resend-too-soon",
                    RetryAt: journey.ActivePhoneChallenge?.ResendAvailableAt);
            var retrySnapshot = journey.ActivePhoneChallenge is null
                ? CreateCollectPhoneSnapshot(stored, phonePolicy, now, feedback)
                : CreateVerifyPhoneSnapshot(
                    stored,
                    journey.ActivePhoneChallenge,
                    phonePolicy,
                    now,
                    feedback);
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                retrySnapshot,
                now,
                cancellationToken);
        }

        if (reserveStatus != AccessFlowCommitStatus.ExternalOperationReserved)
        {
            return await ReplayCommitAsync(
                reserveStatus,
                scope,
                command.RequestId,
                payloadHash,
                cancellationToken);
        }

        string? providerReference = null;
        if (!bypass)
        {
            try
            {
                providerReference = await phoneSender.SendAsync(
                    scope.AppEnvironmentId,
                    new PhoneVerificationDelivery(
                        normalizedPhone,
                        code,
                        applicationClient!.SmsRetrieverAppHash),
                    cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await TryFailProofChallengeDeliveryAsync(
                    scope,
                    stored.FlowId,
                    command.RequestId,
                    payloadHash,
                    challenge.Id);
                throw;
            }
            catch (Exception exception)
            {
                await TryFailProofChallengeDeliveryAsync(
                    scope,
                    stored.FlowId,
                    command.RequestId,
                    payloadHash,
                    challenge.Id);
                logger.LogWarning(
                    exception,
                    "Phone verification delivery failed for challenge {ChallengeId}.",
                    challenge.Id);
                return AccessFlowResult.Failure(AccessFlowError.DeliveryUnavailable);
            }
        }

        var finalizedAt = timeProvider.GetUtcNow();
        var snapshot = CreateVerifyPhoneSnapshot(
            stored,
            new StoredProofChallenge(
                challenge.Id,
                challenge.Type,
                challenge.DestinationValue,
                challenge.SecretHash,
                providerReference,
                challenge.Attempts,
                challenge.MaxAttempts,
                challenge.ExpiresAt,
                challenge.ResendAvailableAt),
            phonePolicy,
            finalizedAt);
        AccessFlowCommitStatus finalizeStatus;
        try
        {
            using var finalization = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            finalizeStatus = await store.TryFinalizeProofChallengeDeliveryAsync(
                new FinalizeProofChallengeDeliveryFlowCommand(
                    scope,
                    stored.FlowId,
                    command.RequestId,
                    payloadHash,
                    command.ExpectedRevision,
                    SerializeSnapshot(snapshot),
                    challenge.Id,
                    providerReference,
                    finalizedAt),
                finalization.Token);
        }
        catch (Exception exception)
        {
            await TryCancelPhoneVerificationAsync(
                scope.AppEnvironmentId,
                providerReference,
                challenge.Id);
            await TryFailProofChallengeDeliveryAsync(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                challenge.Id);
            logger.LogError(
                exception,
                "Phone verification finalization failed for challenge {ChallengeId} after delivery.",
                challenge.Id);
            throw;
        }

        if (finalizeStatus is not (AccessFlowCommitStatus.Committed
            or AccessFlowCommitStatus.RequestAlreadyExists))
        {
            await TryCancelPhoneVerificationAsync(
                scope.AppEnvironmentId,
                providerReference,
                challenge.Id);
            await TryFailProofChallengeDeliveryAsync(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                challenge.Id);
        }

        return await ReplayAfterExternalAsync(
            finalizeStatus,
            scope,
            command.RequestId,
            payloadHash);
    }

    private async Task<AccessFlowResult> ConfirmPhoneAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        IdentifierAccessPolicy phonePolicy,
        AppVerificationPolicy verificationPolicy,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var journey = await store.FindPhoneJourneyAsync(
            stored.FlowId,
            now,
            cancellationToken);
        var challenge = journey.ActivePhoneChallenge;
        if (challenge is null)
        {
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                CreateCollectPhoneSnapshot(
                    stored,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot(
                        "phone-verification-no-active-code",
                        "code")),
                now,
                cancellationToken);
        }

        var code = ReadInputString(command.Input, "code")?.Trim();
        if (string.IsNullOrEmpty(code))
        {
            return await AdvanceWithFeedbackAsync(
                scope,
                stored,
                command.RequestId,
                payloadHash,
                CreateVerifyPhoneSnapshot(
                    stored,
                    challenge,
                    phonePolicy,
                    now,
                    new AccessFlowFeedbackSnapshot("missing-code", "code")),
                now,
                cancellationToken);
        }

        var candidateHash = HashSecret(code);
        var matches = CryptographicOperations.FixedTimeEquals(
            challenge.SecretHash,
            candidateHash);
        CryptographicOperations.ZeroMemory(candidateHash);
        if (!matches)
        {
            var exhausted = challenge.Attempts + 1 >= challenge.MaxAttempts;
            var feedback = new AccessFlowFeedbackSnapshot(
                exhausted
                    ? "phone-verification-too-many-attempts"
                    : "phone-verification-invalid-code",
                "code");
            var failedSnapshot = exhausted
                ? CreateCollectPhoneSnapshot(stored, phonePolicy, now, feedback)
                : CreateVerifyPhoneSnapshot(stored, challenge, phonePolicy, now, feedback);
            var status = await store.TryRecordFailedProofAttemptAsync(
                new RecordFailedProofAttemptFlowCommand(
                    scope,
                    stored.FlowId,
                    command.RequestId,
                    payloadHash,
                    command.ExpectedRevision,
                    SerializeSnapshot(failedSnapshot),
                    challenge.ChallengeId,
                    challenge.Attempts,
                    new ProofAttempt(
                        Guid.CreateVersion7(now),
                        challenge.ChallengeId,
                        ProofAttemptOutcome.Failed,
                        now),
                    now),
                cancellationToken);
            return await ReplayCommitAsync(
                status,
                scope,
                command.RequestId,
                payloadHash,
                cancellationToken);
        }

        var owner = await store.FindPhoneOwnerAsync(
            scope.RealmId,
            challenge.DestinationValue,
            cancellationToken);
        var beginStatus = await store.TryBeginPhoneConfirmationAsync(
            new BeginPhoneConfirmationFlowCommand(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                command.ExpectedRevision,
                challenge.ChallengeId,
                challenge.Attempts,
                challenge.DestinationValue,
                owner,
                now),
            cancellationToken);
        if (beginStatus != AccessFlowCommitStatus.ExternalOperationReserved)
        {
            return await ReplayCommitAsync(
                beginStatus,
                scope,
                command.RequestId,
                payloadHash,
                cancellationToken);
        }

        var confirmedAt = timeProvider.GetUtcNow();
        var conflict = owner is
        {
            IsVerified: true,
            IdentityId: var ownerIdentityId,
        } && ownerIdentityId != stored.IdentityId;
        IdentityIdentifier? phoneIdentifier = null;
        if (owner is null)
        {
            phoneIdentifier = new IdentityIdentifier(
                Guid.CreateVersion7(confirmedAt),
                stored.IdentityId,
                scope.RealmId,
                IdentifierScheme.Phone,
                challenge.DestinationValue,
                confirmedAt,
                confirmedAt,
                "sms");
        }
        var subjectIdentifierId = owner?.IdentifierId
            ?? phoneIdentifier!.Id;
        var proof = new IdentityProof(
            Guid.CreateVersion7(confirmedAt),
            stored.FlowId,
            stored.IdentityId,
            challenge.ChallengeId,
            ProofChallengeType.PhonePossession,
            subjectIdentifierId,
            confirmedAt);
        PhoneRegistrationConflict? phoneConflict = null;
        IdentitySession? productSession = null;
        AccessFlowSnapshot snapshot;
        if (conflict)
        {
            phoneConflict = new PhoneRegistrationConflict(
                stored.FlowId,
                owner!.IdentityId,
                owner.IdentifierId,
                confirmedAt,
                Min(
                    confirmedAt.AddMinutes(
                        verificationPolicy.PhoneConflictLifetimeMinutes),
                    stored.ExpiresAt));
            snapshot = CreatePhoneConflictSnapshot(
                stored,
                phonePolicy,
                confirmedAt,
                MaskEmail(owner.Email));
        }
        else
        {
            var issued = flowTokens.IssueSession(
                stored.FlowId,
                command.RequestId,
                stored.IdentityId,
                scope.AppEnvironmentId);
            productSession = new IdentitySession(
                Guid.CreateVersion7(confirmedAt),
                stored.IdentityId,
                scope.AppEnvironmentId,
                IdentitySessionPurpose.Product,
                issued.TokenHash,
                confirmedAt,
                confirmedAt.Add(ProductSessionDuration));
            snapshot = CreateTerminalSnapshot(
                stored,
                "completed",
                "phoneVerified");
        }

        AccessFlowCommitStatus commitStatus;
        try
        {
            using var finalization = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            commitStatus = await store.TryConfirmPhoneAsync(
                new ConfirmPhoneFlowCommand(
                    scope,
                    stored.FlowId,
                    command.RequestId,
                    payloadHash,
                    command.ExpectedRevision,
                    SerializeSnapshot(snapshot),
                    challenge.ChallengeId,
                    challenge.Attempts,
                    challenge.DestinationValue,
                    owner,
                    phoneIdentifier,
                    new ProofAttempt(
                        Guid.CreateVersion7(confirmedAt),
                        challenge.ChallengeId,
                        ProofAttemptOutcome.Succeeded,
                        confirmedAt),
                    proof,
                    phoneConflict,
                    productSession,
                    confirmedAt),
                finalization.Token);
        }
        catch (Exception exception)
        {
            await TryReleasePhoneConfirmationAsync(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                challenge.ChallengeId);
            logger.LogError(
                exception,
                "Phone verification finalization failed for challenge {ChallengeId} after local proof validation.",
                challenge.ChallengeId);
            throw;
        }

        if (commitStatus is not (AccessFlowCommitStatus.Committed
            or AccessFlowCommitStatus.RequestAlreadyExists))
        {
            await TryReleasePhoneConfirmationAsync(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                challenge.ChallengeId);
        }

        return await ReplayAfterExternalAsync(
            commitStatus,
            scope,
            command.RequestId,
            payloadHash);
    }

    private async Task<AccessFlowResult> CompleteRegistrationAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        string outcome,
        IdentityIdentifier? identifier,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Terminal session authority is deterministic for this flow/request pair. The
        // store persists only its hash, while exact replay can derive the same clear
        // token after verifying the committed request and durable session facts.
        var issuedToken = flowTokens.IssueSession(
            stored.FlowId,
            command.RequestId,
            stored.IdentityId,
            scope.AppEnvironmentId);
        var productSession = new IdentitySession(
            Guid.CreateVersion7(now),
            stored.IdentityId,
            scope.AppEnvironmentId,
            IdentitySessionPurpose.Product,
            issuedToken.TokenHash,
            now,
            now.Add(ProductSessionDuration));
        var snapshot = CreateTerminalSnapshot(stored, "completed", outcome);
        var status = await store.TryCompleteRegistrationAsync(
            new CompleteRegistrationFlowCommand(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                command.ExpectedRevision,
                SerializeSnapshot(snapshot),
                identifier,
                productSession,
                now),
            cancellationToken);
        return await ReplayCommitAsync(
            status,
            scope,
            command.RequestId,
            payloadHash,
            cancellationToken);
    }

    private async Task<AccessFlowResult> CompletePhoneManagementAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        string normalizedPhone,
        string outcome,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Phone management also rotates its source product session. Deterministic
        // issuance lets an exact replay recover the same result without persisting the
        // clear bearer token.
        var issuedToken = flowTokens.IssueSession(
            stored.FlowId,
            command.RequestId,
            stored.IdentityId,
            scope.AppEnvironmentId);
        var productSession = new IdentitySession(
            Guid.CreateVersion7(now),
            stored.IdentityId,
            scope.AppEnvironmentId,
            IdentitySessionPurpose.Product,
            issuedToken.TokenHash,
            now,
            now.Add(ProductSessionDuration));
        var snapshot = CreateTerminalSnapshot(stored, "completed", outcome);
        var status = await store.TryCompletePhoneManagementAsync(
            new CompletePhoneManagementFlowCommand(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                command.ExpectedRevision,
                SerializeSnapshot(snapshot),
                normalizedPhone,
                productSession,
                now),
            cancellationToken);
        return await ReplayCommitAsync(
            status,
            scope,
            command.RequestId,
            payloadHash,
            cancellationToken);
    }

    private async Task<AccessFlowResult> TransferPhoneAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        IdentifierAccessPolicy phonePolicy,
        AppVerificationPolicy verificationPolicy,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var journey = await store.FindPhoneJourneyAsync(
            stored.FlowId,
            now,
            cancellationToken);
        var conflict = journey.PhoneConflict;
        if (conflict is null)
        {
            return AccessFlowResult.Failure(AccessFlowError.ActionNotAvailable);
        }

        var expectedAttempts = conflict.FailedEmailAttempts;
        if (conflict.EmailResolutionExhaustedAt is not null
            || expectedAttempts >= verificationPolicy.PhoneConflictEmailMaxAttempts)
        {
            return AccessFlowResult.Failure(AccessFlowError.ActionNotAvailable);
        }

        var submittedEmail = ReadInputString(command.Input, "previousEmail");
        // This is an exact normalized knowledge check against the previous owner's
        // stored e-mail, not possession proof: no code or link is delivered to it.
        var matches = EmailPasswordAccessService.TryNormalizeEmail(
                submittedEmail,
                out var normalizedEmail)
            && string.Equals(
                normalizedEmail,
                conflict.PreviousEmail,
                StringComparison.Ordinal);
        if (!matches || conflict.PreviousEmailIdentifierId is null)
        {
            // The attempt budget and next masked snapshot are committed together so
            // parallel guesses cannot each consume the same expected attempt number.
            var nextAttempts = checked(expectedAttempts + 1);
            var exhausted = nextAttempts
                >= verificationPolicy.PhoneConflictEmailMaxAttempts;
            var snapshot = CreatePhoneConflictSnapshot(
                stored,
                phonePolicy,
                now,
                MaskEmail(conflict.PreviousEmail),
                allowEmailTransfer: !exhausted,
                new AccessFlowFeedbackSnapshot(
                    exhausted
                        ? "phone-conflict-too-many-attempts"
                        : "phone-conflict-email-mismatch",
                    "previousEmail"));
            var failureStatus = await store.TryRecordPhoneConflictEmailFailureAsync(
                new RecordPhoneConflictEmailFailureFlowCommand(
                    scope,
                    stored.FlowId,
                    command.RequestId,
                    payloadHash,
                    command.ExpectedRevision,
                    SerializeSnapshot(snapshot),
                    expectedAttempts,
                    verificationPolicy.PhoneConflictEmailMaxAttempts,
                    now),
                cancellationToken);
            return await ReplayCommitAsync(
                failureStatus,
                scope,
                command.RequestId,
                payloadHash,
                cancellationToken);
        }

        var issued = flowTokens.IssueSession(
            stored.FlowId,
            command.RequestId,
            stored.IdentityId,
            scope.AppEnvironmentId);
        var productSession = new IdentitySession(
            Guid.CreateVersion7(now),
            stored.IdentityId,
            scope.AppEnvironmentId,
            IdentitySessionPurpose.Product,
            issued.TokenHash,
            now,
            now.Add(ProductSessionDuration));
        var terminal = CreateTerminalSnapshot(
            stored,
            "completed",
            "phoneTransferred",
            conflict.PreviousIdentityId,
            stored.IdentityId);
        var status = await store.TryTransferPhoneAsync(
            new TransferPhoneFlowCommand(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                command.ExpectedRevision,
                SerializeSnapshot(terminal),
                expectedAttempts,
                verificationPolicy.PhoneConflictEmailMaxAttempts,
                conflict.PreviousIdentityId,
                normalizedEmail,
                productSession,
                now),
            cancellationToken);
        return await ReplayCommitAsync(
            status,
            scope,
            command.RequestId,
            payloadHash,
            cancellationToken);
    }

    private async Task<AccessFlowResult> ChangePhoneAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        IdentifierAccessPolicy phonePolicy,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var snapshot = CreateCollectPhoneSnapshot(stored, phonePolicy, now);
        var status = await store.TryChangePhoneAsync(
            new ChangePhoneFlowCommand(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                command.ExpectedRevision,
                SerializeSnapshot(snapshot),
                now),
            cancellationToken);
        return await ReplayCommitAsync(
            status,
            scope,
            command.RequestId,
            payloadHash,
            cancellationToken);
    }

    private async Task<AccessFlowResult> RecoverPreviousIdentityAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        AccessFlowActionCommand command,
        byte[] payloadHash,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var journey = await store.FindPhoneJourneyAsync(
            stored.FlowId,
            now,
            cancellationToken);
        var conflict = journey.PhoneConflict;
        if (conflict is null)
        {
            return AccessFlowResult.Failure(AccessFlowError.ActionNotAvailable);
        }

        // The previous-e-mail attempt budget protects only transfer's knowledge check.
        // Recovery accepts no address from the caller and sends exclusively to the
        // previous identity's stored canonical e-mail. Exhausting guesses therefore
        // must not remove the stronger mailbox-possession recovery path.

        // Database state and e-mail delivery cannot share one transaction. Reserve the
        // request first so only one caller owns the external effect and replay can see
        // whether that effect is pending, committed, or failed.
        var reserveStatus = await store.TryReservePreviousIdentityRecoveryAsync(
            new ReservePreviousIdentityRecoveryFlowCommand(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash,
                command.ExpectedRevision,
                conflict.PreviousIdentityId,
                conflict.ConflictingIdentifierId,
                now),
            cancellationToken);
        if (reserveStatus != AccessFlowCommitStatus.ExternalOperationReserved)
        {
            return await ReplayCommitAsync(
                reserveStatus,
                scope,
                command.RequestId,
                payloadHash,
                cancellationToken);
        }

        EmailPasswordRecoveryResult recovery;
        try
        {
            // Trusted orchestration selects the stored previous identity by id. The
            // client cannot redirect this recovery message to a submitted address.
            recovery = await passwordRecovery.RequestForIdentityAsync(
                scope.RealmId,
                scope.AppEnvironmentId,
                conflict.PreviousIdentityId,
                cancellationToken);
        }
        catch (Exception)
        {
            await TryFailPreviousIdentityRecoveryAsync(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash);
            throw;
        }
        if (recovery.Outcome != EmailPasswordRecoveryOutcome.Sent)
        {
            // Issuance can succeed even when the provider rejects delivery. If the
            // recovery service returned a token id, consume that exact token before
            // exposing the failed outcome.
            await TryInvalidateRecoveryTokenAsync(recovery.TokenId);
            await TryFailPreviousIdentityRecoveryAsync(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash);
            return AccessFlowResult.Failure(recovery.Outcome switch
            {
                EmailPasswordRecoveryOutcome.RateLimited =>
                    AccessFlowError.PasswordRecoveryRateLimited,
                EmailPasswordRecoveryOutcome.DeliveryUnavailable
                    or EmailPasswordRecoveryOutcome.EnvironmentNotConfigured =>
                    AccessFlowError.PasswordRecoveryUnavailable,
                _ => AccessFlowError.ActionNotAvailable,
            });
        }

        var terminal = CreateTerminalSnapshot(
            stored,
            "registrationAbandoned",
            "previousIdentityRecoveryRequested",
            conflict.PreviousIdentityId,
            stored.IdentityId);
        AccessFlowCommitStatus finalizeStatus;
        try
        {
            // Once e-mail delivery is accepted, finish with a bounded token independent
            // of client cancellation. A disconnected caller must not strand the action
            // merely because its HTTP request ended.
            using var finalization = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            finalizeStatus = await store.TryFinalizePreviousIdentityRecoveryAsync(
                new RecoverPreviousIdentityFlowCommand(
                    scope,
                    stored.FlowId,
                    command.RequestId,
                    payloadHash,
                    command.ExpectedRevision,
                    SerializeSnapshot(terminal),
                    conflict.PreviousIdentityId,
                    conflict.ConflictingIdentifierId,
                    now),
                finalization.Token);
        }
        catch (Exception exception)
        {
            await TryInvalidateRecoveryTokenAsync(recovery.TokenId);
            await TryFailPreviousIdentityRecoveryAsync(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash);
            logger.LogError(
                exception,
                "Previous identity recovery finalization failed for flow {FlowId} after the e-mail was sent.",
                stored.FlowId);
            throw;
        }

        if (finalizeStatus is not (AccessFlowCommitStatus.Committed
            or AccessFlowCommitStatus.RequestAlreadyExists))
        {
            // The e-mail is out but the flow did not conclude. Kill the link so the
            // mailbox and the app tell the same story; the client retries with a
            // new requestId and receives a fresh e-mail.
            await TryInvalidateRecoveryTokenAsync(recovery.TokenId);
            await TryFailPreviousIdentityRecoveryAsync(
                scope,
                stored.FlowId,
                command.RequestId,
                payloadHash);
        }

        return await ReplayAfterExternalAsync(
            finalizeStatus,
            scope,
            command.RequestId,
            payloadHash);
    }

    private async Task TryFailPreviousIdentityRecoveryAsync(
        AccessFlowScope scope,
        Guid flowId,
        Guid requestId,
        byte[] payloadHash)
    {
        try
        {
            // Compensation is deliberately bounded and best-effort: it improves replay
            // state after an external failure but cannot roll back the provider call.
            using var compensation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await store.TryFailPreviousIdentityRecoveryAsync(
                new FailPreviousIdentityRecoveryFlowCommand(
                    scope,
                    flowId,
                    requestId,
                    payloadHash),
                compensation.Token);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Could not close the failed previous identity recovery for flow {FlowId}.",
                flowId);
        }
    }

    private async Task TryInvalidateRecoveryTokenAsync(Guid? tokenId)
    {
        if (tokenId is null)
        {
            return;
        }

        try
        {
            // The token id is the narrow compensation handle. Clear reset authority
            // never returns to this coordinator and therefore cannot leak from it.
            using var compensation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await passwordRecovery.InvalidateAsync(tokenId.Value, compensation.Token);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Could not invalidate password reset token {TokenId} after a failed recovery.",
                tokenId);
        }
    }

    private async Task TryFailProofChallengeDeliveryAsync(
        AccessFlowScope scope,
        Guid flowId,
        Guid requestId,
        byte[] payloadHash,
        Guid challengeId)
    {
        try
        {
            using var compensation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await store.TryFailProofChallengeDeliveryAsync(
                new FailProofChallengeDeliveryFlowCommand(
                    scope,
                    flowId,
                    requestId,
                    payloadHash,
                    challengeId,
                    timeProvider.GetUtcNow()),
                compensation.Token);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Could not close failed phone verification delivery {ChallengeId}.",
                challengeId);
        }
    }

    private async Task TryReleasePhoneConfirmationAsync(
        AccessFlowScope scope,
        Guid flowId,
        Guid requestId,
        byte[] payloadHash,
        Guid challengeId)
    {
        try
        {
            using var compensation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await store.TryReleasePhoneConfirmationAsync(
                new ReleasePhoneConfirmationFlowCommand(
                    scope,
                    flowId,
                    requestId,
                    payloadHash,
                    challengeId,
                    timeProvider.GetUtcNow()),
                compensation.Token);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Could not release phone verification confirmation {ChallengeId}.",
                challengeId);
        }
    }

    private async Task TryCancelPhoneVerificationAsync(
        Guid appEnvironmentId,
        string? providerReference,
        Guid challengeId)
    {
        if (providerReference is null)
        {
            return;
        }

        try
        {
            using var compensation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await phoneSender.CancelAsync(
                appEnvironmentId,
                providerReference,
                compensation.Token);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Could not cancel provider phone verification {ChallengeId}.",
                challengeId);
        }
    }

    private async Task<AccessFlowResult> ReplayAfterExternalAsync(
        AccessFlowCommitStatus status,
        AccessFlowScope scope,
        Guid requestId,
        byte[] payloadHash)
    {
        // Once a provider effect has occurred, replay gets a bounded token independent
        // of the disconnected caller so the durable final outcome can still be read.
        using var replay = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        return await ReplayCommitAsync(
            status,
            scope,
            requestId,
            payloadHash,
            replay.Token);
    }

    private async Task<AccessFlowResult> AdvanceWithFeedbackAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        Guid requestId,
        byte[] payloadHash,
        AccessFlowSnapshot snapshot,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var status = await store.TryAdvanceAsync(
            new AdvanceAccessFlowCommand(
                scope,
                stored.FlowId,
                requestId,
                payloadHash,
                stored.CurrentRevision,
                SerializeSnapshot(snapshot),
                now),
            cancellationToken);
        return await ReplayCommitAsync(
            status,
            scope,
            requestId,
            payloadHash,
            cancellationToken);
    }

    private async Task<AccessFlowResult> ReplayCommitAsync(
        AccessFlowCommitStatus status,
        AccessFlowScope scope,
        Guid requestId,
        byte[] payloadHash,
        CancellationToken cancellationToken)
    {
        if (status is AccessFlowCommitStatus.Committed
            or AccessFlowCommitStatus.RequestAlreadyExists)
        {
            // Never construct success from the in-memory command. Read the request that
            // actually won so concurrency and exact idempotency share one response path.
            return await ReplayRequestAsync(
                scope,
                requestId,
                payloadHash,
                cancellationToken);
        }

        return AccessFlowResult.Failure(status switch
        {
            AccessFlowCommitStatus.FlowNotFound => AccessFlowError.FlowNotFound,
            AccessFlowCommitStatus.RevisionConflict => AccessFlowError.RevisionConflict,
            AccessFlowCommitStatus.RegistrationNotPending =>
                AccessFlowError.RegistrationNotPending,
            AccessFlowCommitStatus.SourceSessionInactive =>
                AccessFlowError.SessionInactive,
            AccessFlowCommitStatus.ExternalOperationPending
                or AccessFlowCommitStatus.ExternalOperationFailed =>
                AccessFlowError.DeliveryUnavailable,
            AccessFlowCommitStatus.ProofChallengeNotActive =>
                AccessFlowError.ActionNotAvailable,
            AccessFlowCommitStatus.PhoneOwnershipChanged =>
                AccessFlowError.RevisionConflict,
            AccessFlowCommitStatus.PhoneConflictNotPending =>
                AccessFlowError.ActionNotAvailable,
            AccessFlowCommitStatus.TooManyAttempts =>
                AccessFlowError.ActionNotAvailable,
            _ => AccessFlowError.InvalidRequest,
        });
    }

    private async Task<AccessFlowResult> ReplayRequestAsync(
        AccessFlowScope scope,
        Guid requestId,
        byte[] payloadHash,
        CancellationToken cancellationToken)
    {
        var existing = await store.FindRequestAsync(
            scope.IntegrationClientId,
            requestId,
            cancellationToken);
        // A store-reported commit without its durable request is not replayable success.
        // Collapse it to request conflict rather than returning an unverified snapshot.
        return existing is null
            ? AccessFlowResult.Failure(AccessFlowError.RequestIdConflict)
            : Replay(existing, payloadHash, scope, requestId);
    }

    private async Task<AccessFlowResult> ExpireAsync(
        AccessFlowScope scope,
        StoredAccessFlow stored,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var expiredSnapshot = CreateExpiredSnapshot(stored);
        var status = await store.TryExpireAsync(
            new ExpireAccessFlowCommand(
                scope,
                stored.FlowId,
                stored.CurrentRevision,
                SerializeSnapshot(expiredSnapshot),
                now),
            cancellationToken);
        if (status == AccessFlowCommitStatus.Committed)
        {
            return Success(expiredSnapshot, scope);
        }

        // Expiry can lose to another transition after the preliminary read. Return the
        // durable winner rather than claiming that this caller's expired snapshot won.
        var refreshed = await store.FindFlowAsync(scope, stored.FlowId, cancellationToken);
        return refreshed is null
            ? AccessFlowResult.Failure(AccessFlowError.FlowNotFound)
            : Success(DeserializeSnapshot(refreshed.SnapshotJson), scope);
    }

    private AccessFlowResult Replay(
        StoredAccessFlowRequest stored,
        byte[] presentedPayloadHash,
        AccessFlowScope scope,
        Guid requestId)
    {
        // A request id names exactly one canonical payload. Comparing the hash in constant
        // time prevents both accidental reuse and a content-probing timing signal.
        if (!CryptographicOperations.FixedTimeEquals(
                stored.PayloadHash,
                presentedPayloadHash))
        {
            return AccessFlowResult.Failure(AccessFlowError.RequestIdConflict);
        }

        // Reserved/failed external operations have no replayable success snapshot. They
        // surface as temporary delivery failure instead of repeating the side effect.
        if (stored.Status != AccessFlowRequestStatus.Committed
            || stored.SnapshotJson is null)
        {
            return AccessFlowResult.Failure(AccessFlowError.DeliveryUnavailable);
        }

        AccessFlowIssuedSession? issuedSession = null;
        if (stored.IssuedSession is not null)
        {
            // Re-derive clear authority only from the committed request scope, then
            // compare against the persisted hash before releasing it. A mismatch is a
            // server invariant violation, not a client-visible alternate result.
            var derived = flowTokens.IssueSession(
                stored.Flow.FlowId,
                requestId,
                stored.IssuedSession.IdentityId,
                scope.AppEnvironmentId);
            if (!CryptographicOperations.FixedTimeEquals(
                    derived.TokenHash,
                    stored.IssuedSession.TokenHash))
            {
                throw new InvalidOperationException(
                    "Stored flow session does not match its idempotent token.");
            }

            issuedSession = new AccessFlowIssuedSession(
                stored.IssuedSession.IdentityId,
                stored.IssuedSession.SessionId,
                derived.Token,
                stored.IssuedSession.ExpiresAt,
                stored.IssuedSession.Purpose.ToString().ToLowerInvariant());
        }

        return new AccessFlowResult(
            DeserializeSnapshot(stored.SnapshotJson),
            flowTokens.IssueCapability(
                stored.Flow.FlowId,
                scope.IntegrationClientId,
                scope.AppEnvironmentId),
            issuedSession,
            null);
    }

    private AccessFlowResult Success(
        AccessFlowSnapshot snapshot,
        AccessFlowScope scope) =>
        new(
            snapshot,
            flowTokens.IssueCapability(
                snapshot.FlowId,
                scope.IntegrationClientId,
                scope.AppEnvironmentId),
            null,
            null);

    private static AccessFlowSnapshot CreateCollectPhoneSnapshot(
        StoredAccessFlow stored,
        IdentifierAccessPolicy phonePolicy,
        DateTimeOffset idTimestamp,
        AccessFlowFeedbackSnapshot? feedback = null) =>
        CreateCollectPhoneSnapshot(
            stored.FlowId,
            checked(stored.CurrentRevision + 1),
            stored.ExpiresAt,
            stored.Intent,
            phonePolicy,
            idTimestamp,
            feedback);

    private static AccessFlowSnapshot CreateCollectPhoneSnapshot(
        Guid flowId,
        int revision,
        DateTimeOffset expiresAt,
        AccessFlowIntent intent,
        IdentifierAccessPolicy phonePolicy,
        DateTimeOffset idTimestamp,
        AccessFlowFeedbackSnapshot? feedback = null)
    {
        var primaryAction = Action(
            phonePolicy.Verification.Enabled
                ? AccessFlowProtocol.RequestPhoneVerificationAction
                : AccessFlowProtocol.SubmitPhoneAction,
            idTimestamp);
        // Skipping is an explicit server grant, not a client interpretation of the
        // step. It exists only for registration when this environment makes phone
        // collection optional; managePhone must always choose a phone action.
        IReadOnlyList<AccessFlowActionSnapshot> actions =
            intent == AccessFlowIntent.ContinueRegistration && !phonePolicy.Required
            ? [
                primaryAction,
                Action(AccessFlowProtocol.SkipRegistrationAction, idTimestamp),
            ]
            : [primaryAction];
        return new(
            AccessFlowProtocol.Version1,
            flowId,
            revision,
            IntentName(intent),
            "active",
            expiresAt,
            new AccessFlowStepSnapshot(AccessFlowProtocol.CollectPhoneStep),
            actions,
            Feedback: feedback);
    }

    private static AccessFlowSnapshot CreateVerifyPhoneSnapshot(
        StoredAccessFlow stored,
        StoredProofChallenge challenge,
        IdentifierAccessPolicy phonePolicy,
        DateTimeOffset idTimestamp,
        AccessFlowFeedbackSnapshot? feedback = null) =>
        CreateVerifyPhoneSnapshot(
            stored.FlowId,
            checked(stored.CurrentRevision + 1),
            stored.ExpiresAt,
            stored.Intent,
            challenge,
            phonePolicy,
            idTimestamp,
            feedback);

    private static AccessFlowSnapshot CreateVerifyPhoneSnapshot(
        Guid flowId,
        int revision,
        DateTimeOffset expiresAt,
        AccessFlowIntent intent,
        StoredProofChallenge challenge,
        IdentifierAccessPolicy phonePolicy,
        DateTimeOffset idTimestamp,
        AccessFlowFeedbackSnapshot? feedback = null)
    {
        IReadOnlyList<AccessFlowActionSnapshot> actions =
            intent == AccessFlowIntent.ContinueRegistration && !phonePolicy.Required
            ? [
                Action(AccessFlowProtocol.ConfirmPhoneVerificationAction, idTimestamp),
                Action(AccessFlowProtocol.ResendPhoneVerificationAction, idTimestamp),
                Action(AccessFlowProtocol.ChangePhoneAction, idTimestamp),
                Action(AccessFlowProtocol.SkipRegistrationAction, idTimestamp),
            ]
            : [
                Action(AccessFlowProtocol.ConfirmPhoneVerificationAction, idTimestamp),
                Action(AccessFlowProtocol.ResendPhoneVerificationAction, idTimestamp),
                Action(AccessFlowProtocol.ChangePhoneAction, idTimestamp),
            ];
        return new(
            AccessFlowProtocol.Version1,
            flowId,
            revision,
            IntentName(intent),
            "active",
            expiresAt,
            new AccessFlowStepSnapshot(
                AccessFlowProtocol.VerifyPhoneStep,
                MaskPhone(challenge.DestinationValue),
                challenge.ExpiresAt,
                challenge.ResendAvailableAt),
            actions,
            Feedback: feedback);
    }

    private static AccessFlowSnapshot CreatePhoneConflictSnapshot(
        StoredAccessFlow stored,
        IdentifierAccessPolicy phonePolicy,
        DateTimeOffset idTimestamp,
        string? previousEmailHint,
        bool allowEmailTransfer = true,
        AccessFlowFeedbackSnapshot? feedback = null) =>
        CreatePhoneConflictSnapshot(
            stored.FlowId,
            checked(stored.CurrentRevision + 1),
            stored.ExpiresAt,
            stored.Intent,
            previousEmailHint,
            phonePolicy,
            idTimestamp,
            allowEmailTransfer,
            feedback);

    private static AccessFlowSnapshot CreatePhoneConflictSnapshot(
        Guid flowId,
        int revision,
        DateTimeOffset expiresAt,
        AccessFlowIntent intent,
        string? previousEmailHint,
        IdentifierAccessPolicy phonePolicy,
        DateTimeOffset idTimestamp,
        bool allowEmailTransfer = true,
        AccessFlowFeedbackSnapshot? feedback = null)
    {
        // Previous-identity recovery exists only while completing a provisional
        // registration. A managePhone flow starts from established product authority
        // and may transfer or replace the phone, but must not abandon that identity.
        IReadOnlyList<AccessFlowActionSnapshot> actions = intent == AccessFlowIntent.ManagePhone
            ? allowEmailTransfer
                ? [
                    Action(AccessFlowProtocol.TransferPhoneAction, idTimestamp),
                    Action(AccessFlowProtocol.ChangePhoneAction, idTimestamp),
                ]
                : [Action(AccessFlowProtocol.ChangePhoneAction, idTimestamp)]
            : (allowEmailTransfer, phonePolicy.Required)
            switch
            {
                (true, true) => [
                    Action(AccessFlowProtocol.TransferPhoneAction, idTimestamp),
                    Action(AccessFlowProtocol.RecoverPreviousIdentityAction, idTimestamp),
                    Action(AccessFlowProtocol.ChangePhoneAction, idTimestamp),
                ],
                (true, false) => [
                    Action(AccessFlowProtocol.TransferPhoneAction, idTimestamp),
                    Action(AccessFlowProtocol.RecoverPreviousIdentityAction, idTimestamp),
                    Action(AccessFlowProtocol.ChangePhoneAction, idTimestamp),
                    Action(AccessFlowProtocol.SkipRegistrationAction, idTimestamp),
                ],
                (false, true) => [
                    Action(AccessFlowProtocol.RecoverPreviousIdentityAction, idTimestamp),
                    Action(AccessFlowProtocol.ChangePhoneAction, idTimestamp),
                ],
                (false, false) => [
                    Action(AccessFlowProtocol.RecoverPreviousIdentityAction, idTimestamp),
                    Action(AccessFlowProtocol.ChangePhoneAction, idTimestamp),
                    Action(AccessFlowProtocol.SkipRegistrationAction, idTimestamp),
                ],
            };
        return new(
            AccessFlowProtocol.Version1,
            flowId,
            revision,
            IntentName(intent),
            "active",
            expiresAt,
            new AccessFlowStepSnapshot(
                AccessFlowProtocol.ResolvePhoneConflictStep,
                PreviousEmailHint: previousEmailHint),
            actions,
            Feedback: feedback);
    }

    private static AccessFlowSnapshot CreateTerminalSnapshot(
        StoredAccessFlow stored,
        string type,
        string outcome,
        Guid? previousIdentityId = null,
        Guid? currentIdentityId = null) =>
        new(
            stored.ProtocolVersion,
            stored.FlowId,
            checked(stored.CurrentRevision + 1),
            IntentName(stored.Intent),
            "completed",
            stored.ExpiresAt,
            null,
            [],
            Result: new AccessFlowResultSnapshot(
                type,
                outcome,
                previousIdentityId,
                currentIdentityId));

    private static AccessFlowSnapshot CreateExpiredSnapshot(
        StoredAccessFlow stored) =>
        new(
            stored.ProtocolVersion,
            stored.FlowId,
            checked(stored.CurrentRevision + 1),
            IntentName(stored.Intent),
            "expired",
            stored.ExpiresAt,
            null,
            [],
            Result: new AccessFlowResultSnapshot("flowExpired"));

    private static ExpireActiveAccessFlowCommand CreateExpirationCommand(
        StoredAccessFlow stored,
        DateTimeOffset expiredAt) =>
        new(
            stored.FlowId,
            stored.CurrentRevision,
            SerializeSnapshot(CreateExpiredSnapshot(stored)),
            expiredAt);

    private static string IntentName(AccessFlowIntent intent) => intent switch
    {
        AccessFlowIntent.ContinueRegistration =>
            AccessFlowProtocol.ContinueRegistrationIntent,
        AccessFlowIntent.ManagePhone => AccessFlowProtocol.ManagePhoneIntent,
        _ => throw new ArgumentOutOfRangeException(nameof(intent), intent, null),
    };

    private static AccessFlowActionSnapshot Action(
        string type,
        DateTimeOffset timestamp) =>
        new(Guid.CreateVersion7(timestamp), type);

    private static string? ReadInputString(JsonElement? input, string propertyName)
    {
        if (input is not { ValueKind: JsonValueKind.Object } value
            || !value.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String)
        {
            return null;
        }
        return property.GetString();
    }

    private static bool IsDevelopmentBypass(
        DevelopmentBypassConfiguration bypass,
        string phone) =>
        bypass.Enabled
        && string.Equals(
            bypass.Phone?.Trim(),
            phone,
            StringComparison.Ordinal);

    private static string GenerateCode() =>
        RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");

    private static byte[] HashSecret(string secret) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(secret));

    private static string MaskPhone(string phone)
    {
        if (phone.Length <= 7)
        {
            return "***";
        }
        return string.Concat(
            phone.AsSpan(0, 3),
            new string('*', phone.Length - 7),
            phone.AsSpan(phone.Length - 4));
    }

    private static string? MaskEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }
        var separator = email.IndexOf('@');
        if (separator <= 0)
        {
            return "***";
        }
        var local = email[..separator];
        var visible = local.Length == 1 ? local : local[..1];
        return $"{visible}***{email[separator..]}";
    }

    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) =>
        left <= right ? left : right;

    private static bool TryValidateApplicationClientKey(
        string? value,
        out string validatedKey)
    {
        try
        {
            validatedKey = TopologyValue.Key(value!, nameof(value));
            return true;
        }
        catch (ArgumentException)
        {
            validatedKey = string.Empty;
            return false;
        }
    }

    private static string SerializeSnapshot(AccessFlowSnapshot snapshot) =>
        JsonSerializer.Serialize(snapshot, JsonOptions);

    private static AccessFlowSnapshot DeserializeSnapshot(string snapshotJson) =>
        JsonSerializer.Deserialize<AccessFlowSnapshot>(snapshotJson, JsonOptions)
        ?? throw new InvalidOperationException("Stored AccessFlow snapshot is empty.");

    private static byte[] HashPayload<TPayload>(TPayload payload)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        try
        {
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<AppEnvironmentConfiguration> RequireConfigurationAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        await configurations.FindAsync(appEnvironmentId, cancellationToken)
        ?? throw new InvalidOperationException(
            "The app environment configuration could not be resolved.");

    private static void ValidateScope(AccessFlowScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (scope.IntegrationClientId == Guid.Empty
            || scope.AppEnvironmentId == Guid.Empty
            || scope.RealmId == Guid.Empty)
        {
            throw new ArgumentException("Access flow scope is incomplete.", nameof(scope));
        }
    }

    private sealed record StartPayload(
        IReadOnlyList<int>? ProtocolVersions,
        string? Intent,
        string? ApplicationClientKey,
        string? SessionToken);

    private sealed record ActionPayload(
        Guid FlowId,
        int ExpectedRevision,
        Guid ActionId,
        string ActionType,
        JsonElement? Input);
}
