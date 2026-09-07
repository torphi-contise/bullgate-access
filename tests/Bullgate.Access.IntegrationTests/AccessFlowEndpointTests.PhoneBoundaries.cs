using System.Net;
using System.Text.Json;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed partial class AccessFlowEndpointTests
{
    [Theory]
    [InlineData(false, null)]
    [InlineData(true, null)]
    [InlineData(false, "11987654321")]
    [InlineData(true, "11987654321")]
    [InlineData(false, "not-a-phone")]
    [InlineData(true, "not-a-phone")]
    public async Task CollectPhone_InvalidNumberDoesNotSendOrPersistAPhoneAndAllowsCorrection(
        bool verifyPhone, string? phone)
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneVerificationEnabled: verifyPhone));
        var registration = await RegisterAndStartFlowAsync(
            $"invalid-flow-phone-{Guid.NewGuid():N}@example.com");
        var actionType = verifyPhone ? "requestPhoneVerification" : "submitPhone";
        var rejected = await ExecuteActionAsync(
            registration, registration.Flow, actionType, new { phone });

        AssertPhoneFeedback(rejected, "invalid-phone", "collectPhone");
        Assert.Equal("phone",
            rejected.GetProperty("snapshot").GetProperty("feedback").GetProperty("field").GetString());
        Assert.Empty(api.PhoneSender.DeliveryAttempts);
        Assert.Empty(await ReadFlowChallengesAsync(registration));
        await AssertNoPhoneProofAsync(registration, failedAttempts: 0);

        const string correctedPhone = "+5511987654360";
        var corrected = await ExecuteActionAsync(
            registration, rejected.GetProperty("snapshot"), actionType,
            new { phone = $"  {correctedPhone}  " });
        var completed = verifyPhone
            ? await ExecuteActionAsync(
                registration, corrected.GetProperty("snapshot"), "confirmPhoneVerification",
                new { code = api.PhoneSender.LastCode })
            : corrected;
        await AssertSingleProductSessionAsync(registration, completed);
        var storedPhone = await ReadPhoneIdentifierAsync(registration.IdentityId);
        Assert.Equal(correctedPhone, storedPhone.NormalizedValue);
        Assert.Equal(verifyPhone, storedPhone.VerifiedAt is not null);
        Assert.Equal(verifyPhone ? "sms" : null, storedPhone.VerificationMethod);
        Assert.Equal(verifyPhone ? 1 : 0, api.PhoneSender.DeliveryAttempts.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SubmitPhone_AnotherIdentitysNumberCannotBeTakenWithoutVerification(bool managePhone)
    {
        const string ownedPhone = "+15555550123";
        const string currentPhone = "+5511987654361";
        const string availablePhone = "+5511987654362";
        var previous = await RegisterAndStartFlowAsync(
            $"phone-owner-{Guid.NewGuid():N}@example.com");
        var previousVerification = await RequestPhoneAsync(previous.Flow, previous.Capability, ownedPhone);
        var previousCompleted = await ExecuteActionAsync(
            previous, previousVerification, "confirmPhoneVerification", new { code = "123456" });
        var previousGraph = await ReadIdentityBusinessStateAsync(previous.IdentityId);
        var previousToken = previousCompleted.GetProperty("issuedSession").GetProperty("sessionToken").GetString()!;

        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneVerificationEnabled: false));
        var current = await RegisterAndStartFlowAsync(
            $"phone-claimant-{Guid.NewGuid():N}@example.com");
        var flow = current;
        if (managePhone)
        {
            var registered = await ExecuteActionAsync(
                current, current.Flow, "submitPhone", new { phone = currentPhone });
            using var started = await StartFlowAsync(
                "managePhone", registered.GetProperty("issuedSession").GetProperty("sessionToken").GetString());
            flow = await ReadStartedFlowAsync(
                started, current.IdentityId,
                registered.GetProperty("issuedSession").GetProperty("sessionToken").GetString());
        }
        var currentGraph = await ReadIdentityBusinessStateAsync(current.IdentityId);

        var rejected = await ExecuteActionAsync(
            flow, flow.Flow, "submitPhone", new { phone = ownedPhone });
        AssertPhoneFeedback(rejected, "phone-already-in-use", "collectPhone");
        Assert.Equal(previousGraph, await ReadIdentityBusinessStateAsync(previous.IdentityId));
        Assert.Equal(currentGraph, await ReadIdentityBusinessStateAsync(current.IdentityId));
        Assert.True((await IntrospectFlowSessionAsync(flow.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
        Assert.Empty(await ReadFlowChallengesAsync(flow));
        Assert.Empty(api.PhoneSender.DeliveryAttempts);

        var completed = await ExecuteActionAsync(
            flow, rejected.GetProperty("snapshot"), "submitPhone", new { phone = availablePhone });
        Assert.Equal("completed", completed.GetProperty("snapshot").GetProperty("status").GetString());
        var issued = completed.GetProperty("issuedSession");
        var currentSession = await IntrospectFlowSessionAsync(issued.GetProperty("sessionToken").GetString()!);
        Assert.True(currentSession.GetProperty("active").GetBoolean());
        Assert.Equal(current.IdentityId, currentSession.GetProperty("identityId").GetGuid());
        Assert.Equal(availablePhone, currentSession.GetProperty("phone").GetString());
        Assert.False((await IntrospectFlowSessionAsync(flow.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
        var assigned = await ReadPhoneIdentifierAsync(current.IdentityId);
        Assert.Equal(availablePhone, assigned.NormalizedValue);
        Assert.Null(assigned.VerifiedAt);
        Assert.Null(assigned.VerificationMethod);
        Assert.Equal(previousGraph, await ReadIdentityBusinessStateAsync(previous.IdentityId));
        var previousSession = await IntrospectFlowSessionAsync(previousToken);
        Assert.True(previousSession.GetProperty("active").GetBoolean());
        Assert.Equal(ownedPhone, previousSession.GetProperty("phone").GetString());
        Assert.Empty(api.PhoneSender.DeliveryAttempts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConfirmPhone_SessionInsertFailureRollsBackBusinessStateAndReleasesTheCodeForRetry(
        bool managePhone)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"phone-confirmation-rollback-{Guid.NewGuid():N}@example.com");
        var flow = registration;
        if (managePhone)
        {
            var initialVerification = await RequestPhoneAsync(registration.Flow, registration.Capability);
            var registered = await ExecuteActionAsync(
                registration, initialVerification, "confirmPhoneVerification", new { code = "123456" });
            var sourceToken = registered.GetProperty("issuedSession").GetProperty("sessionToken").GetString();
            using var started = await StartFlowAsync("managePhone", sourceToken);
            flow = await ReadStartedFlowAsync(started, registration.IdentityId, sourceToken);
        }

        const string newPhone = "+5511987654363";
        var verification = await RequestPhoneAsync(flow.Flow, flow.Capability, newPhone);
        var challenge = Assert.Single(await ReadFlowChallengesAsync(flow));
        var code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        var before = await ReadIdentityBusinessStateAsync(registration.IdentityId);
        Guid environmentId;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            environmentId = await db.AccessFlows.Where(item => item.Id == flow.FlowId)
                .Select(item => item.AppEnvironmentId).SingleAsync();
        }
        var failedRequestId = Guid.NewGuid();
        await using (var fault = await PostgreSqlInsertFault.CreateAsync(
            database.ConnectionString, "identity_sessions", environmentId))
        {
            Assert.False(await fault.WasTriggeredAsync());
            using var failed = await PostLifecycleActionAsync(
                flow, verification, "confirmPhoneVerification", failedRequestId, new { code });
            Assert.True(await fault.WasTriggeredAsync());
            Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        }

        Assert.Equal(before, await ReadIdentityBusinessStateAsync(registration.IdentityId));
        Assert.Equal(verification.GetRawText(), (await GetFlowSnapshotAsync(flow)).GetRawText());
        var released = Assert.Single(await ReadFlowChallengesAsync(flow));
        Assert.Equal(challenge.Id, released.Id);
        Assert.Equal(ProofChallengeStatus.Active, released.Status);
        Assert.Equal(0, released.Attempts);
        Assert.Null(released.CompletedAt);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.ProofAttempts.AnyAsync(item => item.ChallengeId == challenge.Id));
            Assert.False(await db.IdentityProofs.AnyAsync(item => item.AccessFlowId == flow.FlowId));
            var request = await db.AccessFlowRequests.AsNoTracking().SingleAsync(
                item => item.RequestId == failedRequestId);
            Assert.Equal(AccessFlowRequestStatus.ExternalFailed, request.Status);
            Assert.Null(request.ResultRevision);
            Assert.Null(request.IssuedSessionId);
        }
        Assert.True((await IntrospectFlowSessionAsync(flow.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
        Assert.Single(api.PhoneSender.DeliveryAttempts);

        // The failed request stays failed; a new decision can reuse the still-valid proof.
        using var failedReplay = await PostLifecycleActionAsync(
            flow, verification, "confirmPhoneVerification", failedRequestId, new { code });
        await AssertDeliveryUnavailableAsync(failedReplay);
        Assert.Equal(before, await ReadIdentityBusinessStateAsync(registration.IdentityId));
        var retryRequestId = Guid.NewGuid();
        var completed = await ExecuteActionAsync(
            flow, verification, "confirmPhoneVerification", new { code }, retryRequestId);
        var replay = await ExecuteActionAsync(
            flow, verification, "confirmPhoneVerification", new { code }, retryRequestId);
        Assert.Equal(completed.GetRawText(), replay.GetRawText());
        Assert.Equal("completed", completed.GetProperty("snapshot").GetProperty("status").GetString());
        await AssertVerifiedPhoneAsync(registration.IdentityId, newPhone);
        Assert.False((await IntrospectFlowSessionAsync(flow.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
        var issued = completed.GetProperty("issuedSession");
        var activeSession = await IntrospectFlowSessionAsync(issued.GetProperty("sessionToken").GetString()!);
        Assert.True(activeSession.GetProperty("active").GetBoolean());
        Assert.Equal(registration.IdentityId, activeSession.GetProperty("identityId").GetGuid());
        Assert.Equal(newPhone, activeSession.GetProperty("phone").GetString());

        await using var finalScope = api.Services.CreateAsyncScope();
        var finalDb = finalScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var sessions = await finalDb.IdentitySessions.AsNoTracking().Where(
            item => item.IdentityId == registration.IdentityId).ToListAsync();
        Assert.Equal(managePhone ? 3 : 2, sessions.Count);
        Assert.Equal(issued.GetProperty("sessionId").GetGuid(),
            Assert.Single(sessions, item => item.RevokedAt is null).Id);
        var proof = await finalDb.IdentityProofs.AsNoTracking().SingleAsync(
            item => item.AccessFlowId == flow.FlowId);
        Assert.Equal(challenge.Id, proof.ChallengeId);
        var attempt = await finalDb.ProofAttempts.AsNoTracking().SingleAsync(
            item => item.ChallengeId == challenge.Id);
        Assert.Equal(ProofAttemptOutcome.Succeeded, attempt.Outcome);
        Assert.Equal(ProofChallengeStatus.Verified,
            Assert.Single(await ReadFlowChallengesAsync(flow)).Status);
        Assert.Single(api.PhoneSender.DeliveryAttempts);
    }

    [Fact]
    public async Task PhoneRequestLimit_FailedDeliveriesDoNotSpendTheSuccessfulDeliveryQuota()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"failed-delivery-quota-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654364";
        api.PhoneSender.RejectDelivery = true;
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            using var failed = await PostLifecycleActionAsync(
                registration, registration.Flow, "requestPhoneVerification",
                Guid.NewGuid(), new { phone });
            await AssertDeliveryUnavailableAsync(failed);
            Assert.Equal(attempt, api.PhoneSender.DeliveryAttempts.Count);
        }
        api.PhoneSender.RejectDelivery = false;
        var failedChallenges = await ReadFlowChallengesAsync(registration);
        Assert.Equal(5, failedChallenges.Count);
        Assert.All(failedChallenges, item => Assert.Equal(ProofChallengeStatus.DeliveryFailed, item.Status));
        Assert.Equal(registration.Flow.GetRawText(), (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertNoPhoneProofAsync(registration, failedAttempts: 0);

        var verification = await RequestPhoneAsync(registration.Flow, registration.Capability, phone);
        Assert.Equal(6, api.PhoneSender.DeliveryAttempts.Count);
        var active = Assert.Single(await ReadFlowChallengesAsync(registration),
            item => item.Status == ProofChallengeStatus.Active);
        var completed = await ExecuteActionAsync(
            registration, verification, "confirmPhoneVerification", new { code = api.PhoneSender.LastCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
        await AssertSuccessfulPhoneProofAsync(registration, active.Id, failedAttempts: 0);
        var finalChallenges = await ReadFlowChallengesAsync(registration);
        Assert.Equal(6, finalChallenges.Count);
        Assert.Equal(5, finalChallenges.Count(item => item.Status == ProofChallengeStatus.DeliveryFailed));
        Assert.Single(finalChallenges, item => item.Status == ProofChallengeStatus.Verified);
        Assert.Equal(6, api.PhoneSender.DeliveryAttempts.Count);
    }

    private async Task<IdentityIdentifier> ReadPhoneIdentifierAsync(Guid identityId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        return await db.IdentityIdentifiers.AsNoTracking().SingleAsync(
            item => item.IdentityId == identityId && item.Scheme == IdentifierScheme.Phone);
    }

    private async Task<string> ReadIdentityBusinessStateAsync(Guid identityId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var identity = await db.Identities.AsNoTracking().Where(item => item.Id == identityId)
            .Select(item => new { item.Id, item.LifecycleState }).SingleAsync();
        var identifiers = await db.IdentityIdentifiers.AsNoTracking()
            .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id)
            .Select(item => new { item.Id, item.Scheme, item.NormalizedValue, item.VerifiedAt, item.VerificationMethod })
            .ToListAsync();
        var sessions = await db.IdentitySessions.AsNoTracking()
            .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id)
            .Select(item => new { item.Id, item.Purpose, item.RevokedAt, item.ExpiresAt }).ToListAsync();
        var contexts = await db.RegistrationContexts.AsNoTracking()
            .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id)
            .Select(item => new { item.Id, item.Status, item.ClosedAt }).ToListAsync();
        var proofs = await db.IdentityProofs.AsNoTracking()
            .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id)
            .Select(item => new { item.Id, item.AccessFlowId, item.ChallengeId, item.SubjectIdentifierId })
            .ToListAsync();
        return JsonSerializer.Serialize(new { identity, identifiers, sessions, contexts, proofs });
    }
}
