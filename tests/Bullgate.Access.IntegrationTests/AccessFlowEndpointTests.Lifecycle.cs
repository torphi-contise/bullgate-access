using System.Net;
using System.Net.Http.Json;
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
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    public async Task Get_ExpiresAtTheDeadlineWithoutCompletingRegistration(
        int secondsFromDeadline,
        bool expired)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"flow-read-expiry-{Guid.NewGuid():N}@example.com");
        clock.Advance(FlowDuration + TimeSpan.FromSeconds(secondsFromDeadline));

        using var response = await SendWithCapabilityAsync(
            HttpMethod.Get,
            $"/v1/access/flows/{registration.FlowId:D}",
            registration.Capability,
            null);
        var body = await ReadSuccessfulResponseAsync(response);
        Assert.Equal(JsonValueKind.Null, body.GetProperty("issuedSession").ValueKind);
        var snapshot = body.GetProperty("snapshot");
        if (expired)
        {
            AssertExpiredSnapshot(snapshot, revision: 2);
        }
        else
        {
            Assert.Equal(registration.Flow.GetRawText(), snapshot.GetRawText());
        }

        // Reading again must not append another terminal revision or extend the deadline.
        Assert.Equal(snapshot.GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertFlowPersistenceAsync(
            registration,
            expired ? AccessFlowStatus.Expired : AccessFlowStatus.Active,
            expired ? 2 : 1);
        await AssertRegistrationStillPendingAsync(registration);

        if (expired)
        {
            using var restarted = await StartFlowAsync(
                "continueRegistration", registration.SourceSessionToken);
            var replacement = await ReadStartedFlowAsync(
                restarted, registration.IdentityId, registration.SourceSessionToken);
            Assert.NotEqual(registration.FlowId, replacement.FlowId);
            var completed = await ExecuteActionAsync(
                replacement, replacement.Flow, "skipRegistration");
            await AssertSingleProductSessionAsync(registration, completed);
        }
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    public async Task SkipRegistration_OnlyCompletesBeforeTheDeadline(
        int secondsFromDeadline,
        bool expired)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"flow-action-expiry-{Guid.NewGuid():N}@example.com");
        clock.Advance(FlowDuration + TimeSpan.FromSeconds(secondsFromDeadline));

        var result = await ExecuteActionAsync(
            registration, registration.Flow, "skipRegistration");
        var snapshot = result.GetProperty("snapshot");
        if (expired)
        {
            AssertExpiredSnapshot(snapshot, revision: 2);
            Assert.Equal(JsonValueKind.Null, result.GetProperty("issuedSession").ValueKind);
            await AssertRegistrationStillPendingAsync(registration);
        }
        else
        {
            Assert.Equal("completed", snapshot.GetProperty("status").GetString());
            Assert.Equal("skipped",
                snapshot.GetProperty("result").GetProperty("outcome").GetString());
            await AssertSingleProductSessionAsync(registration, result);
        }

        // A new request cannot run the old action on either terminal outcome.
        using var repeated = await PostLifecycleActionAsync(
            registration, registration.Flow, "skipRegistration", Guid.NewGuid());
        await AssertFlowErrorAsync(repeated, "action-not-available", "action");
        Assert.Equal(snapshot.GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertFlowPersistenceAsync(
            registration,
            expired ? AccessFlowStatus.Expired : AccessFlowStatus.Completed,
            revision: 2);
        if (expired)
        {
            await AssertRegistrationStillPendingAsync(registration);
        }
        else
        {
            await AssertSingleProductSessionAsync(registration, result);
        }
    }

    [Theory]
    [InlineData("stale-revision", "revision-conflict", "expectedRevision")]
    [InlineData("future-revision", "revision-conflict", "expectedRevision")]
    [InlineData("old-action-id", "action-not-available", "action")]
    [InlineData("wrong-action-type", "action-not-available", "action")]
    [InlineData("unknown-action-id", "action-not-available", "action")]
    public async Task Act_RejectsDecisionsOutsideTheCurrentSnapshotWithoutChangingRegistration(
        string scenario,
        string error,
        string field)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"flow-stale-action-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654330";
        var verification = await RequestPhoneAsync(
            registration.Flow, registration.Capability, phone);
        var delivery = Assert.Single(api.PhoneSender.DeliveryAttempts);
        var revision = verification.GetProperty("revision").GetInt32();
        var actionId = FindAction(verification, "skipRegistration").GetProperty("id").GetGuid();
        var actionType = "skipRegistration";
        switch (scenario)
        {
            case "stale-revision":
                revision = registration.Flow.GetProperty("revision").GetInt32();
                actionId = FindAction(registration.Flow, "skipRegistration")
                    .GetProperty("id").GetGuid();
                break;
            case "future-revision":
                revision++;
                break;
            case "old-action-id":
                actionId = FindAction(registration.Flow, "skipRegistration")
                    .GetProperty("id").GetGuid();
                break;
            case "wrong-action-type":
                actionType = "confirmPhoneVerification";
                break;
            case "unknown-action-id":
                actionId = Guid.NewGuid();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(scenario));
        }

        var rejectedRequestId = Guid.NewGuid();
        using var rejected = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId = rejectedRequestId,
                expectedRevision = revision,
                action = new { id = actionId, type = actionType, input = new { code = delivery.Code } },
            });
        await AssertFlowErrorAsync(rejected, error, field);
        Assert.Equal(verification.GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertRegistrationStillPendingAsync(registration);
        await AssertFlowPersistenceAsync(registration, AccessFlowStatus.Active, revision: 2);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.AccessFlowRequests.AnyAsync(
                request => request.RequestId == rejectedRequestId));
            var challenge = await db.ProofChallenges.AsNoTracking().SingleAsync(
                item => item.AccessFlowId == registration.FlowId);
            Assert.Equal(ProofChallengeStatus.Active, challenge.Status);
            Assert.Empty(await db.ProofAttempts.ToListAsync());
        }
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Empty(api.PhoneSender.CancellationAttempts);
        Assert.Empty(api.PhoneSender.ApprovalAttempts);

        // Rejection must not consume the request id or the valid code.
        var completed = await ExecuteActionAsync(
            registration,
            verification,
            "confirmPhoneVerification",
            new { code = delivery.Code },
            rejectedRequestId);
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
        Assert.Single(api.PhoneSender.DeliveryAttempts);
    }

    [Fact]
    public async Task Act_ReusingARequestIdForAnotherPhoneDoesNotSendOrReplaceTheOriginalChallenge()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"flow-request-conflict-{Guid.NewGuid():N}@example.com");
        const string originalPhone = "+5511987654330";
        var requestId = Guid.NewGuid();
        var accepted = await ExecuteActionAsync(
            registration, registration.Flow, "requestPhoneVerification",
            new { phone = originalPhone }, requestId);
        var verification = accepted.GetProperty("snapshot");
        var delivery = Assert.Single(api.PhoneSender.DeliveryAttempts);

        using var conflicting = await PostLifecycleActionAsync(
            registration, registration.Flow, "requestPhoneVerification", requestId,
            new { phone = "+5511987654331" });
        await AssertFlowErrorAsync(conflicting, "request-id-conflict", "requestId");
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Empty(api.PhoneSender.CancellationAttempts);
        Assert.Equal(verification.GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertRegistrationStillPendingAsync(registration);

        var completed = await ExecuteActionAsync(
            registration, verification, "confirmPhoneVerification", new { code = delivery.Code });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, originalPhone);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Single(await db.ProofChallenges.Where(
            item => item.AccessFlowId == registration.FlowId).ToListAsync());
        var request = await db.AccessFlowRequests.AsNoTracking().SingleAsync(
            item => item.RequestId == requestId);
        Assert.Equal(AccessFlowRequestStatus.Committed, request.Status);
        Assert.Equal(2, request.ResultRevision);
    }

    [Fact]
    public async Task Act_ReplayingAnEarlierStepDoesNotResendSmsOrRewindTheFlow()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"flow-old-replay-{Guid.NewGuid():N}@example.com");
        var requestId = Guid.NewGuid();
        var original = await ExecuteActionAsync(
            registration, registration.Flow, "requestPhoneVerification",
            new { phone = "+5511987654330" }, requestId);
        var changed = await ExecuteActionAsync(
            registration, original.GetProperty("snapshot"), "changePhone");
        var current = changed.GetProperty("snapshot");
        Assert.Equal(3, current.GetProperty("revision").GetInt32());
        Assert.Equal("collectPhone", current.GetProperty("step").GetProperty("type").GetString());

        var replayed = await ExecuteActionAsync(
            registration, registration.Flow, "requestPhoneVerification",
            new { phone = "+5511987654330" }, requestId);
        Assert.Equal(original.GetRawText(), replayed.GetRawText());
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Equal(current.GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertFlowPersistenceAsync(registration, AccessFlowStatus.Active, revision: 3);
        await AssertRegistrationStillPendingAsync(registration);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var challenge = await db.ProofChallenges.AsNoTracking().SingleAsync(
                item => item.AccessFlowId == registration.FlowId);
            Assert.Equal(ProofChallengeStatus.Superseded, challenge.Status);
            Assert.Equal(3, await db.AccessFlowRequests.CountAsync(
                item => item.FlowId == registration.FlowId));
        }

        // The current screen remains usable; only its new request may send another SMS.
        var verification = await RequestPhoneAsync(
            current, registration.Capability, "+5511987654331");
        Assert.Equal(4, verification.GetProperty("revision").GetInt32());
        Assert.Equal(2, api.PhoneSender.DeliveryAttempts.Count);
        var completed = await ExecuteActionAsync(
            registration, verification, "confirmPhoneVerification",
            new { code = api.PhoneSender.LastCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, "+5511987654331");
    }

    [Fact]
    public async Task CompletedFlow_AfterItsDeadlineReplaysTheSameSessionWithoutExpiringOrIssuingAnother()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"flow-terminal-replay-{Guid.NewGuid():N}@example.com");
        var requestId = Guid.NewGuid();
        var completed = await ExecuteActionAsync(
            registration, registration.Flow, "skipRegistration", requestId: requestId);
        clock.Advance(FlowDuration + TimeSpan.FromSeconds(1));

        var replayed = await ExecuteActionAsync(
            registration, registration.Flow, "skipRegistration", requestId: requestId);
        Assert.Equal(completed.GetRawText(), replayed.GetRawText());
        using var newRequest = await PostLifecycleActionAsync(
            registration, registration.Flow, "skipRegistration", Guid.NewGuid());
        await AssertFlowErrorAsync(newRequest, "action-not-available", "action");
        Assert.Equal(completed.GetProperty("snapshot").GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertSingleProductSessionAsync(registration, replayed);
        await AssertFlowPersistenceAsync(registration, AccessFlowStatus.Completed, revision: 2);

        using var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = replayed.GetProperty("issuedSession").GetProperty("sessionToken").GetString() });
        var session = await ReadSuccessfulResponseAsync(introspection);
        Assert.True(session.GetProperty("active").GetBoolean());
        Assert.Equal(registration.IdentityId, session.GetProperty("identityId").GetGuid());
        Assert.Equal("product", session.GetProperty("sessionPurpose").GetString());
    }

    private Task<HttpResponseMessage> PostLifecycleActionAsync(
        StartedRegistration registration,
        JsonElement snapshot,
        string actionType,
        Guid requestId,
        object? input = null) =>
        SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId,
                expectedRevision = snapshot.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(snapshot, actionType).GetProperty("id").GetGuid(),
                    type = actionType,
                    input,
                },
            });

    private static async Task<JsonElement> ReadSuccessfulResponseAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.Clone();
    }

    private static async Task AssertFlowErrorAsync(
        HttpResponseMessage response, string error, string field)
    {
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(error, body.RootElement.GetProperty("error").GetString());
        Assert.Equal(field, body.RootElement.GetProperty("field").GetString());
        Assert.False(body.RootElement.TryGetProperty("issuedSession", out _));
    }

    private static void AssertExpiredSnapshot(JsonElement snapshot, int revision)
    {
        Assert.Equal("expired", snapshot.GetProperty("status").GetString());
        Assert.Equal(revision, snapshot.GetProperty("revision").GetInt32());
        Assert.Equal("flowExpired", snapshot.GetProperty("result").GetProperty("type").GetString());
        Assert.Empty(snapshot.GetProperty("actions").EnumerateArray());
    }

    private async Task AssertFlowPersistenceAsync(
        StartedRegistration registration, AccessFlowStatus status, int revision)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var flow = await db.AccessFlows.AsNoTracking().SingleAsync(
            item => item.Id == registration.FlowId);
        Assert.Equal(status, flow.Status);
        Assert.Equal(revision, flow.CurrentRevision);
        Assert.Equal(registration.Flow.GetProperty("expiresAt").GetDateTimeOffset(), flow.ExpiresAt);
        Assert.Equal(revision, await db.AccessFlowRevisions.CountAsync(
            item => item.FlowId == registration.FlowId));
    }

    private async Task AssertRegistrationStillPendingAsync(StartedRegistration registration)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var context = await db.RegistrationContexts.AsNoTracking().SingleAsync(
            item => item.IdentityId == registration.IdentityId);
        Assert.Equal(RegistrationContextStatus.Open, context.Status);
        Assert.Null(context.ClosedAt);
        var session = Assert.Single(await db.IdentitySessions.AsNoTracking().Where(
            item => item.IdentityId == registration.IdentityId).ToListAsync());
        Assert.Equal(IdentitySessionPurpose.Registration, session.Purpose);
        Assert.Null(session.RevokedAt);
        Assert.True(session.ExpiresAt > clock.GetUtcNow());
        var email = Assert.Single(await db.IdentityIdentifiers.AsNoTracking().Where(
            item => item.IdentityId == registration.IdentityId).ToListAsync());
        Assert.Equal(IdentifierScheme.Email, email.Scheme);
    }

    private async Task AssertSingleProductSessionAsync(
        StartedRegistration registration, JsonElement completed)
    {
        Assert.Equal("completed",
            completed.GetProperty("snapshot").GetProperty("status").GetString());
        var issuedSession = completed.GetProperty("issuedSession");
        Assert.Equal("product", issuedSession.GetProperty("purpose").GetString());
        Assert.Equal(registration.IdentityId, issuedSession.GetProperty("identityId").GetGuid());
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var sessions = await db.IdentitySessions.AsNoTracking().Where(
            item => item.IdentityId == registration.IdentityId).ToListAsync();
        Assert.Equal(2, sessions.Count);
        var product = Assert.Single(sessions, item => item.Purpose == IdentitySessionPurpose.Product);
        Assert.Equal(issuedSession.GetProperty("sessionId").GetGuid(), product.Id);
        Assert.Null(product.RevokedAt);
        Assert.NotNull(Assert.Single(sessions,
            item => item.Purpose == IdentitySessionPurpose.Registration).RevokedAt);
        var context = await db.RegistrationContexts.AsNoTracking().SingleAsync(
            item => item.IdentityId == registration.IdentityId);
        Assert.Equal(RegistrationContextStatus.Completed, context.Status);
        Assert.NotNull(context.ClosedAt);
    }

    private async Task AssertVerifiedPhoneAsync(Guid identityId, string phone)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var identifier = await db.IdentityIdentifiers.AsNoTracking().SingleAsync(
            item => item.IdentityId == identityId && item.Scheme == IdentifierScheme.Phone);
        Assert.Equal(phone, identifier.NormalizedValue);
        Assert.NotNull(identifier.VerifiedAt);
        Assert.Equal("sms", identifier.VerificationMethod);
    }
}
