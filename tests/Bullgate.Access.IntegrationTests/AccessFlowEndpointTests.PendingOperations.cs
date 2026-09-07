using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Bullgate.Access.IntegrationTests;

public sealed partial class AccessFlowEndpointTests
{
    [Fact]
    public async Task PhoneDelivery_ExactRetryWhilePendingDoesNotSendAgainAndLaterReplaysSuccess()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"pending-replay-{Guid.NewGuid():N}@example.com");
        var requestId = Guid.NewGuid();
        var input = new { phone = "+5511987654340" };
        var gate = new AsyncOperationGate();
        api.PhoneSender.SendGate = gate;
        var deliveryTask = PostLifecycleActionAsync(
            registration, registration.Flow, "requestPhoneVerification", requestId, input);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            await gate.WaitUntilEnteredAsync(deadline.Token);

            using var replay = await PostLifecycleActionAsync(
                registration, registration.Flow, "requestPhoneVerification", requestId, input)
                .WaitAsync(deadline.Token);
            await AssertDeliveryUnavailableAsync(replay);
            Assert.Single(api.PhoneSender.DeliveryAttempts);
            await AssertOnlyDeliveryRequestAsync(
                registration, requestId,
                AccessFlowRequestStatus.PendingExternal, ProofChallengeStatus.PendingDelivery);
            Assert.Equal(registration.Flow.GetRawText(),
                (await GetFlowSnapshotAsync(registration)).GetRawText());
            await AssertRegistrationStillPendingAsync(registration);
        }
        finally
        {
            gate.Release();
            api.PhoneSender.SendGate = null;
        }

        using var delivered = await deliveryTask.WaitAsync(TimeSpan.FromSeconds(10));
        var accepted = await ReadSuccessfulResponseAsync(delivered);
        var replayed = await ExecuteActionAsync(
            registration, registration.Flow, "requestPhoneVerification", input, requestId);
        Assert.Equal(accepted.GetRawText(), replayed.GetRawText());
        await AssertOnlyDeliveryRequestAsync(
            registration, requestId,
            AccessFlowRequestStatus.Committed, ProofChallengeStatus.Active);

        var completed = await ExecuteActionAsync(
            registration, accepted.GetProperty("snapshot"), "confirmPhoneVerification",
            new { code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, input.phone);
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Empty(api.PhoneSender.CancellationAttempts);
    }

    [Fact]
    public async Task PhoneDelivery_ExactRetryAfterFailureDoesNotResendWhenTheProviderRecovers()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"failed-replay-{Guid.NewGuid():N}@example.com");
        var requestId = Guid.NewGuid();
        var input = new { phone = "+5511987654341" };
        api.PhoneSender.RejectDelivery = true;
        using var failed = await PostLifecycleActionAsync(
            registration, registration.Flow, "requestPhoneVerification", requestId, input);
        await AssertDeliveryUnavailableAsync(failed);
        api.PhoneSender.RejectDelivery = false;

        using var replay = await PostLifecycleActionAsync(
            registration, registration.Flow, "requestPhoneVerification", requestId, input);
        await AssertDeliveryUnavailableAsync(replay);
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        await AssertOnlyDeliveryRequestAsync(
            registration, requestId,
            AccessFlowRequestStatus.ExternalFailed, ProofChallengeStatus.DeliveryFailed);
        Assert.Equal(registration.Flow.GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertRegistrationStillPendingAsync(registration);

        var accepted = await ExecuteActionAsync(
            registration, registration.Flow, "requestPhoneVerification", input);
        Assert.Equal(2, api.PhoneSender.DeliveryAttempts.Count);
        var completed = await ExecuteActionAsync(
            registration, accepted.GetProperty("snapshot"), "confirmPhoneVerification",
            new { code = api.PhoneSender.LastCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, input.phone);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenges = await db.ProofChallenges.AsNoTracking().Where(
            item => item.AccessFlowId == registration.FlowId).ToListAsync();
        Assert.Equal(2, challenges.Count);
        Assert.Single(challenges, item => item.Status == ProofChallengeStatus.DeliveryFailed);
        Assert.Single(challenges, item => item.Status == ProofChallengeStatus.Verified);
        var originalRequest = await db.AccessFlowRequests.AsNoTracking().SingleAsync(
            item => item.RequestId == requestId);
        Assert.Equal(AccessFlowRequestStatus.ExternalFailed, originalRequest.Status);
        Assert.Null(originalRequest.ResultRevision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Expire_PendingSmsThroughGetOrActionCannotBeRevivedByLateDelivery(bool expireByAction)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"pending-expiry-{Guid.NewGuid():N}@example.com");
        var requestId = Guid.NewGuid();
        var input = new { phone = "+5511987654342" };
        var gate = new AsyncOperationGate();
        api.PhoneSender.SendGate = gate;
        var deliveryTask = PostLifecycleActionAsync(
            registration, registration.Flow, "requestPhoneVerification", requestId, input);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        JsonElement expired;
        try
        {
            await gate.WaitUntilEnteredAsync(deadline.Token);
            await AssertOnlyDeliveryRequestAsync(
                registration, requestId,
                AccessFlowRequestStatus.PendingExternal, ProofChallengeStatus.PendingDelivery);
            clock.Advance(FlowDuration);

            using var response = expireByAction
                ? await PostLifecycleActionAsync(
                    registration, registration.Flow, "skipRegistration", Guid.NewGuid())
                    .WaitAsync(deadline.Token)
                : await SendWithCapabilityAsync(
                    HttpMethod.Get, $"/v1/access/flows/{registration.FlowId:D}",
                    registration.Capability, null).WaitAsync(deadline.Token);
            var body = await ReadSuccessfulResponseAsync(response);
            Assert.Equal(JsonValueKind.Null, body.GetProperty("issuedSession").ValueKind);
            expired = body.GetProperty("snapshot");
            AssertExpiredSnapshot(expired, revision: 2);
            await AssertOnlyDeliveryRequestAsync(
                registration, requestId,
                AccessFlowRequestStatus.ExternalFailed, ProofChallengeStatus.DeliveryFailed);
            await AssertRegistrationStillPendingAsync(registration);
        }
        finally
        {
            gate.Release();
            api.PhoneSender.SendGate = null;
        }

        using var late = await deliveryTask.WaitAsync(TimeSpan.FromSeconds(10));
        await AssertDeliveryUnavailableAsync(late);
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.NotNull(Assert.Single(api.PhoneSender.CancellationAttempts));
        using var replay = await PostLifecycleActionAsync(
            registration, registration.Flow, "requestPhoneVerification", requestId, input);
        await AssertDeliveryUnavailableAsync(replay);
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Single(api.PhoneSender.CancellationAttempts);
        Assert.Equal(expired.GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        await AssertFlowPersistenceAsync(registration, AccessFlowStatus.Expired, revision: 2);
        await AssertOnlyDeliveryRequestAsync(
            registration, requestId,
            AccessFlowRequestStatus.ExternalFailed, ProofChallengeStatus.DeliveryFailed);
        await AssertRegistrationStillPendingAsync(registration);

        using var restarted = await StartFlowAsync(
            "continueRegistration", registration.SourceSessionToken);
        var replacement = await ReadStartedFlowAsync(
            restarted, registration.IdentityId, registration.SourceSessionToken);
        Assert.NotEqual(registration.FlowId, replacement.FlowId);
        var completed = await ExecuteActionAsync(
            replacement, replacement.Flow, "skipRegistration");
        await AssertSingleProductSessionAsync(registration, completed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SkipRegistration_ConcurrentRequestsCommitOnlyOneSession(bool sameRequestId)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"concurrent-completion-{Guid.NewGuid():N}@example.com");
        var firstRequestId = Guid.NewGuid();
        var secondRequestId = sameRequestId ? firstRequestId : Guid.NewGuid();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var blocker = new NpgsqlConnection(database.ConnectionString);
        await blocker.OpenAsync(deadline.Token);
        await using var transaction = await blocker.BeginTransactionAsync(deadline.Token);
        await using (var command = blocker.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT id FROM identities WHERE id = @identityId FOR UPDATE";
            command.Parameters.AddWithValue("identityId", registration.IdentityId);
            await command.ExecuteScalarAsync(deadline.Token);
        }

        var firstTask = PostLifecycleActionAsync(
            registration, registration.Flow, "skipRegistration", firstRequestId);
        var secondTask = PostLifecycleActionAsync(
            registration, registration.Flow, "skipRegistration", secondRequestId);
        try
        {
            // Both requests must reach the transaction after accepting the same snapshot.
            await WaitForBlockedFlowCompletionsAsync(deadline.Token);
            Assert.False(firstTask.IsCompleted);
            Assert.False(secondTask.IsCompleted);
        }
        finally
        {
            await transaction.RollbackAsync(CancellationToken.None);
        }

        using var first = await firstTask.WaitAsync(TimeSpan.FromSeconds(10));
        using var second = await secondTask.WaitAsync(TimeSpan.FromSeconds(10));
        var winnerIsFirst = first.StatusCode == HttpStatusCode.OK;
        var accepted = await ReadSuccessfulResponseAsync(winnerIsFirst ? first : second);
        var other = winnerIsFirst ? second : first;
        if (sameRequestId)
        {
            Assert.Equal(accepted.GetRawText(),
                (await ReadSuccessfulResponseAsync(other)).GetRawText());
        }
        else
        {
            await AssertFlowErrorAsync(other, "revision-conflict", "expectedRevision");
        }

        await AssertSingleProductSessionAsync(registration, accepted);
        await AssertFlowPersistenceAsync(registration, AccessFlowStatus.Completed, revision: 2);
        var winnerRequestId = winnerIsFirst ? firstRequestId : secondRequestId;
        var replayed = await ExecuteActionAsync(
            registration, registration.Flow, "skipRegistration", requestId: winnerRequestId);
        Assert.Equal(accepted.GetRawText(), replayed.GetRawText());
        await AssertSingleProductSessionAsync(registration, replayed);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var request = Assert.Single(await db.AccessFlowRequests.AsNoTracking().Where(
            item => item.FlowId == registration.FlowId
                && item.Kind == AccessFlowRequestKind.Action).ToListAsync());
        Assert.Equal(winnerRequestId, request.RequestId);
        Assert.Equal(AccessFlowRequestStatus.Committed, request.Status);
        Assert.Equal(2, request.ResultRevision);
        Assert.Equal(accepted.GetProperty("issuedSession").GetProperty("sessionId").GetGuid(),
            request.IssuedSessionId);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task ManagePhone_ExpirationPreservesTheOldPhoneAndSessionUntilANewFlowCompletes(
        bool expireByAction,
        bool verifyPhone)
    {
        const string oldPhone = "+15555550123";
        const string newPhone = "+5511987654343";
        var registration = await RegisterAndStartFlowAsync(
            $"manage-expiry-{Guid.NewGuid():N}@example.com");
        var initialVerification = await RequestPhoneAsync(
            registration.Flow, registration.Capability, oldPhone);
        var registered = await ExecuteActionAsync(
            registration, initialVerification, "confirmPhoneVerification", new { code = "123456" });
        var sourceToken = registered.GetProperty("issuedSession").GetProperty("sessionToken").GetString()!;
        var sourceSessionId = registered.GetProperty("issuedSession").GetProperty("sessionId").GetGuid();
        await AssertSingleProductSessionAsync(registration, registered);
        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneVerificationEnabled: verifyPhone));
        using var start = await StartFlowAsync("managePhone", sourceToken);
        var managed = await ReadStartedFlowAsync(start, registration.IdentityId, sourceToken);
        var snapshot = managed.Flow;
        var actionType = "submitPhone";
        object input = new { phone = newPhone };
        if (verifyPhone)
        {
            // A code requested near the deadline is capped by the flow's own expiration.
            clock.Advance(FlowDuration - TimeSpan.FromMinutes(1));
            snapshot = await RequestPhoneAsync(snapshot, managed.Capability, newPhone);
            input = new { code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code };
            actionType = "confirmPhoneVerification";
            await using var scope = api.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var challenge = await db.ProofChallenges.AsNoTracking().SingleAsync(
                item => item.AccessFlowId == managed.FlowId);
            Assert.Equal(managed.Flow.GetProperty("expiresAt").GetDateTimeOffset(), challenge.ExpiresAt);
            clock.Advance(TimeSpan.FromMinutes(1));
        }
        else
        {
            clock.Advance(FlowDuration);
        }

        using var expiredResponse = expireByAction
            ? await PostLifecycleActionAsync(managed, snapshot, actionType, Guid.NewGuid(), input)
            : await SendWithCapabilityAsync(
                HttpMethod.Get, $"/v1/access/flows/{managed.FlowId:D}", managed.Capability, null);
        var expired = await ReadSuccessfulResponseAsync(expiredResponse);
        AssertExpiredSnapshot(expired.GetProperty("snapshot"), verifyPhone ? 3 : 2);
        Assert.Equal(JsonValueKind.Null, expired.GetProperty("issuedSession").ValueKind);
        using var oldAction = await PostLifecycleActionAsync(
            managed, snapshot, actionType, Guid.NewGuid(), input);
        await AssertFlowErrorAsync(oldAction, "action-not-available", "action");

        await AssertVerifiedPhoneAsync(registration.IdentityId, oldPhone);
        await AssertSingleProductSessionAsync(registration, registered);
        var oldSession = await IntrospectFlowSessionAsync(sourceToken);
        Assert.True(oldSession.GetProperty("active").GetBoolean());
        Assert.Equal(oldPhone, oldSession.GetProperty("phone").GetString());
        await AssertFlowPersistenceAsync(managed, AccessFlowStatus.Expired, verifyPhone ? 3 : 2);
        Assert.Equal(verifyPhone ? 1 : 0, api.PhoneSender.DeliveryAttempts.Count);

        using var restart = await StartFlowAsync("managePhone", sourceToken);
        var replacement = await ReadStartedFlowAsync(restart, registration.IdentityId, sourceToken);
        Assert.NotEqual(managed.FlowId, replacement.FlowId);
        JsonElement completed;
        if (verifyPhone)
        {
            var newVerification = await RequestPhoneAsync(replacement.Flow, replacement.Capability, newPhone);
            completed = await ExecuteActionAsync(
                replacement, newVerification, "confirmPhoneVerification",
                new { code = api.PhoneSender.LastCode });
            await AssertVerifiedPhoneAsync(registration.IdentityId, newPhone);
        }
        else
        {
            completed = await ExecuteActionAsync(
                replacement, replacement.Flow, "submitPhone", new { phone = newPhone });
        }
        Assert.Equal("completed", completed.GetProperty("snapshot").GetProperty("status").GetString());
        var issued = completed.GetProperty("issuedSession");
        Assert.NotEqual(sourceSessionId, issued.GetProperty("sessionId").GetGuid());
        Assert.Equal(registration.IdentityId, issued.GetProperty("identityId").GetGuid());
        Assert.Equal("product", issued.GetProperty("purpose").GetString());
        Assert.False((await IntrospectFlowSessionAsync(sourceToken)).GetProperty("active").GetBoolean());
        var newSession = await IntrospectFlowSessionAsync(issued.GetProperty("sessionToken").GetString()!);
        Assert.True(newSession.GetProperty("active").GetBoolean());
        Assert.Equal(newPhone, newSession.GetProperty("phone").GetString());
        Assert.Equal(verifyPhone ? 2 : 0, api.PhoneSender.DeliveryAttempts.Count);
        await using var finalScope = api.Services.CreateAsyncScope();
        var finalDb = finalScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var sessions = await finalDb.IdentitySessions.AsNoTracking().Where(
            item => item.IdentityId == registration.IdentityId).ToListAsync();
        Assert.Equal(3, sessions.Count);
        Assert.Equal(issued.GetProperty("sessionId").GetGuid(),
            Assert.Single(sessions, item => item.RevokedAt is null).Id);
        var phone = await finalDb.IdentityIdentifiers.AsNoTracking().SingleAsync(
            item => item.IdentityId == registration.IdentityId && item.Scheme == IdentifierScheme.Phone);
        Assert.Equal(newPhone, phone.NormalizedValue);
        if (!verifyPhone)
        {
            Assert.Null(phone.VerifiedAt);
            Assert.Null(phone.VerificationMethod);
        }
    }

    private async Task<JsonElement> IntrospectFlowSessionAsync(string token)
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect", new { sessionToken = token });
        return await ReadSuccessfulResponseAsync(response);
    }

    private static async Task AssertDeliveryUnavailableAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("verification-delivery-unavailable", body.RootElement.GetProperty("error").GetString());
        Assert.False(body.RootElement.TryGetProperty("issuedSession", out _));
    }

    private async Task AssertOnlyDeliveryRequestAsync(
        StartedRegistration registration,
        Guid requestId,
        AccessFlowRequestStatus requestStatus,
        ProofChallengeStatus challengeStatus)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var request = Assert.Single(await db.AccessFlowRequests.AsNoTracking().Where(
            item => item.FlowId == registration.FlowId && item.Kind == AccessFlowRequestKind.Action)
            .ToListAsync());
        Assert.Equal(requestId, request.RequestId);
        Assert.Equal(requestStatus, request.Status);
        Assert.Null(request.IssuedSessionId);
        Assert.Equal(requestStatus == AccessFlowRequestStatus.Committed ? 2 : (int?)null,
            request.ResultRevision);
        var challenge = await db.ProofChallenges.AsNoTracking().SingleAsync(
            item => item.AccessFlowId == registration.FlowId);
        Assert.Equal(challengeStatus, challenge.Status);
        Assert.Equal(challengeStatus == ProofChallengeStatus.DeliveryFailed,
            challenge.CompletedAt is not null);
        Assert.Empty(await db.ProofAttempts.ToListAsync());
        Assert.Empty(await db.IdentityProofs.ToListAsync());
    }

    private async Task WaitForBlockedFlowCompletionsAsync(CancellationToken cancellationToken)
    {
        await using var observer = new NpgsqlConnection(database.ConnectionString);
        await observer.OpenAsync(cancellationToken);
        while (true)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT count(*) FROM pg_stat_activity
                WHERE datname = current_database()
                  AND pid <> pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND query ILIKE '%FROM identities%'
                  AND query ILIKE '%FOR UPDATE%';
                """;
            if (Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken)) >= 2)
            {
                return;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken);
        }
    }
}
