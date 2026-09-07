using System.Net;
using System.Text.Json;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed partial class AccessFlowEndpointTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t ")]
    public async Task ConfirmPhone_MissingCodeDoesNotSpendAnAttemptAndAllowsPastingTheValidCode(string? code)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"missing-phone-code-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654350";
        var verification = await RequestPhoneAsync(registration.Flow, registration.Capability, phone);
        var original = Assert.Single(await ReadFlowChallengesAsync(registration));

        var rejected = await ExecuteActionAsync(
            registration, verification, "confirmPhoneVerification", new { code });
        AssertPhoneFeedback(rejected, "missing-code", "verifyPhone");
        var unchanged = Assert.Single(await ReadFlowChallengesAsync(registration));
        Assert.Equal(original.Id, unchanged.Id);
        Assert.Equal(0, unchanged.Attempts);
        Assert.Equal(ProofChallengeStatus.Active, unchanged.Status);
        Assert.Equal(original.ExpiresAt, unchanged.ExpiresAt);
        await AssertNoPhoneProofAsync(registration, failedAttempts: 0);

        var completed = await ExecuteActionAsync(
            registration, rejected.GetProperty("snapshot"), "confirmPhoneVerification",
            new { code = $" \t{Assert.Single(api.PhoneSender.DeliveryAttempts).Code} " });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
        await AssertSuccessfulPhoneProofAsync(registration, original.Id, failedAttempts: 0);
        Assert.Single(api.PhoneSender.DeliveryAttempts);
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    public async Task ConfirmPhone_CorrectCodeOnlyWorksBeforeItsOwnDeadline(
        int secondsFromDeadline, bool expired)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"phone-code-expiry-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654351";
        var verification = await RequestPhoneAsync(registration.Flow, registration.Capability, phone);
        var original = Assert.Single(await ReadFlowChallengesAsync(registration));
        clock.Advance(original.ExpiresAt - clock.GetUtcNow() + TimeSpan.FromSeconds(secondsFromDeadline));
        Assert.True(clock.GetUtcNow() < registration.Flow.GetProperty("expiresAt").GetDateTimeOffset());

        var result = await ExecuteActionAsync(
            registration, verification, "confirmPhoneVerification",
            new { code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code });
        if (!expired)
        {
            await AssertSingleProductSessionAsync(registration, result);
            await AssertSuccessfulPhoneProofAsync(registration, original.Id, failedAttempts: 0);
        }
        else
        {
            AssertPhoneFeedback(result, "phone-verification-no-active-code", "collectPhone");
            await AssertNoPhoneProofAsync(registration, failedAttempts: 0);
            Assert.Single(api.PhoneSender.DeliveryAttempts);
            var freshVerification = await RequestPhoneAsync(
                result.GetProperty("snapshot"), registration.Capability, phone);
            var challenges = await ReadFlowChallengesAsync(registration);
            Assert.Equal(2, challenges.Count);
            Assert.Equal(ProofChallengeStatus.Superseded,
                Assert.Single(challenges, item => item.Id == original.Id).Status);
            var replacement = Assert.Single(challenges, item => item.Status == ProofChallengeStatus.Active);
            var completed = await ExecuteActionAsync(
                registration, freshVerification, "confirmPhoneVerification",
                new { code = api.PhoneSender.LastCode });
            await AssertSingleProductSessionAsync(registration, completed);
            await AssertSuccessfulPhoneProofAsync(registration, replacement.Id, failedAttempts: 0);
            Assert.Equal(2, api.PhoneSender.DeliveryAttempts.Count);
        }
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
    }

    [Fact]
    public async Task ResendPhone_ExpiredCodeReturnsToPhoneCollectionWithoutSendingAnotherSms()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"resend-expired-code-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654352";
        var verification = await RequestPhoneAsync(registration.Flow, registration.Capability, phone);
        var original = Assert.Single(await ReadFlowChallengesAsync(registration));
        clock.Advance(original.ExpiresAt - clock.GetUtcNow());

        var result = await ExecuteActionAsync(registration, verification, "resendPhoneVerification");
        AssertPhoneFeedback(result, "phone-verification-no-active-code", "collectPhone");
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Single(await ReadFlowChallengesAsync(registration));
        await AssertNoPhoneProofAsync(registration, failedAttempts: 0);

        var freshVerification = await RequestPhoneAsync(
            result.GetProperty("snapshot"), registration.Capability, phone);
        var completed = await ExecuteActionAsync(
            registration, freshVerification, "confirmPhoneVerification",
            new { code = api.PhoneSender.LastCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
        var replacement = Assert.Single(await ReadFlowChallengesAsync(registration),
            item => item.Status == ProofChallengeStatus.Verified);
        Assert.NotEqual(original.Id, replacement.Id);
        await AssertSuccessfulPhoneProofAsync(registration, replacement.Id, failedAttempts: 0);
        Assert.Equal(2, api.PhoneSender.DeliveryAttempts.Count);
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    public async Task ResendPhone_OnlySendsAgainAtOrAfterTheCooldown(
        int secondsFromCooldown, bool allowed)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"resend-cooldown-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654353";
        var verification = await RequestPhoneAsync(registration.Flow, registration.Capability, phone);
        var original = Assert.Single(await ReadFlowChallengesAsync(registration));
        clock.Advance(original.ResendAvailableAt - clock.GetUtcNow()
            + TimeSpan.FromSeconds(secondsFromCooldown));
        var requestId = Guid.NewGuid();

        var result = await ExecuteActionAsync(
            registration, verification, "resendPhoneVerification", requestId: requestId);
        var challenges = await ReadFlowChallengesAsync(registration);
        Guid expectedChallengeId;
        if (!allowed)
        {
            AssertPhoneFeedback(result, "phone-verification-resend-too-soon", "verifyPhone");
            Assert.Equal(original.ResendAvailableAt,
                result.GetProperty("snapshot").GetProperty("feedback").GetProperty("retryAt").GetDateTimeOffset());
            var unchanged = Assert.Single(challenges);
            Assert.Equal(original.Id, unchanged.Id);
            Assert.Equal(original.ExpiresAt, unchanged.ExpiresAt);
            Assert.Equal(original.ResendAvailableAt, unchanged.ResendAvailableAt);
            expectedChallengeId = original.Id;
        }
        else
        {
            Assert.Equal(2, challenges.Count);
            var superseded = Assert.Single(challenges, item => item.Id == original.Id);
            Assert.Equal(ProofChallengeStatus.Superseded, superseded.Status);
            var replacement = Assert.Single(challenges, item => item.Status == ProofChallengeStatus.Active);
            Assert.Equal(phone, replacement.DestinationValue);
            expectedChallengeId = replacement.Id;
        }
        Assert.Equal(allowed ? 2 : 1, api.PhoneSender.DeliveryAttempts.Count);
        await AssertNoPhoneProofAsync(registration, failedAttempts: 0);

        var replay = await ExecuteActionAsync(
            registration, verification, "resendPhoneVerification", requestId: requestId);
        Assert.Equal(result.GetRawText(), replay.GetRawText());
        Assert.Equal(allowed ? 2 : 1, api.PhoneSender.DeliveryAttempts.Count);
        var completed = await ExecuteActionAsync(
            registration, result.GetProperty("snapshot"), "confirmPhoneVerification",
            new { code = api.PhoneSender.LastCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
        await AssertSuccessfulPhoneProofAsync(registration, expectedChallengeId, failedAttempts: 0);
    }

    [Fact]
    public async Task ResendPhone_DeliveryFailurePreservesThePreviousCodeAndItsRemainingAttempts()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"resend-failure-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654354";
        var verification = await RequestPhoneAsync(registration.Flow, registration.Capability, phone);
        var originalCode = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        var wrongCode = originalCode == "000000" ? "000001" : "000000";
        var failedAttempt = await ExecuteActionAsync(
            registration, verification, "confirmPhoneVerification", new { code = wrongCode });
        verification = failedAttempt.GetProperty("snapshot");
        var original = Assert.Single(await ReadFlowChallengesAsync(registration));
        Assert.Equal(1, original.Attempts);
        clock.Advance(original.ResendAvailableAt - clock.GetUtcNow());
        api.PhoneSender.RejectDelivery = true;

        using var failed = await PostLifecycleActionAsync(
            registration, verification, "resendPhoneVerification", Guid.NewGuid());
        await AssertDeliveryUnavailableAsync(failed);
        api.PhoneSender.RejectDelivery = false;
        Assert.Equal(verification.GetRawText(),
            (await GetFlowSnapshotAsync(registration)).GetRawText());
        var challenges = await ReadFlowChallengesAsync(registration);
        Assert.Equal(2, challenges.Count);
        var active = Assert.Single(challenges, item => item.Status == ProofChallengeStatus.Active);
        Assert.Equal(original.Id, active.Id);
        Assert.Equal(1, active.Attempts);
        Assert.Equal(original.ExpiresAt, active.ExpiresAt);
        Assert.Single(challenges, item => item.Status == ProofChallengeStatus.DeliveryFailed);
        await AssertNoPhoneProofAsync(registration, failedAttempts: 1);

        var completed = await ExecuteActionAsync(
            registration, verification, "confirmPhoneVerification", new { code = originalCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
        await AssertSuccessfulPhoneProofAsync(registration, original.Id, failedAttempts: 1);
        Assert.Equal(2, api.PhoneSender.DeliveryAttempts.Count);
    }

    [Fact]
    public async Task ConfirmPhone_FifthWrongCodeExhaustsTheChallengeAndReplayDoesNotSpendAnotherAttempt()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"phone-attempt-limit-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654355";
        var snapshot = await RequestPhoneAsync(registration.Flow, registration.Capability, phone);
        var original = Assert.Single(await ReadFlowChallengesAsync(registration));
        var originalCode = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        var wrongCode = originalCode == "000000" ? "000001" : "000000";
        var fifthRequestId = Guid.NewGuid();
        JsonElement beforeFifth = default;
        JsonElement fifth = default;
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var before = snapshot;
            var result = await ExecuteActionAsync(
                registration, before, "confirmPhoneVerification", new { code = wrongCode },
                attempt == 5 ? fifthRequestId : Guid.NewGuid());
            AssertPhoneFeedback(result,
                attempt == 5 ? "phone-verification-too-many-attempts" : "phone-verification-invalid-code",
                attempt == 5 ? "collectPhone" : "verifyPhone");
            var challenge = Assert.Single(await ReadFlowChallengesAsync(registration));
            Assert.Equal(attempt, challenge.Attempts);
            Assert.Equal(attempt == 5 ? ProofChallengeStatus.Exhausted : ProofChallengeStatus.Active,
                challenge.Status);
            snapshot = result.GetProperty("snapshot");
            if (attempt == 5)
            {
                beforeFifth = before;
                fifth = result;
            }
        }

        var replay = await ExecuteActionAsync(
            registration, beforeFifth, "confirmPhoneVerification", new { code = wrongCode }, fifthRequestId);
        Assert.Equal(fifth.GetRawText(), replay.GetRawText());
        await AssertNoPhoneProofAsync(registration, failedAttempts: 5);
        Assert.Equal(5, Assert.Single(await ReadFlowChallengesAsync(registration)).Attempts);
        Assert.DoesNotContain("confirmPhoneVerification", ActionTypes(snapshot));

        using var exhaustedCode = await SendWithCapabilityAsync(
            HttpMethod.Post, $"/v1/access/flows/{registration.FlowId:D}/actions", registration.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = snapshot.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(beforeFifth, "confirmPhoneVerification").GetProperty("id").GetGuid(),
                    type = "confirmPhoneVerification",
                    input = new { code = originalCode },
                },
            });
        await AssertFlowErrorAsync(exhaustedCode, "action-not-available", "action");
        await AssertNoPhoneProofAsync(registration, failedAttempts: 5);

        var freshVerification = await RequestPhoneAsync(snapshot, registration.Capability, phone);
        var replacement = Assert.Single(await ReadFlowChallengesAsync(registration),
            item => item.Status == ProofChallengeStatus.Active);
        var completed = await ExecuteActionAsync(
            registration, freshVerification, "confirmPhoneVerification", new { code = api.PhoneSender.LastCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
        await AssertSuccessfulPhoneProofAsync(registration, replacement.Id, failedAttempts: 5);
        var exhausted = Assert.Single(await ReadFlowChallengesAsync(registration), item => item.Id == original.Id);
        Assert.Equal(ProofChallengeStatus.Exhausted, exhausted.Status);
        Assert.Equal(5, exhausted.Attempts);
        Assert.Equal(2, api.PhoneSender.DeliveryAttempts.Count);
    }

    [Fact]
    public async Task PhoneRequestLimit_BlocksTheSixthSmsWhileKeepingTheFifthCodeUsable()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"phone-request-limit-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654356";
        var verification = await RequestFivePhoneCodesAsync(registration, phone);
        var active = Assert.Single(await ReadFlowChallengesAsync(registration),
            item => item.Status == ProofChallengeStatus.Active);
        clock.Advance(active.ResendAvailableAt - clock.GetUtcNow());

        var limited = await ExecuteActionAsync(registration, verification, "resendPhoneVerification");
        AssertPhoneFeedback(limited, "phone-verification-rate-limited", "verifyPhone");
        Assert.Equal(5, api.PhoneSender.DeliveryAttempts.Count);
        Assert.Equal(5, (await ReadFlowChallengesAsync(registration)).Count);
        var preserved = Assert.Single(await ReadFlowChallengesAsync(registration),
            item => item.Status == ProofChallengeStatus.Active);
        Assert.Equal(active.Id, preserved.Id);
        Assert.Equal(active.ExpiresAt, preserved.ExpiresAt);
        await AssertNoPhoneProofAsync(registration, failedAttempts: 0);

        var completed = await ExecuteActionAsync(
            registration, limited.GetProperty("snapshot"), "confirmPhoneVerification",
            new { code = api.PhoneSender.LastCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, phone);
        await AssertSuccessfulPhoneProofAsync(registration, active.Id, failedAttempts: 0);
        Assert.Equal(5, api.PhoneSender.DeliveryAttempts.Count);
    }

    [Fact]
    public async Task PhoneRequestLimit_SurvivesPhoneChangesAndFlowRestartsUntilTheOldestRequestLeavesTheWindow()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"phone-quota-restart-{Guid.NewGuid():N}@example.com");
        var firstRequestAt = clock.GetUtcNow();
        const string newPhone = "+5511987654358";
        var verification = await RequestFivePhoneCodesAsync(registration, "+5511987654357");
        var changed = await ExecuteActionAsync(registration, verification, "changePhone");
        var limited = await ExecuteActionAsync(
            registration, changed.GetProperty("snapshot"), "requestPhoneVerification", new { phone = newPhone });
        AssertPhoneFeedback(limited, "phone-verification-rate-limited", "collectPhone");
        Assert.Equal(5, api.PhoneSender.DeliveryAttempts.Count);
        await AssertNoPhoneProofAsync(registration, failedAttempts: 0);

        clock.Advance(registration.Flow.GetProperty("expiresAt").GetDateTimeOffset() - clock.GetUtcNow());
        using var restarted = await StartFlowAsync("continueRegistration", registration.SourceSessionToken);
        var replacement = await ReadStartedFlowAsync(
            restarted, registration.IdentityId, registration.SourceSessionToken);
        Assert.NotEqual(registration.FlowId, replacement.FlowId);
        var stillLimited = await ExecuteActionAsync(
            replacement, replacement.Flow, "requestPhoneVerification", new { phone = newPhone });
        AssertPhoneFeedback(stillLimited, "phone-verification-rate-limited", "collectPhone");
        Assert.Empty(await ReadFlowChallengesAsync(replacement));
        Assert.Equal(5, api.PhoneSender.DeliveryAttempts.Count);

        // The rolling window includes a request made exactly one hour ago.
        clock.Advance(firstRequestAt.AddHours(1) - clock.GetUtcNow());
        using var nextStart = await StartFlowAsync("continueRegistration", registration.SourceSessionToken);
        var next = await ReadStartedFlowAsync(nextStart, registration.IdentityId, registration.SourceSessionToken);
        Assert.NotEqual(replacement.FlowId, next.FlowId);
        var boundary = await ExecuteActionAsync(
            next, next.Flow, "requestPhoneVerification", new { phone = newPhone });
        AssertPhoneFeedback(boundary, "phone-verification-rate-limited", "collectPhone");
        Assert.Empty(await ReadFlowChallengesAsync(next));
        Assert.Equal(5, api.PhoneSender.DeliveryAttempts.Count);

        clock.Advance(TimeSpan.FromSeconds(1));
        var freshVerification = await RequestPhoneAsync(
            boundary.GetProperty("snapshot"), next.Capability, newPhone);
        Assert.Equal(6, api.PhoneSender.DeliveryAttempts.Count);
        var completed = await ExecuteActionAsync(
            next, freshVerification, "confirmPhoneVerification", new { code = api.PhoneSender.LastCode });
        await AssertSingleProductSessionAsync(registration, completed);
        await AssertVerifiedPhoneAsync(registration.IdentityId, newPhone);
        var challenge = Assert.Single(await ReadFlowChallengesAsync(next));
        await AssertSuccessfulPhoneProofAsync(next, challenge.Id, failedAttempts: 0);
    }

    private async Task<JsonElement> RequestFivePhoneCodesAsync(StartedRegistration registration, string phone)
    {
        var snapshot = await RequestPhoneAsync(registration.Flow, registration.Capability, phone);
        for (var count = 2; count <= 5; count++)
        {
            clock.Advance(TimeSpan.FromSeconds(TestEnvironmentConfigurations.VerificationPolicy.ResendCooldownSeconds));
            var result = await ExecuteActionAsync(registration, snapshot, "resendPhoneVerification");
            snapshot = result.GetProperty("snapshot");
            Assert.Equal("verifyPhone", snapshot.GetProperty("step").GetProperty("type").GetString());
            Assert.Equal(count, api.PhoneSender.DeliveryAttempts.Count);
        }
        return snapshot;
    }

    private async Task<List<ProofChallenge>> ReadFlowChallengesAsync(StartedRegistration registration)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        return await db.ProofChallenges.AsNoTracking().Where(
            item => item.AccessFlowId == registration.FlowId).ToListAsync();
    }

    private static void AssertPhoneFeedback(JsonElement response, string code, string step)
    {
        var snapshot = response.GetProperty("snapshot");
        Assert.Equal("active", snapshot.GetProperty("status").GetString());
        Assert.Equal(code, snapshot.GetProperty("feedback").GetProperty("code").GetString());
        Assert.Equal(step, snapshot.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(JsonValueKind.Null, response.GetProperty("issuedSession").ValueKind);
    }

    private async Task AssertNoPhoneProofAsync(StartedRegistration registration, int failedAttempts)
    {
        await AssertRegistrationStillPendingAsync(registration);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Empty(await db.IdentityProofs.Where(item => item.IdentityId == registration.IdentityId).ToListAsync());
        var attempts = await db.ProofAttempts.ToListAsync();
        Assert.Equal(failedAttempts, attempts.Count);
        Assert.All(attempts, item => Assert.Equal(ProofAttemptOutcome.Failed, item.Outcome));
    }

    private async Task AssertSuccessfulPhoneProofAsync(
        StartedRegistration registration, Guid challengeId, int failedAttempts)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var proof = await db.IdentityProofs.AsNoTracking().SingleAsync(
            item => item.IdentityId == registration.IdentityId);
        Assert.Equal(challengeId, proof.ChallengeId);
        Assert.Equal(registration.FlowId, proof.AccessFlowId);
        var attempts = await db.ProofAttempts.AsNoTracking().ToListAsync();
        Assert.Equal(failedAttempts + 1, attempts.Count);
        Assert.Equal(failedAttempts, attempts.Count(item => item.Outcome == ProofAttemptOutcome.Failed));
        Assert.Equal(challengeId, Assert.Single(attempts,
            item => item.Outcome == ProofAttemptOutcome.Succeeded).ChallengeId);
        Assert.Equal(ProofChallengeStatus.Verified,
            (await db.ProofChallenges.AsNoTracking().SingleAsync(item => item.Id == challengeId)).Status);
    }
}
