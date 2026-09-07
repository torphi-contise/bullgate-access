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
    private const string ManagedOldPhone = "+5511987654380";
    private const string ManagedConflictingPhone = "+15555550123";
    private const string ManagedAlternativePhone = "+5511987654381";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ManagePhone_SubmittingTheCurrentPhoneKeepsItsIdentifierAndRotatesOnlyTheSourceSession(
        bool alreadyVerified)
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneRequired: true,
            phoneVerificationEnabled: alreadyVerified));
        var registration = await RegisterAndStartFlowAsync(
            $"managed-own-phone-{Guid.NewGuid():N}@example.test");
        JsonElement completedRegistration;
        if (alreadyVerified)
        {
            var verification = await RequestPhoneAsync(
                registration.Flow, registration.Capability, ManagedOldPhone);
            completedRegistration = await ExecuteActionAsync(
                registration,
                verification,
                "confirmPhoneVerification",
                new { code = api.PhoneSender.LastCode });
        }
        else
        {
            completedRegistration = await ExecuteActionAsync(
                registration,
                registration.Flow,
                "submitPhone",
                new { phone = ManagedOldPhone });
        }
        var sourceToken = completedRegistration.GetProperty("issuedSession")
            .GetProperty("sessionToken")
            .GetString()!;
        var before = await ReadPhoneIdentifierAsync(registration.IdentityId);
        Assert.Equal(alreadyVerified, before.VerifiedAt is not null);
        var recovery = await SeedActiveRecoveryArtifactsAsync(
            registration.IdentityId, ManagedOldPhone);
        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneRequired: true));
        using var started = await StartFlowAsync("managePhone", sourceToken);
        var managed = await ReadStartedFlowAsync(
            started, registration.IdentityId, sourceToken);
        var verificationSnapshot = await RequestPhoneAsync(
            managed.Flow, managed.Capability, ManagedOldPhone);
        var requestId = Guid.NewGuid();

        var completed = await ExecuteActionAsync(
            managed,
            verificationSnapshot,
            "confirmPhoneVerification",
            new { code = api.PhoneSender.LastCode },
            requestId);

        Assert.Equal(
            "phoneVerified",
            completed.GetProperty("snapshot")
                .GetProperty("result")
                .GetProperty("outcome")
                .GetString());
        var after = await ReadPhoneIdentifierAsync(registration.IdentityId);
        Assert.Equal(before.Id, after.Id);
        Assert.NotNull(after.VerifiedAt);
        Assert.Equal("sms", after.VerificationMethod);
        if (alreadyVerified)
        {
            Assert.Equal(before.VerifiedAt, after.VerifiedAt);
        }
        Assert.False((await IntrospectFlowSessionAsync(sourceToken))
            .GetProperty("active").GetBoolean());
        var issued = completed.GetProperty("issuedSession");
        var replacementToken = issued.GetProperty("sessionToken").GetString()!;
        Assert.True((await IntrospectFlowSessionAsync(replacementToken))
            .GetProperty("active").GetBoolean());
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.Single(await db.IdentityIdentifiers.AsNoTracking()
                .Where(item => item.IdentityId == registration.IdentityId
                    && item.Scheme == IdentifierScheme.Phone)
                .ToListAsync());
            Assert.False(await db.PhoneRegistrationConflicts.AnyAsync());
            await AssertRecoveryArtifactsInvalidatedAsync(db, recovery);
        }
        var state = await ReadIdentityBusinessStateAsync(registration.IdentityId);
        var replay = await ExecuteActionAsync(
            managed,
            verificationSnapshot,
            "confirmPhoneVerification",
            new { code = api.PhoneSender.LastCode },
            requestId);
        Assert.Equal(completed.GetRawText(), replay.GetRawText());
        Assert.Equal(state, await ReadIdentityBusinessStateAsync(registration.IdentityId));
    }

    [Fact]
    public async Task ManagePhone_VerifiedProofMovesAnUnverifiedPhoneWithoutOpeningAConflict()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneRequired: true,
            phoneVerificationEnabled: false));
        var previous = await RegisterAndStartFlowAsync(
            $"managed-unverified-owner-{Guid.NewGuid():N}@example.test");
        var previousCompleted = await ExecuteActionAsync(
            previous,
            previous.Flow,
            "submitPhone",
            new { phone = ManagedConflictingPhone });
        var previousToken = previousCompleted.GetProperty("issuedSession")
            .GetProperty("sessionToken")
            .GetString()!;
        var previousPhone = await ReadPhoneIdentifierAsync(previous.IdentityId);
        Assert.Null(previousPhone.VerifiedAt);

        var current = await RegisterAndStartFlowAsync(
            $"managed-unverified-claimant-{Guid.NewGuid():N}@example.test");
        var currentCompleted = await ExecuteActionAsync(
            current,
            current.Flow,
            "submitPhone",
            new { phone = ManagedOldPhone });
        var currentToken = currentCompleted.GetProperty("issuedSession")
            .GetProperty("sessionToken")
            .GetString()!;
        var previousAccount = await ReadNonPhoneAccountStateAsync(previous.IdentityId);
        var currentAccount = await ReadNonPhoneAccountStateAsync(current.IdentityId);
        var previousRecovery = await SeedActiveRecoveryArtifactsAsync(
            previous.IdentityId, ManagedConflictingPhone);
        var currentRecovery = await SeedActiveRecoveryArtifactsAsync(
            current.IdentityId, ManagedOldPhone);
        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneRequired: true));
        using var started = await StartFlowAsync("managePhone", currentToken);
        var managed = await ReadStartedFlowAsync(
            started, current.IdentityId, currentToken);
        var verification = await RequestPhoneAsync(
            managed.Flow, managed.Capability, ManagedConflictingPhone);

        var completed = await ExecuteActionAsync(
            managed,
            verification,
            "confirmPhoneVerification",
            new { code = "123456" });

        Assert.Equal(
            "phoneVerified",
            completed.GetProperty("snapshot")
                .GetProperty("result")
                .GetProperty("outcome")
                .GetString());
        Assert.Equal(
            "completed",
            completed.GetProperty("snapshot").GetProperty("status").GetString());
        Assert.Equal(previousAccount, await ReadNonPhoneAccountStateAsync(previous.IdentityId));
        Assert.Equal(currentAccount, await ReadNonPhoneAccountStateAsync(current.IdentityId));
        var transferred = await ReadPhoneIdentifierAsync(current.IdentityId);
        Assert.Equal(previousPhone.Id, transferred.Id);
        Assert.NotNull(transferred.VerifiedAt);
        Assert.Equal("sms", transferred.VerificationMethod);
        Assert.True((await IntrospectFlowSessionAsync(previousToken))
            .GetProperty("active").GetBoolean());
        Assert.False((await IntrospectFlowSessionAsync(currentToken))
            .GetProperty("active").GetBoolean());
        var issued = completed.GetProperty("issuedSession");
        Assert.True((await IntrospectFlowSessionAsync(
            issued.GetProperty("sessionToken").GetString()!))
            .GetProperty("active").GetBoolean());
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await db.IdentityIdentifiers.AnyAsync(
            item => item.IdentityId == previous.IdentityId
                && item.Scheme == IdentifierScheme.Phone));
        Assert.False(await db.IdentityIdentifiers.AnyAsync(
            item => item.NormalizedValue == ManagedOldPhone));
        Assert.False(await db.PhoneRegistrationConflicts.AnyAsync());
        await AssertRecoveryArtifactsInvalidatedAsync(db, previousRecovery);
        await AssertRecoveryArtifactsInvalidatedAsync(db, currentRecovery);
        var identities = await db.Identities.AsNoTracking()
            .Where(item => item.Id == previous.IdentityId || item.Id == current.IdentityId)
            .ToListAsync();
        Assert.All(identities, item => Assert.Equal(
            IdentityLifecycleState.Active, item.LifecycleState));
    }

    [Fact]
    public async Task ManagePhoneConflict_OnlyThePreviousOwnersCurrentEmailAuthorizesTransfer()
    {
        var scenario = await CreateManagedPhoneConflictAsync();
        var oldEmail = scenario.PreviousEmail;
        var newEmail = $"managed-updated-{Guid.NewGuid():N}@example.test";
        using (var changed = await client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken = scenario.PreviousToken, email = newEmail }))
        {
            Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        }
        var previous = await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId);
        var current = await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId);

        var rejected = await ExecuteActionAsync(
            scenario.Current,
            scenario.Conflict,
            "transferPhoneToCurrentIdentity",
            new { previousEmail = oldEmail });

        AssertPhoneFeedback(
            rejected,
            "phone-conflict-email-mismatch",
            "resolvePhoneConflict");
        Assert.Equal(previous, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(current, await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId));
        await AssertManagedConflictAttemptsAsync(scenario, 1);
        var snapshot = rejected.GetProperty("snapshot");
        Assert.DoesNotContain(
            oldEmail,
            snapshot.GetProperty("step").GetProperty("previousEmailHint").GetString()!);

        var completed = await ExecuteActionAsync(
            scenario.Current,
            snapshot,
            "transferPhoneToCurrentIdentity",
            new { previousEmail = $"  {newEmail.ToUpperInvariant()}  " });
        await AssertManagedTransferCompletedAsync(scenario, snapshot, completed);
        Assert.True((await IntrospectFlowSessionAsync(scenario.PreviousToken))
            .GetProperty("active").GetBoolean());
        using var oldLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = oldEmail, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldLogin.StatusCode);
        using var newLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = newEmail, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, newLogin.StatusCode);
    }

    [Fact]
    public async Task ManagePhoneConflict_PreviousOwnerChangingPhoneInvalidatesTheOldDecision()
    {
        var scenario = await CreateManagedPhoneConflictAsync();
        var currentBefore = await ReadNonPhoneAccountStateAsync(scenario.Current.IdentityId);
        using var previousStarted = await StartFlowAsync(
            "managePhone", scenario.PreviousToken);
        var previousFlow = await ReadStartedFlowAsync(
            previousStarted,
            scenario.Previous.IdentityId,
            scenario.PreviousToken);
        var previousVerification = await RequestPhoneAsync(
            previousFlow.Flow,
            previousFlow.Capability,
            ManagedAlternativePhone);
        var previousCompleted = await ExecuteActionAsync(
            previousFlow,
            previousVerification,
            "confirmPhoneVerification",
            new { code = api.PhoneSender.LastCode });
        Assert.Equal(
            "phoneVerified",
            previousCompleted.GetProperty("snapshot")
                .GetProperty("result")
                .GetProperty("outcome")
                .GetString());
        await AssertVerifiedPhoneAsync(
            scenario.Previous.IdentityId,
            ManagedAlternativePhone);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.PhoneRegistrationConflicts.AnyAsync(
                item => item.AccessFlowId == scenario.Current.FlowId));
            Assert.False(await db.IdentityIdentifiers.AnyAsync(
                item => item.NormalizedValue == ManagedConflictingPhone));
            var proof = await db.IdentityProofs.AsNoTracking()
                .SingleAsync(item => item.AccessFlowId == scenario.Current.FlowId);
            Assert.Null(proof.SubjectIdentifierId);
        }
        Assert.Equal(currentBefore, await ReadNonPhoneAccountStateAsync(scenario.Current.IdentityId));
        Assert.True((await IntrospectFlowSessionAsync(scenario.Current.SourceSessionToken!))
            .GetProperty("active").GetBoolean());

        var staleRequestId = Guid.NewGuid();
        using var staleTransfer = await PostLifecycleActionAsync(
            scenario.Current,
            scenario.Conflict,
            "transferPhoneToCurrentIdentity",
            staleRequestId,
            new { previousEmail = scenario.PreviousEmail });
        await AssertFlowErrorAsync(staleTransfer, "action-not-available", "action");
        await AssertManagedRequestAbsentAsync(staleRequestId);
        Assert.Equal(currentBefore, await ReadNonPhoneAccountStateAsync(scenario.Current.IdentityId));

        var changed = await ExecuteActionAsync(
            scenario.Current,
            scenario.Conflict,
            "changePhone");
        Assert.Equal(
            "collectPhone",
            changed.GetProperty("snapshot")
                .GetProperty("step")
                .GetProperty("type")
                .GetString());
        Assert.Equal(["requestPhoneVerification"], ActionTypes(changed.GetProperty("snapshot")));
        Assert.True((await IntrospectFlowSessionAsync(scenario.Current.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
        await AssertManagedAccountsRemainActiveAsync(scenario);
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(true, 4)]
    public async Task ManagePhoneConflict_TransfersOnlyTheProvenPhoneAndReplaysTheSameSession(
        bool hasCurrentPhone, int failedAttemptsBeforeMatch)
    {
        var scenario = await CreateManagedPhoneConflictAsync(hasCurrentPhone: hasCurrentPhone);
        var previousAccount = await ReadNonPhoneAccountStateAsync(scenario.Previous.IdentityId);
        var currentAccount = await ReadNonPhoneAccountStateAsync(scenario.Current.IdentityId);
        var previousRecovery = await SeedActiveRecoveryArtifactsAsync(
            scenario.Previous.IdentityId, ManagedConflictingPhone);
        var currentRecovery = await SeedActiveRecoveryArtifactsAsync(
            scenario.Current.IdentityId, hasCurrentPhone ? ManagedOldPhone : ManagedConflictingPhone);
        var snapshot = scenario.Conflict;
        for (var attempt = 1; attempt <= failedAttemptsBeforeMatch; attempt++)
        {
            var mismatch = await ExecuteActionAsync(
                scenario.Current, snapshot, "transferPhoneToCurrentIdentity",
                new { previousEmail = "wrong@example.test" });
            AssertPhoneFeedback(mismatch, "phone-conflict-email-mismatch", "resolvePhoneConflict");
            snapshot = mismatch.GetProperty("snapshot");
        }
        var phoneBefore = await ReadPhoneIdentifierAsync(scenario.Previous.IdentityId);
        clock.Advance(TimeSpan.FromSeconds(1));
        var requestId = Guid.NewGuid();
        var input = new { previousEmail = $"  {scenario.PreviousEmail.ToUpperInvariant()}  " };

        var completed = await ExecuteActionAsync(
            scenario.Current, snapshot, "transferPhoneToCurrentIdentity", input, requestId);
        await AssertManagedTransferCompletedAsync(scenario, snapshot, completed);
        var assigned = await ReadPhoneIdentifierAsync(scenario.Current.IdentityId);
        Assert.Equal(phoneBefore.Id, assigned.Id);
        Assert.True(assigned.VerifiedAt > phoneBefore.VerifiedAt);
        Assert.Equal(previousAccount, await ReadNonPhoneAccountStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(currentAccount, await ReadNonPhoneAccountStateAsync(scenario.Current.IdentityId));
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await AssertRecoveryArtifactsInvalidatedAsync(db, previousRecovery);
            await AssertRecoveryArtifactsInvalidatedAsync(db, currentRecovery);
            if (hasCurrentPhone)
            {
                var previousProof = await db.IdentityProofs.AsNoTracking()
                    .SingleAsync(item => item.AccessFlowId == scenario.RegistrationFlowId);
                Assert.Null(previousProof.SubjectIdentifierId);
            }
        }
        var previousAfter = await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId);
        var currentAfter = await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId);
        var replay = await ExecuteActionAsync(
            scenario.Current, snapshot, "transferPhoneToCurrentIdentity", input, requestId);
        Assert.Equal(completed.GetRawText(), replay.GetRawText());
        Assert.Equal(previousAfter, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(currentAfter, await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-an-email")]
    [InlineData("current")]
    public async Task ManagePhoneConflict_InvalidOrCurrentAccountEmailCannotAuthorizeTransfer(
        string? submittedEmail)
    {
        var scenario = await CreateManagedPhoneConflictAsync();
        var previous = await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId);
        var current = await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId);
        var rejected = await ExecuteActionAsync(
            scenario.Current, scenario.Conflict, "transferPhoneToCurrentIdentity",
            new { previousEmail = submittedEmail == "current" ? scenario.CurrentEmail : submittedEmail });

        AssertPhoneFeedback(rejected, "phone-conflict-email-mismatch", "resolvePhoneConflict");
        Assert.Equal(previous, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(current, await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId));
        await AssertManagedConflictAttemptsAsync(scenario, 1);
        var retrySnapshot = rejected.GetProperty("snapshot");
        var corrected = await ExecuteActionAsync(
            scenario.Current, retrySnapshot, "transferPhoneToCurrentIdentity",
            new { previousEmail = scenario.PreviousEmail });
        await AssertManagedTransferCompletedAsync(scenario, retrySnapshot, corrected);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ManagePhoneConflict_FifthMismatchLeavesOnlyAnotherPhoneWithoutAbandoningTheAccount(
        bool phoneRequired)
    {
        var scenario = await CreateManagedPhoneConflictAsync(phoneRequired: phoneRequired);
        var previous = await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId);
        var current = await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId);
        var snapshot = scenario.Conflict;
        JsonElement lastInputSnapshot = default;
        JsonElement lastResponse = default;
        var lastRequestId = Guid.Empty;
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            lastInputSnapshot = snapshot;
            lastRequestId = Guid.NewGuid();
            lastResponse = await ExecuteActionAsync(
                scenario.Current, snapshot, "transferPhoneToCurrentIdentity",
                new { previousEmail = "wrong@example.test" }, lastRequestId);
            AssertPhoneFeedback(lastResponse,
                attempt == 5 ? "phone-conflict-too-many-attempts" : "phone-conflict-email-mismatch",
                "resolvePhoneConflict");
            snapshot = lastResponse.GetProperty("snapshot");
            await AssertManagedConflictAttemptsAsync(scenario, attempt);
        }
        Assert.Equal(["changePhone"], ActionTypes(snapshot));
        var replay = await ExecuteActionAsync(
            scenario.Current, lastInputSnapshot, "transferPhoneToCurrentIdentity",
            new { previousEmail = "wrong@example.test" }, lastRequestId);
        Assert.Equal(lastResponse.GetRawText(), replay.GetRawText());
        await AssertManagedConflictAttemptsAsync(scenario, 5);
        var rejectedId = Guid.NewGuid();
        using var blockedTransfer = await SendManagedActionAsync(
            scenario, snapshot, FindAction(lastInputSnapshot, "transferPhoneToCurrentIdentity"),
            "transferPhoneToCurrentIdentity", rejectedId,
            new { previousEmail = scenario.PreviousEmail });
        await AssertFlowErrorAsync(blockedTransfer, "action-not-available", "action");
        await AssertManagedRequestAbsentAsync(rejectedId);
        Assert.Equal(previous, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(current, await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId));

        var changed = await ExecuteActionAsync(scenario.Current, snapshot, "changePhone");
        var collect = changed.GetProperty("snapshot");
        Assert.Equal(["requestPhoneVerification"], ActionTypes(collect));
        Assert.Equal(previous, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(current, await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId));
        await AssertManagedConflictAbsentAsync(scenario);
        var verify = await RequestPhoneAsync(collect, scenario.Current.Capability, ManagedAlternativePhone);
        var completed = await ExecuteActionAsync(
            scenario.Current, verify, "confirmPhoneVerification", new { code = api.PhoneSender.LastCode });
        Assert.Equal("phoneVerified",
            completed.GetProperty("snapshot").GetProperty("result").GetProperty("outcome").GetString());
        await AssertVerifiedPhoneAsync(scenario.Current.IdentityId, ManagedAlternativePhone);
        Assert.Equal(previous, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.False((await IntrospectFlowSessionAsync(scenario.Current.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
        var issued = completed.GetProperty("issuedSession");
        var session = await IntrospectFlowSessionAsync(issued.GetProperty("sessionToken").GetString()!);
        Assert.True(session.GetProperty("active").GetBoolean());
        Assert.Equal(scenario.Current.IdentityId, session.GetProperty("identityId").GetGuid());
        await AssertManagedAccountsRemainActiveAsync(scenario);
    }

    [Theory]
    [InlineData("recoverPreviousIdentity", false)]
    [InlineData("recoverPreviousIdentity", true)]
    [InlineData("skipRegistration", false)]
    [InlineData("skipRegistration", true)]
    public async Task ManagePhoneConflict_RegistrationActionsCannotBeForgedBeforeOrAfterTransferLockout(
        string forbiddenAction, bool exhausted)
    {
        var scenario = await CreateManagedPhoneConflictAsync(phoneRequired: false);
        var snapshot = scenario.Conflict;
        if (exhausted)
        {
            for (var attempt = 0; attempt < 5; attempt++)
            {
                var mismatch = await ExecuteActionAsync(
                    scenario.Current, snapshot, "transferPhoneToCurrentIdentity",
                    new { previousEmail = "wrong@example.test" });
                snapshot = mismatch.GetProperty("snapshot");
            }
        }
        Assert.Equal(
            exhausted ? ["changePhone"] : ["transferPhoneToCurrentIdentity", "changePhone"],
            ActionTypes(snapshot));
        var previous = await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId);
        var current = await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId);
        var requestId = Guid.NewGuid();
        using var rejected = await SendManagedActionAsync(
            scenario, snapshot, FindAction(snapshot, "changePhone"), forbiddenAction, requestId);
        await AssertFlowErrorAsync(rejected, "action-not-available", "action");
        await AssertManagedRequestAbsentAsync(requestId);
        Assert.Equal(previous, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(current, await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId));
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.PasswordResetTokens.AnyAsync());
        }
        Assert.Equal(snapshot.GetRawText(), (await GetFlowSnapshotAsync(scenario.Current)).GetRawText());
        await AssertManagedAccountsRemainActiveAsync(scenario);
        var changed = await ExecuteActionAsync(scenario.Current, snapshot, "changePhone", requestId: requestId);
        Assert.Equal("collectPhone", changed.GetProperty("snapshot").GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(JsonValueKind.Null, changed.GetProperty("issuedSession").ValueKind);
        Assert.True((await IntrospectFlowSessionAsync(scenario.Current.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task ManagePhoneConflict_FailedSessionInsertRollsBackTransferAndBothRecoveryInvalidations()
    {
        var scenario = await CreateManagedPhoneConflictAsync();
        var previousRecovery = await SeedActiveRecoveryArtifactsAsync(
            scenario.Previous.IdentityId, ManagedConflictingPhone);
        var currentRecovery = await SeedActiveRecoveryArtifactsAsync(
            scenario.Current.IdentityId, ManagedOldPhone);
        var previous = await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId);
        var current = await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId);
        Guid environmentId;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            environmentId = await db.AccessFlows.Where(item => item.Id == scenario.Current.FlowId)
                .Select(item => item.AppEnvironmentId).SingleAsync();
        }
        var requestId = Guid.NewGuid();
        var input = new { previousEmail = scenario.PreviousEmail };
        await using (var fault = await PostgreSqlInsertFault.CreateAsync(
            database.ConnectionString, "identity_sessions", environmentId))
        {
            Assert.False(await fault.WasTriggeredAsync());
            using var failed = await PostLifecycleActionAsync(
                scenario.Current, scenario.Conflict, "transferPhoneToCurrentIdentity", requestId, input);
            Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
            Assert.True(await fault.WasTriggeredAsync());
        }
        Assert.Equal(previous, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(current, await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId));
        Assert.Equal(scenario.Conflict.GetRawText(), (await GetFlowSnapshotAsync(scenario.Current)).GetRawText());
        await AssertManagedRequestAbsentAsync(requestId);
        await AssertManagedConflictAttemptsAsync(scenario, 0);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            foreach (var artifacts in new[] { previousRecovery, currentRecovery })
            {
                var reset = await db.PasswordResetTokens.AsNoTracking()
                    .SingleAsync(item => item.Id == artifacts.PasswordResetTokenId);
                Assert.True(reset.IsActive(clock.GetUtcNow()));
                var challenge = await db.PhonePasswordResetChallenges.AsNoTracking()
                    .SingleAsync(item => item.Id == artifacts.PhoneChallengeId);
                Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
                Assert.Null(challenge.CompletedAt);
            }
        }
        var retry = await ExecuteActionAsync(
            scenario.Current, scenario.Conflict, "transferPhoneToCurrentIdentity", input, requestId);
        await AssertManagedTransferCompletedAsync(scenario, scenario.Conflict, retry);
        var replay = await ExecuteActionAsync(
            scenario.Current, scenario.Conflict, "transferPhoneToCurrentIdentity", input, requestId);
        Assert.Equal(retry.GetRawText(), replay.GetRawText());
        await using var finalScope = api.Services.CreateAsyncScope();
        var finalDb = finalScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await AssertRecoveryArtifactsInvalidatedAsync(finalDb, previousRecovery);
        await AssertRecoveryArtifactsInvalidatedAsync(finalDb, currentRecovery);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    public async Task ManagePhoneConflict_TransferRequiresAnUnexpiredConflictEvenWhileTheFlowIsActive(
        int secondsFromConflictDeadline)
    {
        var scenario = await CreateManagedPhoneConflictAsync();
        var previous = await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId);
        var current = await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId);
        DateTimeOffset expiresAt;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            expiresAt = (await db.PhoneRegistrationConflicts.AsNoTracking()
                .SingleAsync(item => item.AccessFlowId == scenario.Current.FlowId)).ExpiresAt;
            var flow = await db.AccessFlows.AsNoTracking()
                .SingleAsync(item => item.Id == scenario.Current.FlowId);
            Assert.True(expiresAt < flow.ExpiresAt);
        }
        clock.Advance(expiresAt.AddSeconds(secondsFromConflictDeadline) - clock.GetUtcNow());
        var requestId = Guid.NewGuid();
        using var response = await PostLifecycleActionAsync(
            scenario.Current, scenario.Conflict, "transferPhoneToCurrentIdentity", requestId,
            new { previousEmail = scenario.PreviousEmail });
        if (secondsFromConflictDeadline < 0)
        {
            await AssertManagedTransferCompletedAsync(
                scenario, scenario.Conflict, await ReadSuccessfulResponseAsync(response));
            return;
        }
        await AssertFlowErrorAsync(response, "action-not-available", "action");
        await AssertManagedRequestAbsentAsync(requestId);
        Assert.Equal(previous, await ReadIdentityBusinessStateAsync(scenario.Previous.IdentityId));
        Assert.Equal(current, await ReadIdentityBusinessStateAsync(scenario.Current.IdentityId));
        await AssertFlowPersistenceAsync(scenario.Current, AccessFlowStatus.Active,
            scenario.Conflict.GetProperty("revision").GetInt32());
        var changed = await ExecuteActionAsync(scenario.Current, scenario.Conflict, "changePhone");
        Assert.Equal("collectPhone", changed.GetProperty("snapshot").GetProperty("step").GetProperty("type").GetString());
        await AssertManagedConflictAbsentAsync(scenario);
        Assert.True((await IntrospectFlowSessionAsync(scenario.Current.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
        await AssertManagedAccountsRemainActiveAsync(scenario);
    }

    private async Task<ManagedPhoneConflict> CreateManagedPhoneConflictAsync(
        bool hasCurrentPhone = true, bool phoneRequired = true)
    {
        var previousEmail = $"managed-previous-{Guid.NewGuid():N}@example.test";
        var previous = await RegisterAndStartFlowAsync(previousEmail);
        var previousVerify = await RequestPhoneAsync(previous.Flow, previous.Capability, ManagedConflictingPhone);
        var previousCompleted = await ExecuteActionAsync(
            previous, previousVerify, "confirmPhoneVerification", new { code = "123456" });
        var previousToken = previousCompleted.GetProperty("issuedSession").GetProperty("sessionToken").GetString()!;
        var currentEmail = $"managed-current-{Guid.NewGuid():N}@example.test";
        var registration = await RegisterAndStartFlowAsync(currentEmail);
        JsonElement registered;
        if (hasCurrentPhone)
        {
            var verification = await RequestPhoneAsync(registration.Flow, registration.Capability, ManagedOldPhone);
            registered = await ExecuteActionAsync(
                registration, verification, "confirmPhoneVerification", new { code = api.PhoneSender.LastCode });
        }
        else
        {
            registered = await ExecuteActionAsync(registration, registration.Flow, "skipRegistration");
        }
        var sourceToken = registered.GetProperty("issuedSession").GetProperty("sessionToken").GetString()!;
        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneRequired: phoneRequired));
        using var started = await StartFlowAsync("managePhone", sourceToken);
        var current = await ReadStartedFlowAsync(started, registration.IdentityId, sourceToken);
        var verify = await RequestPhoneAsync(current.Flow, current.Capability, ManagedConflictingPhone);
        var response = await ExecuteActionAsync(
            current, verify, "confirmPhoneVerification", new { code = "123456" });
        var conflict = response.GetProperty("snapshot");
        Assert.Equal("resolvePhoneConflict", conflict.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(JsonValueKind.Null, response.GetProperty("issuedSession").ValueKind);
        Assert.Equal(["transferPhoneToCurrentIdentity", "changePhone"], ActionTypes(conflict));
        return new ManagedPhoneConflict(
            previous, previousEmail, previousToken, current, currentEmail,
            registration.FlowId, conflict);
    }

    private async Task AssertManagedTransferCompletedAsync(
        ManagedPhoneConflict scenario, JsonElement inputSnapshot, JsonElement response)
    {
        var snapshot = response.GetProperty("snapshot");
        Assert.Equal("completed", snapshot.GetProperty("status").GetString());
        Assert.Empty(ActionTypes(snapshot));
        var result = snapshot.GetProperty("result");
        Assert.Equal("phoneTransferred", result.GetProperty("outcome").GetString());
        Assert.Equal(scenario.Previous.IdentityId, result.GetProperty("previousIdentityId").GetGuid());
        Assert.Equal(scenario.Current.IdentityId, result.GetProperty("currentIdentityId").GetGuid());
        var issued = response.GetProperty("issuedSession");
        Assert.Equal(scenario.Current.IdentityId, issued.GetProperty("identityId").GetGuid());
        Assert.Equal("product", issued.GetProperty("purpose").GetString());
        var session = await IntrospectFlowSessionAsync(issued.GetProperty("sessionToken").GetString()!);
        Assert.True(session.GetProperty("active").GetBoolean());
        Assert.Equal(ManagedConflictingPhone, session.GetProperty("phone").GetString());
        Assert.False((await IntrospectFlowSessionAsync(scenario.Current.SourceSessionToken!))
            .GetProperty("active").GetBoolean());
        var previousSession = await IntrospectFlowSessionAsync(scenario.PreviousToken);
        Assert.True(previousSession.GetProperty("active").GetBoolean());
        Assert.Equal(JsonValueKind.Null, previousSession.GetProperty("phone").ValueKind);
        await AssertVerifiedPhoneAsync(scenario.Current.IdentityId, ManagedConflictingPhone);
        await AssertManagedAccountsRemainActiveAsync(scenario);
        await AssertManagedConflictAbsentAsync(scenario);
        await AssertFlowPersistenceAsync(scenario.Current, AccessFlowStatus.Completed,
            inputSnapshot.GetProperty("revision").GetInt32() + 1);
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await db.IdentityIdentifiers.AnyAsync(
            item => item.Scheme == IdentifierScheme.Phone && item.NormalizedValue == ManagedOldPhone));
        Assert.False(await db.IdentityIdentifiers.AnyAsync(
            item => item.IdentityId == scenario.Previous.IdentityId && item.Scheme == IdentifierScheme.Phone));
        var sessions = await db.IdentitySessions.AsNoTracking()
            .Where(item => item.IdentityId == scenario.Current.IdentityId).ToListAsync();
        Assert.Equal(3, sessions.Count);
        Assert.Equal(issued.GetProperty("sessionId").GetGuid(),
            Assert.Single(sessions, item => item.RevokedAt == null).Id);
        var flow = await db.AccessFlows.AsNoTracking().SingleAsync(item => item.Id == scenario.Current.FlowId);
        Assert.Null(flow.RegistrationContextId);
        var proof = await db.IdentityProofs.AsNoTracking()
            .SingleAsync(item => item.AccessFlowId == scenario.Current.FlowId);
        Assert.Equal((await ReadPhoneIdentifierAsync(scenario.Current.IdentityId)).Id, proof.SubjectIdentifierId);
    }

    private async Task AssertManagedAccountsRemainActiveAsync(ManagedPhoneConflict scenario)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var ids = new[] { scenario.Previous.IdentityId, scenario.Current.IdentityId };
        var identities = await db.Identities.AsNoTracking().Where(item => ids.Contains(item.Id)).ToListAsync();
        Assert.Equal(2, identities.Count);
        Assert.All(identities, identity => Assert.Equal(IdentityLifecycleState.Active, identity.LifecycleState));
        var contexts = await db.RegistrationContexts.AsNoTracking()
            .Where(item => ids.Contains(item.IdentityId)).ToListAsync();
        Assert.Equal(2, contexts.Count);
        Assert.All(contexts, context => Assert.Equal(RegistrationContextStatus.Completed, context.Status));
        Assert.Equal(2, await db.PasswordCredentials.CountAsync(item => ids.Contains(item.IdentityId)));
    }

    private async Task AssertManagedConflictAttemptsAsync(ManagedPhoneConflict scenario, int attempts)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var conflict = await db.PhoneRegistrationConflicts.AsNoTracking()
            .SingleAsync(item => item.AccessFlowId == scenario.Current.FlowId);
        Assert.Equal(attempts, conflict.FailedEmailAttempts);
        Assert.Equal(attempts == 5, conflict.EmailResolutionExhaustedAt is not null);
    }

    private async Task AssertManagedConflictAbsentAsync(ManagedPhoneConflict scenario)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await db.PhoneRegistrationConflicts.AnyAsync(item => item.AccessFlowId == scenario.Current.FlowId));
    }

    private async Task AssertManagedRequestAbsentAsync(Guid requestId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await db.AccessFlowRequests.AnyAsync(item => item.RequestId == requestId));
    }

    private async Task<string> ReadNonPhoneAccountStateAsync(Guid identityId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        return JsonSerializer.Serialize(new
        {
            Identity = await db.Identities.AsNoTracking().SingleAsync(item => item.Id == identityId),
            Contacts = await db.IdentityIdentifiers.AsNoTracking()
                .Where(item => item.IdentityId == identityId && item.Scheme != IdentifierScheme.Phone)
                .OrderBy(item => item.Id).ToListAsync(),
            Password = await db.PasswordCredentials.AsNoTracking().SingleAsync(item => item.IdentityId == identityId),
            Social = await db.SocialCredentials.AsNoTracking()
                .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id).ToListAsync(),
            Contexts = await db.RegistrationContexts.AsNoTracking()
                .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id).ToListAsync(),
        });
    }

    private Task<HttpResponseMessage> SendManagedActionAsync(
        ManagedPhoneConflict scenario, JsonElement snapshot, JsonElement action,
        string actionType, Guid requestId, object? input = null) =>
        SendWithCapabilityAsync(
            HttpMethod.Post, $"/v1/access/flows/{scenario.Current.FlowId:D}/actions", scenario.Current.Capability,
            new
            {
                requestId,
                expectedRevision = snapshot.GetProperty("revision").GetInt32(),
                action = new { id = action.GetProperty("id").GetGuid(), type = actionType, input },
            });

    private sealed record ManagedPhoneConflict(
        StartedRegistration Previous,
        string PreviousEmail,
        string PreviousToken,
        StartedRegistration Current,
        string CurrentEmail,
        Guid RegistrationFlowId,
        JsonElement Conflict);
}
