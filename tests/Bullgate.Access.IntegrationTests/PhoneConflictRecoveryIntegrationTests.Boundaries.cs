using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed partial class PhoneConflictRecoveryIntegrationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RecoverPreviousIdentity_UsesCurrentStoredEmailDespiteCallerSelectedDestination(
        bool emailChangedAfterConflict)
    {
        var conflict = await CreatePhoneConflictAsync();
        var destination = conflict.Previous.Email;
        if (emailChangedAfterConflict)
        {
            var session = await LoginForRecoveryAsync(conflict.Previous);
            destination = $"updated-{Guid.NewGuid():N}@example.com";
            using var changed = await client.PutAsJsonAsync(
                "/v1/account/email",
                new { sessionToken = session, email = destination });
            Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        }
        var previousState = await ReadAuthenticationStateAsync(conflict.Previous.IdentityId);
        var action = FindAction(conflict.Current.Flow, "recoverPreviousIdentity");

        using var response = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = conflict.Current.Flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = action.GetProperty("id").GetGuid(),
                    type = "recoverPreviousIdentity",
                    input = new
                    {
                        email = conflict.Current.Email,
                        previousEmail = conflict.Current.Email,
                        previousIdentityId = conflict.Current.IdentityId,
                        recoveryUrl = "https://untrusted.example.test/reset",
                    },
                },
            });

        var result = await ReadRecoverySuccessAsync(response);
        await AssertRecoveryCompletedAsync(conflict, result);
        var delivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        Assert.Equal(destination, delivery.Email);
        Assert.Equal(RecoveryUrl, new Uri(delivery.ResetUrl).GetLeftPart(UriPartial.Path));
        Assert.DoesNotContain(destination, result.GetRawText());
        Assert.DoesNotContain(delivery.ResetUrl, result.GetRawText());
        Assert.DoesNotContain(ResetTokenFrom(delivery.ResetUrl), result.GetRawText());
        Assert.Equal(previousState, await ReadAuthenticationStateAsync(conflict.Previous.IdentityId));
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var token = await db.PasswordResetTokens.AsNoTracking().SingleAsync();
        Assert.Equal(conflict.Previous.IdentityId, token.IdentityId);
        Assert.Null(token.UsedAt);
    }

    [Fact]
    public async Task RecoverPreviousIdentity_KeepsPreviousAccessUntilTheDeliveredResetLinkIsUsed()
    {
        var conflict = await CreatePhoneConflictAsync();
        var firstSession = await LoginForRecoveryAsync(conflict.Previous);
        var secondSession = await LoginForRecoveryAsync(conflict.Previous);
        var provisionalSession = await LoginForRecoveryAsync(conflict.Current);
        await AddCurrentSocialCredentialAsync(conflict.Previous.IdentityId, conflict.Previous.Email);
        var earlierReset = await IssueResetTokenAsync(conflict.Previous.IdentityId);
        Assert.True(earlierReset.Succeeded);
        var previousState = await ReadAuthenticationStateAsync(conflict.Previous.IdentityId);

        using var response = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, Guid.NewGuid()));
        await AssertRecoveryCompletedAsync(conflict, await ReadRecoverySuccessAsync(response));

        Assert.Equal(previousState, await ReadAuthenticationStateAsync(conflict.Previous.IdentityId));
        await AssertRecoverySessionActiveAsync(firstSession, true);
        await AssertRecoverySessionActiveAsync(secondSession, true);
        await AssertRecoverySessionActiveAsync(provisionalSession, false);
        using var provisionalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = conflict.Current.Email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, provisionalLogin.StatusCode);
        var thirdSession = await LoginForRecoveryAsync(conflict.Previous);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var tokens = await db.PasswordResetTokens.AsNoTracking()
                .Where(token => token.IdentityId == conflict.Previous.IdentityId).ToListAsync();
            Assert.Equal(2, tokens.Count);
            Assert.All(tokens, token => Assert.True(token.IsActive(clock.GetUtcNow())));
        }

        var delivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        using var reset = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token = ResetTokenFrom(delivery.ResetUrl), newPassword = "restored-password-456" });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
        await AssertRecoverySessionActiveAsync(firstSession, false);
        await AssertRecoverySessionActiveAsync(secondSession, false);
        await AssertRecoverySessionActiveAsync(thirdSession, false);
        await AssertResetRejectedAsync(earlierReset.Token);
        await AssertResetRejectedAsync(ResetTokenFrom(delivery.ResetUrl));
        using var oldPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = conflict.Previous.Email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldPassword.StatusCode);
        var restoredSession = await LoginForRecoveryAsync(conflict.Previous, "restored-password-456");
        await AssertRecoverySessionActiveAsync(restoredSession, true);
    }

    [Fact]
    public async Task RecoverPreviousIdentity_AllowsASocialOnlyPreviousAccountToCreateItsFirstPassword()
    {
        var conflict = await CreatePhoneConflictAsync();
        await AddCurrentSocialCredentialAsync(
            conflict.Previous.IdentityId,
            conflict.Previous.Email);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var credential = await db.PasswordCredentials
                .SingleAsync(item => item.IdentityId == conflict.Previous.IdentityId);
            db.PasswordCredentials.Remove(credential);
            await db.SaveChangesAsync();
        }
        using (var unavailablePassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = conflict.Previous.Email, password = "password-123" }))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unavailablePassword.StatusCode);
        }

        using var recovery = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, Guid.NewGuid()));
        await AssertRecoveryCompletedAsync(
            conflict,
            await ReadRecoverySuccessAsync(recovery));
        var delivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        using var reset = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new
            {
                token = ResetTokenFrom(delivery.ResetUrl),
                newPassword = "first-password-456",
            });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
        using var login = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new
            {
                email = conflict.Previous.Email,
                password = "first-password-456",
            });
        var loginResult = await ReadRecoverySuccessAsync(login);
        Assert.Equal(
            conflict.Previous.IdentityId,
            loginResult.GetProperty("identityId").GetGuid());
        Assert.True(loginResult.GetProperty("hasPassword").GetBoolean());
        Assert.True(loginResult.GetProperty("hasGoogle").GetBoolean());
        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        Assert.True(await verification.PasswordCredentials.AnyAsync(
            item => item.IdentityId == conflict.Previous.IdentityId));
        Assert.True(await verification.SocialCredentials.AnyAsync(
            item => item.IdentityId == conflict.Previous.IdentityId
                && item.Provider == SocialProvider.Google));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RecoverPreviousIdentity_DeliveryFailureAfterLockoutPreservesRecoveryAndTransferLimit(
        bool senderAvailable)
    {
        var conflict = await CreatePhoneConflictAsync();
        var originalTransfer = FindAction(conflict.Current.Flow, "transferPhoneToCurrentIdentity");
        conflict = await ExhaustTransferAttemptsAsync(conflict);
        var previousState = await ReadAuthenticationStateAsync(conflict.Previous.IdentityId);
        api.PasswordRecoveryEmailSender.IsAvailable = senderAvailable;
        api.PasswordRecoveryEmailSender.DeliverySucceeds = false;
        var requestId = Guid.NewGuid();
        var actionBody = CreateRecoveryActionBody(conflict, requestId);

        using var failed = await SendWithCapabilityAsync(
            conflict.Current.FlowId, conflict.Current.Capability, actionBody);
        await AssertRecoveryErrorAsync(
            failed, HttpStatusCode.ServiceUnavailable, "password-recovery-unavailable");
        await AssertConflictPreservedAsync(conflict, senderAvailable ? 1 : 0);
        await AssertRecoveryRequestAsync(conflict, requestId, AccessFlowRequestStatus.ExternalFailed);
        await AssertTransferStillBlockedAsync(conflict, originalTransfer);
        if (senderAvailable)
        {
            var failedDelivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
            await AssertResetRejectedAsync(ResetTokenFrom(failedDelivery.ResetUrl));
        }

        api.PasswordRecoveryEmailSender.IsAvailable = true;
        api.PasswordRecoveryEmailSender.DeliverySucceeds = true;
        using var replay = await SendWithCapabilityAsync(
            conflict.Current.FlowId, conflict.Current.Capability, actionBody);
        await AssertRecoveryErrorAsync(
            replay, HttpStatusCode.ServiceUnavailable, "verification-delivery-unavailable");
        Assert.Equal(senderAvailable ? 1 : 0, api.PasswordRecoveryEmailSender.DeliveryAttempts.Count);
        Assert.Equal(previousState, await ReadAuthenticationStateAsync(conflict.Previous.IdentityId));

        using var retried = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, Guid.NewGuid()));
        await AssertRecoveryCompletedAsync(conflict, await ReadRecoverySuccessAsync(retried));
        Assert.Equal(senderAvailable ? 2 : 1, api.PasswordRecoveryEmailSender.DeliveryAttempts.Count);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tokens = await db.PasswordResetTokens.AsNoTracking()
            .Where(token => token.IdentityId == conflict.Previous.IdentityId).ToListAsync();
        Assert.Equal(senderAvailable ? 2 : 1, tokens.Count);
        Assert.Single(tokens, token => token.IsActive(clock.GetUtcNow()));
    }

    [Fact]
    public async Task RecoverPreviousIdentity_FinalPersistenceFailureInvalidatesDeliveredLinkAndAllowsFreshRecovery()
    {
        var conflict = await CreatePhoneConflictAsync();
        var currentState = await ReadAuthenticationStateAsync(conflict.Current.IdentityId);
        var previousState = await ReadAuthenticationStateAsync(conflict.Previous.IdentityId);
        var requestId = Guid.NewGuid();
        var actionBody = CreateRecoveryActionBody(conflict, requestId);

        await using (var fault = await PostgreSqlInsertFault.CreateAsync(
            database.ConnectionString, "access_flow_revisions", appEnvironmentId))
        {
            Assert.False(await fault.WasTriggeredAsync());
            using var failed = await SendWithCapabilityAsync(
                conflict.Current.FlowId, conflict.Current.Capability, actionBody);
            Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
            Assert.True(await fault.WasTriggeredAsync());
        }

        var failedDelivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        Assert.Equal(conflict.Previous.Email, failedDelivery.Email);
        await AssertResetRejectedAsync(ResetTokenFrom(failedDelivery.ResetUrl));
        Assert.Equal(currentState, await ReadAuthenticationStateAsync(conflict.Current.IdentityId));
        Assert.Equal(previousState, await ReadAuthenticationStateAsync(conflict.Previous.IdentityId));
        Assert.Equal(
            conflict.Current.Flow.GetRawText(),
            (await GetRecoveryFlowSnapshotAsync(conflict.Current)).GetRawText());
        await AssertConflictPreservedAsync(conflict, expectedPreviousTokenCount: 1);
        await AssertRecoveryRequestAsync(
            conflict, requestId, AccessFlowRequestStatus.ExternalFailed);

        using (var replay = await SendWithCapabilityAsync(
            conflict.Current.FlowId, conflict.Current.Capability, actionBody))
        {
            await AssertRecoveryErrorAsync(
                replay,
                HttpStatusCode.ServiceUnavailable,
                "verification-delivery-unavailable");
        }
        Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        Assert.Equal(currentState, await ReadAuthenticationStateAsync(conflict.Current.IdentityId));
        Assert.Equal(previousState, await ReadAuthenticationStateAsync(conflict.Previous.IdentityId));

        using var retried = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, Guid.NewGuid()));
        await AssertRecoveryCompletedAsync(
            conflict,
            await ReadRecoverySuccessAsync(retried));
        var deliveries = api.PasswordRecoveryEmailSender.DeliveryAttempts.ToArray();
        Assert.Equal(2, deliveries.Length);
        Assert.NotEqual(
            ResetTokenFrom(deliveries[0].ResetUrl),
            ResetTokenFrom(deliveries[1].ResetUrl));
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tokens = await db.PasswordResetTokens.AsNoTracking()
            .Where(token => token.IdentityId == conflict.Previous.IdentityId)
            .OrderBy(token => token.CreatedAt)
            .ToListAsync();
        Assert.Equal(2, tokens.Count);
        Assert.NotNull(tokens[0].UsedAt);
        Assert.True(tokens[1].IsActive(clock.GetUtcNow()));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RecoverPreviousIdentity_RetryDuringEmailDeliveryDoesNotSendOrAbandonTwice(
        bool sameRequestId)
    {
        var conflict = await CreatePhoneConflictAsync();
        var previousState = await ReadAuthenticationStateAsync(conflict.Previous.IdentityId);
        var requestId = Guid.NewGuid();
        var body = CreateRecoveryActionBody(conflict, requestId);
        var gate = new AsyncOperationGate();
        api.PasswordRecoveryEmailSender.SendGate = gate;
        var pending = SendWithCapabilityAsync(
            conflict.Current.FlowId, conflict.Current.Capability, body);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            await gate.WaitUntilEnteredAsync(deadline.Token);
            var retryId = sameRequestId ? requestId : Guid.NewGuid();
            using var retry = await SendWithCapabilityAsync(
                conflict.Current.FlowId,
                conflict.Current.Capability,
                CreateRecoveryActionBody(conflict, retryId));
            await AssertRecoveryErrorAsync(
                retry, HttpStatusCode.ServiceUnavailable, "verification-delivery-unavailable");
            Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
            await AssertConflictPreservedAsync(conflict, expectedPreviousTokenCount: 1);
            await AssertRecoveryRequestAsync(conflict, requestId, AccessFlowRequestStatus.PendingExternal);
            if (!sameRequestId)
            {
                await using var scope = api.Services.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
                Assert.False(await db.AccessFlowRequests.AnyAsync(item => item.RequestId == retryId));
            }
            Assert.Equal(previousState, await ReadAuthenticationStateAsync(conflict.Previous.IdentityId));
        }
        finally
        {
            gate.Release();
        }

        using var response = await pending.WaitAsync(deadline.Token);
        api.PasswordRecoveryEmailSender.SendGate = null;
        var completed = await ReadRecoverySuccessAsync(response);
        await AssertRecoveryCompletedAsync(conflict, completed);
        await AssertRecoveryRequestAsync(conflict, requestId, AccessFlowRequestStatus.Committed);
        using var replay = await SendWithCapabilityAsync(
            conflict.Current.FlowId, conflict.Current.Capability, body);
        Assert.Equal(completed.GetRawText(), (await ReadRecoverySuccessAsync(replay)).GetRawText());
        Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        Assert.Equal(previousState, await ReadAuthenticationStateAsync(conflict.Previous.IdentityId));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    public async Task RecoverPreviousIdentity_RequiresConflictProofBeforeItsOwnDeadline(
        int secondsFromConflictDeadline)
    {
        var conflict = await CreatePhoneConflictAsync();
        DateTimeOffset expiresAt;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            expiresAt = (await db.PhoneRegistrationConflicts.AsNoTracking()
                .SingleAsync(item => item.AccessFlowId == conflict.Current.FlowId)).ExpiresAt;
            var flow = await db.AccessFlows.AsNoTracking()
                .SingleAsync(item => item.Id == conflict.Current.FlowId);
            Assert.True(expiresAt < flow.ExpiresAt);
        }
        clock.Advance(expiresAt.AddSeconds(secondsFromConflictDeadline) - clock.GetUtcNow());
        var requestId = Guid.NewGuid();
        using var response = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, requestId));
        if (secondsFromConflictDeadline < 0)
        {
            await AssertRecoveryCompletedAsync(conflict, await ReadRecoverySuccessAsync(response));
            Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
            return;
        }

        await AssertRecoveryErrorAsync(response, HttpStatusCode.Conflict, "action-not-available");
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        await AssertConflictPreservedAsync(conflict, expectedPreviousTokenCount: 0);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.AccessFlowRequests.AnyAsync(item => item.RequestId == requestId));
            var flow = await db.AccessFlows.AsNoTracking()
                .SingleAsync(item => item.Id == conflict.Current.FlowId);
            Assert.Equal(AccessFlowStatus.Active, flow.Status);
            Assert.Equal(conflict.Current.Flow.GetProperty("revision").GetInt32(), flow.CurrentRevision);
        }

        // The registration is still usable, but recovery needs a fresh phone proof.
        using var changed = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateChangePhoneActionBody(conflict, Guid.NewGuid()));
        var collect = (await ReadRecoverySuccessAsync(changed)).GetProperty("snapshot");
        Assert.Equal("collectPhone", collect.GetProperty("step").GetProperty("type").GetString());
        var current = conflict.Current with { Flow = collect };
        var verification = await RequestPhoneAsync(current, conflict.Phone);
        var freshConflict = await ConfirmPhoneAsync(current, verification);
        conflict = conflict with { Current = current with { Flow = freshConflict } };
        using var recovered = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, requestId));
        await AssertRecoveryCompletedAsync(conflict, await ReadRecoverySuccessAsync(recovered));
        Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
    }

    [Fact]
    public async Task RecoverPreviousIdentity_PreviousOwnerChangingPhoneInvalidatesTheOldRecoveryDecision()
    {
        const string replacementPhone = "+5511987654390";
        var conflict = await CreatePhoneConflictAsync();
        var currentState = await ReadAuthenticationStateAsync(conflict.Current.IdentityId);
        var previousToken = await LoginForRecoveryAsync(conflict.Previous);
        using var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = ProtocolVersion1,
                intent = "managePhone",
                applicationClientKey = ApplicationClientKey,
                sessionToken = previousToken,
            });
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var startedRoot = startedBody.RootElement;
        var manageSnapshot = startedRoot.GetProperty("snapshot").Clone();
        var managed = new StartedRegistration(
            conflict.Previous.Email,
            conflict.Previous.IdentityId,
            manageSnapshot.GetProperty("flowId").GetGuid(),
            startedRoot.GetProperty("flowCapability").GetString()!,
            manageSnapshot);
        var verification = await RequestPhoneAsync(managed, replacementPhone);
        var confirm = FindAction(verification, "confirmPhoneVerification");
        using (var confirmed = await SendWithCapabilityAsync(
            managed.FlowId,
            managed.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = verification.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = confirm.GetProperty("id").GetGuid(),
                    type = "confirmPhoneVerification",
                    input = new { code = api.PhoneSender.LastCode },
                },
            }))
        {
            var completed = await ReadRecoverySuccessAsync(confirmed);
            Assert.Equal(
                "phoneVerified",
                completed.GetProperty("snapshot")
                    .GetProperty("result")
                    .GetProperty("outcome")
                    .GetString());
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.PhoneRegistrationConflicts.AnyAsync(
                item => item.AccessFlowId == conflict.Current.FlowId));
            Assert.False(await db.IdentityIdentifiers.AnyAsync(
                item => item.NormalizedValue == conflict.Phone));
            var replacement = await db.IdentityIdentifiers.AsNoTracking()
                .SingleAsync(item => item.IdentityId == conflict.Previous.IdentityId
                    && item.Scheme == IdentifierScheme.Phone);
            Assert.Equal(replacementPhone, replacement.NormalizedValue);
            Assert.NotNull(replacement.VerifiedAt);
            var proof = await db.IdentityProofs.AsNoTracking()
                .SingleAsync(item => item.AccessFlowId == conflict.Current.FlowId);
            Assert.Null(proof.SubjectIdentifierId);
        }
        Assert.Equal(currentState, await ReadAuthenticationStateAsync(conflict.Current.IdentityId));

        var staleRequestId = Guid.NewGuid();
        using (var staleRecovery = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, staleRequestId)))
        {
            await AssertRecoveryErrorAsync(
                staleRecovery,
                HttpStatusCode.Conflict,
                "action-not-available");
        }
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.AccessFlowRequests.AnyAsync(
                item => item.RequestId == staleRequestId));
            Assert.Equal(
                IdentityLifecycleState.Active,
                (await db.Identities.AsNoTracking()
                    .SingleAsync(item => item.Id == conflict.Current.IdentityId))
                    .LifecycleState);
            Assert.Equal(
                RegistrationContextStatus.Open,
                (await db.RegistrationContexts.AsNoTracking()
                    .SingleAsync(item => item.IdentityId == conflict.Current.IdentityId))
                    .Status);
        }

        using var changed = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateChangePhoneActionBody(conflict, Guid.NewGuid()));
        var collect = (await ReadRecoverySuccessAsync(changed)).GetProperty("snapshot");
        Assert.Equal(
            "collectPhone",
            collect.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(currentState, await ReadAuthenticationStateAsync(conflict.Current.IdentityId));
    }

    private async Task ConfigureRecoveryPolicyAsync(bool phoneRequired)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
        var configured = await handler.HandleAsync(CreateBootstrapCommand(topologySuffix, phoneRequired));
        Assert.Empty(configured.IssuedCredentials);
    }

    private async Task<PhoneConflictScenario> ExhaustTransferAttemptsAsync(PhoneConflictScenario conflict)
    {
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var snapshot = conflict.Current.Flow;
            var transfer = FindAction(snapshot, "transferPhoneToCurrentIdentity");
            using var mismatch = await SendWithCapabilityAsync(
                conflict.Current.FlowId,
                conflict.Current.Capability,
                new
                {
                    requestId = Guid.NewGuid(),
                    expectedRevision = snapshot.GetProperty("revision").GetInt32(),
                    action = new
                    {
                        id = transfer.GetProperty("id").GetGuid(),
                        type = "transferPhoneToCurrentIdentity",
                        input = new { previousEmail = "wrong@example.com" },
                    },
                });
            var next = (await ReadRecoverySuccessAsync(mismatch)).GetProperty("snapshot");
            Assert.Equal(attempt == 5 ? "phone-conflict-too-many-attempts" : "phone-conflict-email-mismatch",
                next.GetProperty("feedback").GetProperty("code").GetString());
            conflict = conflict with { Current = conflict.Current with { Flow = next } };
        }
        Assert.DoesNotContain("transferPhoneToCurrentIdentity", RecoveryActionTypes(conflict.Current.Flow));
        FindAction(conflict.Current.Flow, "recoverPreviousIdentity");
        return conflict;
    }

    private async Task AssertTransferStillBlockedAsync(PhoneConflictScenario conflict, JsonElement oldAction)
    {
        var requestId = Guid.NewGuid();
        using var transfer = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            new
            {
                requestId,
                expectedRevision = conflict.Current.Flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = oldAction.GetProperty("id").GetGuid(),
                    type = "transferPhoneToCurrentIdentity",
                    input = new { previousEmail = conflict.Previous.Email },
                },
            });
        await AssertRecoveryErrorAsync(transfer, HttpStatusCode.Conflict, "action-not-available");
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var stored = await db.PhoneRegistrationConflicts.AsNoTracking()
            .SingleAsync(item => item.AccessFlowId == conflict.Current.FlowId);
        Assert.Equal(5, stored.FailedEmailAttempts);
        Assert.NotNull(stored.EmailResolutionExhaustedAt);
        Assert.False(await db.AccessFlowRequests.AnyAsync(item => item.RequestId == requestId));
        var phone = await db.IdentityIdentifiers.AsNoTracking()
            .SingleAsync(item => item.Scheme == IdentifierScheme.Phone && item.NormalizedValue == conflict.Phone);
        Assert.Equal(conflict.Previous.IdentityId, phone.IdentityId);
    }

    private async Task AssertRecoveryCompletedAsync(PhoneConflictScenario conflict, JsonElement result)
    {
        var snapshot = result.GetProperty("snapshot");
        Assert.Equal("completed", snapshot.GetProperty("status").GetString());
        Assert.Empty(snapshot.GetProperty("actions").EnumerateArray());
        Assert.Equal("registrationAbandoned", snapshot.GetProperty("result").GetProperty("type").GetString());
        Assert.Equal("previousIdentityRecoveryRequested", snapshot.GetProperty("result").GetProperty("outcome").GetString());
        Assert.Equal(conflict.Previous.IdentityId, snapshot.GetProperty("result").GetProperty("previousIdentityId").GetGuid());
        Assert.Equal(conflict.Current.IdentityId, snapshot.GetProperty("result").GetProperty("currentIdentityId").GetGuid());
        Assert.Equal(JsonValueKind.Null, result.GetProperty("issuedSession").ValueKind);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(IdentityLifecycleState.Abandoned,
            (await db.Identities.AsNoTracking().SingleAsync(item => item.Id == conflict.Current.IdentityId)).LifecycleState);
        Assert.Equal(IdentityLifecycleState.Active,
            (await db.Identities.AsNoTracking().SingleAsync(item => item.Id == conflict.Previous.IdentityId)).LifecycleState);
        Assert.Equal(RegistrationContextStatus.Abandoned,
            (await db.RegistrationContexts.AsNoTracking()
                .SingleAsync(item => item.IdentityId == conflict.Current.IdentityId)).Status);
        Assert.False(await db.IdentitySessions.AnyAsync(
            item => item.IdentityId == conflict.Current.IdentityId && item.RevokedAt == null));
        Assert.False(await db.PhoneRegistrationConflicts.AnyAsync(item => item.AccessFlowId == conflict.Current.FlowId));
        var phone = await db.IdentityIdentifiers.AsNoTracking()
            .SingleAsync(item => item.Scheme == IdentifierScheme.Phone && item.NormalizedValue == conflict.Phone);
        Assert.Equal(conflict.Previous.IdentityId, phone.IdentityId);
        Assert.NotNull(phone.VerifiedAt);
        var flow = await db.AccessFlows.AsNoTracking().SingleAsync(item => item.Id == conflict.Current.FlowId);
        Assert.Equal(AccessFlowStatus.Completed, flow.Status);
        Assert.Equal(conflict.Current.Flow.GetProperty("revision").GetInt32() + 1, flow.CurrentRevision);
        Assert.Equal(flow.CurrentRevision,
            await db.AccessFlowRevisions.CountAsync(item => item.FlowId == flow.Id));
    }

    private async Task AssertRecoveryRequestAsync(
        PhoneConflictScenario conflict, Guid requestId, AccessFlowRequestStatus status)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var request = await db.AccessFlowRequests.AsNoTracking().SingleAsync(item => item.RequestId == requestId);
        Assert.Equal(conflict.Current.FlowId, request.FlowId);
        Assert.Equal(status, request.Status);
        var flow = await db.AccessFlows.AsNoTracking().SingleAsync(item => item.Id == request.FlowId);
        var startingRevision = conflict.Current.Flow.GetProperty("revision").GetInt32();
        Assert.Equal(status == AccessFlowRequestStatus.Committed ? startingRevision + 1 : startingRevision,
            flow.CurrentRevision);
        if (status == AccessFlowRequestStatus.Committed)
        {
            Assert.Equal(flow.CurrentRevision, request.ResultRevision);
        }
        else
        {
            Assert.Null(request.ResultRevision);
        }
    }

    private async Task<string> ReadAuthenticationStateAsync(Guid identityId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        return JsonSerializer.Serialize(new
        {
            Identity = await db.Identities.AsNoTracking().SingleAsync(item => item.Id == identityId),
            Identifiers = await db.IdentityIdentifiers.AsNoTracking()
                .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id).ToListAsync(),
            Password = await db.PasswordCredentials.AsNoTracking().SingleAsync(item => item.IdentityId == identityId),
            Social = await db.SocialCredentials.AsNoTracking()
                .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id).ToListAsync(),
            Sessions = await db.IdentitySessions.AsNoTracking()
                .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id).ToListAsync(),
            Contexts = await db.RegistrationContexts.AsNoTracking()
                .Where(item => item.IdentityId == identityId).OrderBy(item => item.Id).ToListAsync(),
        });
    }

    private async Task<string> LoginForRecoveryAsync(StartedRegistration registration, string password = "password-123")
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = registration.Email, password });
        var result = await ReadRecoverySuccessAsync(response);
        Assert.Equal(registration.IdentityId, result.GetProperty("identityId").GetGuid());
        return result.GetProperty("sessionToken").GetString()!;
    }

    private async Task AssertRecoverySessionActiveAsync(string sessionToken, bool active)
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect", new { sessionToken });
        Assert.Equal(active, (await ReadRecoverySuccessAsync(response)).GetProperty("active").GetBoolean());
    }

    private async Task<JsonElement> GetRecoveryFlowSnapshotAsync(StartedRegistration registration)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"/v1/access/flows/{registration.FlowId:D}");
        request.Headers.TryAddWithoutValidation(CapabilityHeader, registration.Capability);
        using var response = await client.SendAsync(request);
        var root = await ReadRecoverySuccessAsync(response);
        return root.GetProperty("snapshot").Clone();
    }

    private async Task AssertResetRejectedAsync(string token)
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset", new { token, newPassword = "must-not-be-installed" });
        await AssertRecoveryErrorAsync(response, HttpStatusCode.BadRequest, "invalid-token");
    }

    private static async Task<JsonElement> ReadRecoverySuccessAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.Clone();
    }

    private static async Task AssertRecoveryErrorAsync(
        HttpResponseMessage response, HttpStatusCode status, string error)
    {
        Assert.Equal(status, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(error, body.RootElement.GetProperty("error").GetString());
        Assert.False(body.RootElement.TryGetProperty("issuedSession", out _));
    }

    private static string ResetTokenFrom(string url) =>
        Uri.UnescapeDataString(new Uri(url).Query["?token=".Length..]);

    private static string[] RecoveryActionTypes(JsonElement snapshot) =>
        snapshot.GetProperty("actions").EnumerateArray()
            .Select(action => action.GetProperty("type").GetString()!).ToArray();
}
