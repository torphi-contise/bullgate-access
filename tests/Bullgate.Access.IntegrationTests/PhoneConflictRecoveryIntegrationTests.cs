using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed partial class PhoneConflictRecoveryIntegrationTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private const string CapabilityHeader = "Bullgate-Flow-Capability";
    private const string RecoveryUrl = "https://baybo.app/reset-password";
    private const string ApplicationClientKey = "android-debug";
    private readonly AdjustableTimeProvider clock = new(
        DateTimeOffset.UnixEpoch.AddSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
    private readonly string topologySuffix = Guid.NewGuid().ToString("N");
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private Guid appEnvironmentId;
    private Guid realmId;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString, clock);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await dbContext.Database.EnsureDeletedAsync();
            await dbContext.Database.EnsureCreatedAsync();
        }

        BootstrapTopologyResult bootstrap;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            bootstrap = await handler.HandleAsync(
                CreateBootstrapCommand(topologySuffix));
        }

        appEnvironmentId = Assert.Single(
            bootstrap.Resources,
            resource => resource.Type == "environment").Id;
        realmId = Assert.Single(
            bootstrap.Resources,
            resource => resource.Type == "realm").Id;
        var credential = Assert.Single(bootstrap.IssuedCredentials);
        client = api.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", credential.Token);
    }

    public async Task DisposeAsync()
    {
        client.Dispose();
        await api.DisposeAsync();
    }

    [Fact]
    public async Task RecoverPreviousIdentity_UsesCommonResetAndAbandonsRecentIdentity()
    {
        var conflict = await CreatePhoneConflictAsync();
        var currentReset = await IssueResetTokenAsync(conflict.Current.IdentityId);
        Assert.True(currentReset.Succeeded);
        await AddCurrentSocialCredentialAsync(
            conflict.Current.IdentityId,
            conflict.Current.Email);

        var actionRequestId = Guid.NewGuid();
        var actionBody = CreateRecoveryActionBody(conflict, actionRequestId);
        using var recovered = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            actionBody);

        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        using var recoveredBody = JsonDocument.Parse(
            await recovered.Content.ReadAsStringAsync());
        var recoveredRoot = recoveredBody.RootElement;
        var recoveredSnapshot = recoveredRoot.GetProperty("snapshot");
        Assert.Equal("completed", recoveredSnapshot.GetProperty("status").GetString());
        Assert.Equal(
            "registrationAbandoned",
            recoveredSnapshot.GetProperty("result").GetProperty("type").GetString());
        Assert.Equal(
            "previousIdentityRecoveryRequested",
            recoveredSnapshot.GetProperty("result").GetProperty("outcome").GetString());
        Assert.Equal(
            conflict.Previous.IdentityId,
            recoveredSnapshot.GetProperty("result")
                .GetProperty("previousIdentityId")
                .GetGuid());
        Assert.Equal(JsonValueKind.Null, recoveredRoot.GetProperty("issuedSession").ValueKind);

        var delivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        Assert.Equal(conflict.Previous.Email, delivery.Email);
        var resetUri = new Uri(delivery.ResetUrl);
        Assert.Equal(RecoveryUrl, resetUri.GetLeftPart(UriPartial.Path));
        var resetToken = Uri.UnescapeDataString(resetUri.Query["?token=".Length..]);
        Assert.Equal(43, resetToken.Length);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identities = await dbContext.Identities
                .AsNoTracking()
                .Where(identity => identity.Id == conflict.Previous.IdentityId
                    || identity.Id == conflict.Current.IdentityId)
                .ToDictionaryAsync(identity => identity.Id);
            Assert.Equal(
                IdentityLifecycleState.Active,
                identities[conflict.Previous.IdentityId].LifecycleState);
            Assert.Equal(
                IdentityLifecycleState.Abandoned,
                identities[conflict.Current.IdentityId].LifecycleState);

            var currentContext = await dbContext.RegistrationContexts
                .AsNoTracking()
                .SingleAsync(context => context.IdentityId == conflict.Current.IdentityId);
            Assert.Equal(RegistrationContextStatus.Abandoned, currentContext.Status);
            Assert.NotNull(currentContext.ClosedAt);

            var phone = await dbContext.IdentityIdentifiers
                .AsNoTracking()
                .SingleAsync(identifier => identifier.Scheme == IdentifierScheme.Phone
                    && identifier.NormalizedValue == conflict.Phone);
            Assert.Equal(conflict.Previous.IdentityId, phone.IdentityId);
            Assert.Empty(await dbContext.IdentityIdentifiers
                .AsNoTracking()
                .Where(identifier => identifier.IdentityId == conflict.Current.IdentityId)
                .ToArrayAsync());
            Assert.False(await dbContext.PasswordCredentials
                .AsNoTracking()
                .AnyAsync(credential => credential.IdentityId == conflict.Current.IdentityId));
            Assert.False(await dbContext.SocialCredentials
                .AsNoTracking()
                .AnyAsync(credential => credential.IdentityId == conflict.Current.IdentityId));
            Assert.False(await dbContext.PasswordResetTokens
                .AsNoTracking()
                .AnyAsync(token => token.IdentityId == conflict.Current.IdentityId));

            var currentSessions = await dbContext.IdentitySessions
                .AsNoTracking()
                .Where(session => session.IdentityId == conflict.Current.IdentityId)
                .ToArrayAsync();
            Assert.NotEmpty(currentSessions);
            Assert.All(currentSessions, session => Assert.NotNull(session.RevokedAt));
            Assert.DoesNotContain(
                currentSessions,
                session => session.Purpose == IdentitySessionPurpose.Product);
            Assert.False(await dbContext.PhoneRegistrationConflicts
                .AsNoTracking()
                .AnyAsync(item => item.AccessFlowId == conflict.Current.FlowId));
            Assert.False(await dbContext.IdentityProofs
                .AsNoTracking()
                .AnyAsync(proof => proof.AccessFlowId == conflict.Current.FlowId));
            Assert.False(await dbContext.ProofAttempts
                .AsNoTracking()
                .AnyAsync(attempt => dbContext.ProofChallenges.Any(challenge =>
                    challenge.Id == attempt.ChallengeId
                    && challenge.AccessFlowId == conflict.Current.FlowId)));
            Assert.False(await dbContext.ProofChallenges
                .AsNoTracking()
                .AnyAsync(challenge =>
                    challenge.AccessFlowId == conflict.Current.FlowId));
            Assert.False(await dbContext.PhonePasswordResetChallenges
                .AsNoTracking()
                .AnyAsync(challenge =>
                    challenge.IdentityId == conflict.Current.IdentityId));

            var previousTokens = await dbContext.PasswordResetTokens
                .AsNoTracking()
                .Where(token => token.IdentityId == conflict.Previous.IdentityId)
                .ToArrayAsync();
            Assert.Single(previousTokens);
            Assert.True(previousTokens[0].IsActive(DateTimeOffset.UtcNow));
        }

        using var replay = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            actionBody);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        using (var replayBody = JsonDocument.Parse(await replay.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                recoveredSnapshot.GetRawText(),
                replayBody.RootElement.GetProperty("snapshot").GetRawText());
            Assert.Equal(
                JsonValueKind.Null,
                replayBody.RootElement.GetProperty("issuedSession").ValueKind);
        }
        Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);

        var reset = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token = resetToken, newPassword = "replacement-password" });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);

        var oldPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = conflict.Previous.Email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldPassword.StatusCode);
        var newPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = conflict.Previous.Email, password = "replacement-password" });
        Assert.Equal(HttpStatusCode.OK, newPassword.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RecoverPreviousIdentity_RemainsAvailableAfterTransferEmailAttemptsAreExhausted(
        bool phoneRequired)
    {
        await ConfigureRecoveryPolicyAsync(phoneRequired);
        var conflict = await CreatePhoneConflictAsync();
        var originalTransfer = FindAction(conflict.Current.Flow, "transferPhoneToCurrentIdentity");
        conflict = await ExhaustTransferAttemptsAsync(conflict);
        Assert.Equal(
            phoneRequired
                ? ["recoverPreviousIdentity", "changePhone"]
                : ["recoverPreviousIdentity", "changePhone", "skipRegistration"],
            RecoveryActionTypes(conflict.Current.Flow));
        await AssertTransferStillBlockedAsync(conflict, originalTransfer);
        using var recovered = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, Guid.NewGuid()));

        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        using var recoveredBody = JsonDocument.Parse(
            await recovered.Content.ReadAsStringAsync());
        Assert.Equal(
            "previousIdentityRecoveryRequested",
            recoveredBody.RootElement.GetProperty("snapshot")
                .GetProperty("result")
                .GetProperty("outcome")
                .GetString());
        Assert.Equal(
            conflict.Previous.Email,
            Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts).Email);
        await AssertRecoveryCompletedAsync(conflict, recoveredBody.RootElement);
    }

    [Theory]
    [InlineData(false, true, 0, 0)]
    [InlineData(true, false, 1, 1)]
    public async Task RecoverPreviousIdentity_DeliveryUnavailable_PreservesRecentIdentityAndConflict(
        bool senderAvailable,
        bool deliverySucceeds,
        int expectedDeliveries,
        int expectedTokens)
    {
        var conflict = await CreatePhoneConflictAsync();
        api.PasswordRecoveryEmailSender.IsAvailable = senderAvailable;
        api.PasswordRecoveryEmailSender.DeliverySucceeds = deliverySucceeds;
        var requestId = Guid.NewGuid();

        using var response = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, requestId));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "password-recovery-unavailable",
                body.RootElement.GetProperty("error").GetString());
        }
        Assert.Equal(
            expectedDeliveries,
            api.PasswordRecoveryEmailSender.DeliveryAttempts.Count);
        await AssertConflictPreservedAsync(conflict, expectedTokens);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            // The failed attempt is recorded and a token issued for it is dead.
            var request = await dbContext.AccessFlowRequests.AsNoTracking().SingleAsync(
                item => item.RequestId == requestId);
            Assert.Equal(AccessFlowRequestStatus.ExternalFailed, request.Status);
            Assert.Null(request.ResultRevision);
            var tokens = await dbContext.PasswordResetTokens.AsNoTracking()
                .Where(token => token.IdentityId == conflict.Previous.IdentityId)
                .ToListAsync();
            Assert.Equal(expectedTokens, tokens.Count);
            Assert.All(tokens, token => Assert.NotNull(token.UsedAt));
        }

        // The same requestId replays the failure without another e-mail.
        using (var replayed = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, requestId)))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, replayed.StatusCode);
            using var replayedBody = JsonDocument.Parse(
                await replayed.Content.ReadAsStringAsync());
            Assert.Equal(
                "verification-delivery-unavailable",
                replayedBody.RootElement.GetProperty("error").GetString());
        }
        Assert.Equal(
            expectedDeliveries,
            api.PasswordRecoveryEmailSender.DeliveryAttempts.Count);

        // A new requestId succeeds once the sender is back.
        api.PasswordRecoveryEmailSender.IsAvailable = true;
        api.PasswordRecoveryEmailSender.DeliverySucceeds = true;
        using var retried = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, Guid.NewGuid()));
        Assert.Equal(HttpStatusCode.OK, retried.StatusCode);
        using var retriedBody = JsonDocument.Parse(await retried.Content.ReadAsStringAsync());
        Assert.Equal(
            "completed",
            retriedBody.RootElement.GetProperty("snapshot").GetProperty("status").GetString());
        Assert.Equal(
            expectedDeliveries + 1,
            api.PasswordRecoveryEmailSender.DeliveryAttempts.Count);
    }

    [Fact]
    public async Task RecoverPreviousIdentity_RateLimited_PreservesRecentIdentityAndConflict()
    {
        var conflict = await CreatePhoneConflictAsync();
        var constraint = new PasswordResetIssueConstraint(
            DateTimeOffset.UtcNow.AddHours(-1),
            5);
        for (var index = 0; index < 5; index++)
        {
            var issued = await IssueResetTokenAsync(
                conflict.Previous.IdentityId,
                constraint);
            Assert.True(issued.Succeeded);
        }

        using var response = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, Guid.NewGuid()));

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "password-recovery-rate-limited",
                body.RootElement.GetProperty("error").GetString());
        }
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        await AssertConflictPreservedAsync(conflict, expectedPreviousTokenCount: 5);
    }

    [Fact]
    public async Task RecoverPreviousIdentity_ReservesBeforeSendingAndRevokedSourcePreventsCommit()
    {
        var conflict = await CreatePhoneConflictAsync();
        var requestId = Guid.NewGuid();
        var expectedRevision = conflict.Current.Flow.GetProperty("revision").GetInt32();
        var gate = new AsyncOperationGate();
        api.PasswordRecoveryEmailSender.SendGate = gate;

        var recoveryTask = SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, requestId));

        using var gateDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await gate.WaitUntilEnteredAsync(gateDeadline.Token);
        try
        {
            // The e-mail is in flight: the request is reserved, the token exists and
            // the flow has not moved.
            await using (var scope = api.Services.CreateAsyncScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
                var request = await dbContext.AccessFlowRequests.AsNoTracking().SingleAsync(
                    item => item.RequestId == requestId);
                Assert.Equal(AccessFlowRequestStatus.PendingExternal, request.Status);
                var token = await dbContext.PasswordResetTokens.AsNoTracking().SingleAsync(
                    item => item.IdentityId == conflict.Previous.IdentityId);
                Assert.Null(token.UsedAt);
                var flow = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                    item => item.Id == conflict.Current.FlowId);
                Assert.Equal(AccessFlowStatus.Active, flow.Status);
                Assert.Equal(expectedRevision, flow.CurrentRevision);
            }

            // Other actions on the flow wait for the reservation to settle.
            using (var blocked = await SendWithCapabilityAsync(
                conflict.Current.FlowId,
                conflict.Current.Capability,
                CreateChangePhoneActionBody(conflict, Guid.NewGuid())))
            {
                Assert.Equal(HttpStatusCode.ServiceUnavailable, blocked.StatusCode);
                using var blockedBody = JsonDocument.Parse(
                    await blocked.Content.ReadAsStringAsync());
                Assert.Equal(
                    "verification-delivery-unavailable",
                    blockedBody.RootElement.GetProperty("error").GetString());
            }

            // The registration session dies while the e-mail is still in flight.
            await using (var scope = api.Services.CreateAsyncScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
                var revokedAt = DateTimeOffset.UtcNow;
                var revoked = await dbContext.IdentitySessions
                    .Where(session => session.IdentityId == conflict.Current.IdentityId
                        && session.RevokedAt == null)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(
                        session => session.RevokedAt,
                        revokedAt));
                Assert.Equal(1, revoked);
            }
        }
        finally
        {
            gate.Release();
        }

        using var rejected = await recoveryTask.WaitAsync(TimeSpan.FromSeconds(10));
        api.PasswordRecoveryEmailSender.SendGate = null;
        Assert.Equal(HttpStatusCode.Conflict, rejected.StatusCode);
        using (var rejectedBody = JsonDocument.Parse(
            await rejected.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "registration-not-pending",
                rejectedBody.RootElement.GetProperty("error").GetString());
        }
        var delivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        Assert.Equal(conflict.Previous.Email, delivery.Email);

        // The e-mail went out, so its link is killed; the flow and both identities
        // stay exactly as they were.
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var token = await dbContext.PasswordResetTokens.AsNoTracking().SingleAsync(
                item => item.IdentityId == conflict.Previous.IdentityId);
            Assert.NotNull(token.UsedAt);
            var request = await dbContext.AccessFlowRequests.AsNoTracking().SingleAsync(
                item => item.RequestId == requestId);
            Assert.Equal(AccessFlowRequestStatus.ExternalFailed, request.Status);
            Assert.Null(request.ResultRevision);
            var flow = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                item => item.Id == conflict.Current.FlowId);
            Assert.Equal(AccessFlowStatus.Active, flow.Status);
            Assert.Equal(expectedRevision, flow.CurrentRevision);
            var currentIdentity = await dbContext.Identities.AsNoTracking().SingleAsync(
                identity => identity.Id == conflict.Current.IdentityId);
            Assert.Equal(IdentityLifecycleState.Active, currentIdentity.LifecycleState);
            var currentContext = await dbContext.RegistrationContexts.AsNoTracking()
                .SingleAsync(context => context.IdentityId == conflict.Current.IdentityId);
            Assert.Equal(RegistrationContextStatus.Open, currentContext.Status);
            Assert.True(await dbContext.PhoneRegistrationConflicts.AsNoTracking().AnyAsync(
                item => item.AccessFlowId == conflict.Current.FlowId));
            var phone = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(
                identifier => identifier.Scheme == IdentifierScheme.Phone
                    && identifier.NormalizedValue == conflict.Phone);
            Assert.Equal(conflict.Previous.IdentityId, phone.IdentityId);
        }

        // The same requestId replays the failure; nothing is sent again.
        using (var replayed = await SendWithCapabilityAsync(
            conflict.Current.FlowId,
            conflict.Current.Capability,
            CreateRecoveryActionBody(conflict, requestId)))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, replayed.StatusCode);
            using var replayedBody = JsonDocument.Parse(
                await replayed.Content.ReadAsStringAsync());
            Assert.Equal(
                "verification-delivery-unavailable",
                replayedBody.RootElement.GetProperty("error").GetString());
        }
        Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
    }

    private async Task<PhoneConflictScenario> CreatePhoneConflictAsync()
    {
        var phone = "+15555550123";
        var previous = await RegisterAndStartFlowAsync(
            $"previous-{Guid.NewGuid():N}@example.com");
        var previousVerification = await RequestPhoneAsync(previous, phone);
        var previousCompleted = await ConfirmPhoneAsync(previous, previousVerification);
        Assert.Equal("completed", previousCompleted.GetProperty("status").GetString());

        var current = await RegisterAndStartFlowAsync(
            $"current-{Guid.NewGuid():N}@example.com");
        var currentVerification = await RequestPhoneAsync(current, phone);
        var conflict = await ConfirmPhoneAsync(current, currentVerification);
        Assert.Equal(
            "resolvePhoneConflict",
            conflict.GetProperty("step").GetProperty("type").GetString());
        Assert.Single(
            conflict.GetProperty("actions").EnumerateArray(),
            action => string.Equals(
                action.GetProperty("type").GetString(),
                "recoverPreviousIdentity",
                StringComparison.Ordinal));

        return new PhoneConflictScenario(previous, current with { Flow = conflict }, phone);
    }

    private async Task<StartedRegistration> RegisterAndStartFlowAsync(string email)
    {
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement.GetProperty("identityId").GetGuid();
        var registrationToken = registrationBody.RootElement
            .GetProperty("sessionToken")
            .GetString()!;

        var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = new[] { 1 },
                intent = "continueRegistration",
                applicationClientKey = ApplicationClientKey,
                sessionToken = registrationToken,
            });
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var root = startedBody.RootElement;
        var flow = root.GetProperty("snapshot").Clone();
        return new StartedRegistration(
            email,
            identityId,
            flow.GetProperty("flowId").GetGuid(),
            root.GetProperty("flowCapability").GetString()!,
            flow);
    }

    private async Task<JsonElement> RequestPhoneAsync(
        StartedRegistration registration,
        string phone)
    {
        var action = FindAction(registration.Flow, "requestPhoneVerification");
        using var response = await SendWithCapabilityAsync(
            registration.FlowId,
            registration.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = registration.Flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = action.GetProperty("id").GetGuid(),
                    type = "requestPhoneVerification",
                    input = new { phone },
                },
            });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("snapshot").Clone();
    }

    private async Task<JsonElement> ConfirmPhoneAsync(
        StartedRegistration registration,
        JsonElement verification)
    {
        var action = FindAction(verification, "confirmPhoneVerification");
        using var response = await SendWithCapabilityAsync(
            registration.FlowId,
            registration.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = verification.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = action.GetProperty("id").GetGuid(),
                    type = "confirmPhoneVerification",
                    input = new { code = "123456" },
                },
            });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("snapshot").Clone();
    }

    private async Task<HttpResponseMessage> SendWithCapabilityAsync(
        Guid flowId,
        string capability,
        object body)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions");
        request.Headers.TryAddWithoutValidation(CapabilityHeader, capability);
        request.Content = JsonContent.Create(body);
        return await client.SendAsync(request);
    }

    private async Task<PasswordResetIssueResult> IssueResetTokenAsync(
        Guid identityId,
        PasswordResetIssueConstraint? constraint = null)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var passwordReset = scope.ServiceProvider.GetRequiredService<PasswordResetService>();
        return await passwordReset.IssueAsync(
            identityId,
            appEnvironmentId,
            constraint);
    }

    private async Task AddCurrentSocialCredentialAsync(Guid identityId, string email)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        dbContext.SocialCredentials.Add(new SocialCredential(
            Guid.NewGuid(),
            identityId,
            realmId,
            SocialProvider.Google,
            $"subject-{Guid.NewGuid():N}",
            email,
            DateTimeOffset.UtcNow));
        await dbContext.SaveChangesAsync();
    }

    private async Task AssertConflictPreservedAsync(
        PhoneConflictScenario conflict,
        int expectedPreviousTokenCount)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var currentIdentity = await dbContext.Identities
            .AsNoTracking()
            .SingleAsync(identity => identity.Id == conflict.Current.IdentityId);
        Assert.Equal(IdentityLifecycleState.Active, currentIdentity.LifecycleState);
        var currentContext = await dbContext.RegistrationContexts
            .AsNoTracking()
            .SingleAsync(context => context.IdentityId == conflict.Current.IdentityId);
        Assert.Equal(RegistrationContextStatus.Open, currentContext.Status);
        Assert.Null(currentContext.ClosedAt);
        Assert.True(await dbContext.IdentityIdentifiers
            .AsNoTracking()
            .AnyAsync(identifier => identifier.IdentityId == conflict.Current.IdentityId
                && identifier.Scheme == IdentifierScheme.Email));
        Assert.True(await dbContext.PasswordCredentials
            .AsNoTracking()
            .AnyAsync(credential => credential.IdentityId == conflict.Current.IdentityId));
        Assert.True(await dbContext.IdentitySessions
            .AsNoTracking()
            .AnyAsync(session => session.IdentityId == conflict.Current.IdentityId
                && session.RevokedAt == null));
        Assert.True(await dbContext.PhoneRegistrationConflicts
            .AsNoTracking()
            .AnyAsync(item => item.AccessFlowId == conflict.Current.FlowId));

        var phone = await dbContext.IdentityIdentifiers
            .AsNoTracking()
            .SingleAsync(identifier => identifier.Scheme == IdentifierScheme.Phone
                && identifier.NormalizedValue == conflict.Phone);
        Assert.Equal(conflict.Previous.IdentityId, phone.IdentityId);
        Assert.Equal(
            expectedPreviousTokenCount,
            await dbContext.PasswordResetTokens
                .AsNoTracking()
                .CountAsync(token => token.IdentityId == conflict.Previous.IdentityId));
    }

    private static object CreateRecoveryActionBody(
        PhoneConflictScenario conflict,
        Guid requestId)
    {
        var action = FindAction(conflict.Current.Flow, "recoverPreviousIdentity");
        return new
        {
            requestId,
            expectedRevision = conflict.Current.Flow.GetProperty("revision").GetInt32(),
            action = new
            {
                id = action.GetProperty("id").GetGuid(),
                type = "recoverPreviousIdentity",
            },
        };
    }

    private static object CreateChangePhoneActionBody(
        PhoneConflictScenario conflict,
        Guid requestId)
    {
        var action = FindAction(conflict.Current.Flow, "changePhone");
        return new
        {
            requestId,
            expectedRevision = conflict.Current.Flow.GetProperty("revision").GetInt32(),
            action = new
            {
                id = action.GetProperty("id").GetGuid(),
                type = "changePhone",
            },
        };
    }

    private static JsonElement FindAction(JsonElement snapshot, string type) =>
        Assert.Single(
            snapshot.GetProperty("actions").EnumerateArray(),
            action => string.Equals(
                action.GetProperty("type").GetString(),
                type,
                StringComparison.Ordinal));

    private static BootstrapTopologyCommand CreateBootstrapCommand(
        string suffix,
        bool phoneRequired = false) =>
        new(
            $"phone-conflict-recovery-{suffix}",
            "Phone conflict recovery tests",
            [
                new BootstrapAppDefinition(
                    $"baybo-{suffix}",
                    "BAYBO",
                    [new BootstrapRealmDefinition($"realm-{suffix}", "BAYBO tests")],
                    [
                        new BootstrapEnvironmentDefinition(
                            "tests",
                            "Tests",
                            $"realm-{suffix}",
                            TestAccessPolicies.Create(phoneRequired: phoneRequired),
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(RecoveryUrl),
                            TestEnvironmentConfigurations.Providers(
                                TestAccessPolicies.Create(),
                                RecoveryUrl),
                            TestEnvironmentConfigurations.DevelopmentBypass(
                                TestAccessPolicies.Create()),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "api",
                                    "API",
                                    [
                                        AccessPermission.ExecuteFlows,
                                        AccessPermission.IntrospectSessions,
                                        AccessPermission.ManageCurrentIdentity,
                                    ]),
                            ],
                            [
                                new BootstrapApplicationClientDefinition(
                                    "android-debug",
                                    "Android debug",
                                    ApplicationClientPlatform.Android,
                                    "app.baybo",
                                    "sha256:fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
                                    "92TvTC0UfaA",
                                    JsonSerializer.SerializeToElement(new { })),
                            ]),
                    ]),
            ]);

    private sealed record StartedRegistration(
        string Email,
        Guid IdentityId,
        Guid FlowId,
        string Capability,
        JsonElement Flow);

    private sealed record PhoneConflictScenario(
        StartedRegistration Previous,
        StartedRegistration Current,
        string Phone);
}
