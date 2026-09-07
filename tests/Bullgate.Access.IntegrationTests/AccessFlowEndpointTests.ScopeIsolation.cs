using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed partial class AccessFlowEndpointTests
{
    [Theory]
    [InlineData(false, "missing")]
    [InlineData(true, "missing")]
    [InlineData(false, "malformed")]
    [InlineData(true, "malformed")]
    [InlineData(false, "altered")]
    [InlineData(true, "altered")]
    [InlineData(false, "session-token")]
    [InlineData(true, "session-token")]
    [InlineData(false, "duplicated")]
    [InlineData(true, "duplicated")]
    public async Task FlowAccess_InvalidAuthorityCannotReadOrCompleteRegistration(
        bool act, string presentation)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"invalid-flow-authority-{Guid.NewGuid():N}@example.com");
        var requestId = Guid.NewGuid();
        string[]? capabilities = presentation switch
        {
            "missing" => null,
            "malformed" => ["bgf_short"],
            "altered" => [AlterCapability(registration.Capability)],
            "session-token" => [registration.SourceSessionToken!],
            "duplicated" => [registration.Capability, registration.Capability],
            _ => throw new ArgumentOutOfRangeException(nameof(presentation)),
        };

        using var rejected = await SendScopedFlowRequestAsync(
            client, registration, act, capabilities, requestId);
        await AssertRejectedFlowAccessAsync(rejected);
        await AssertUntouchedActiveFlowAsync(registration);

        // A rejected action must not consume the id or block the authorized decision.
        using var accepted = await SendScopedFlowRequestAsync(
            client, registration, act: true, [registration.Capability], requestId);
        await AssertSingleProductSessionAsync(registration, await ReadSuccessfulResponseAsync(accepted));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FlowAccess_AnotherFlowsCapabilityCannotReadOrCompleteTheTarget(bool act)
    {
        var target = await RegisterAndStartFlowAsync(
            $"target-flow-{Guid.NewGuid():N}@example.com");
        var other = await RegisterAndStartFlowAsync(
            $"other-flow-{Guid.NewGuid():N}@example.com");
        Assert.NotEqual(target.FlowId, other.FlowId);
        Assert.NotEqual(target.Capability, other.Capability);
        var requestId = Guid.NewGuid();

        using var rejected = await SendScopedFlowRequestAsync(
            client, target, act, [other.Capability], requestId);
        await AssertRejectedFlowAccessAsync(rejected);
        await AssertUntouchedActiveFlowAsync(target);
        await AssertUntouchedActiveFlowAsync(other);

        using var accepted = await SendScopedFlowRequestAsync(
            client, target, act: true, [target.Capability], requestId);
        await AssertSingleProductSessionAsync(target, await ReadSuccessfulResponseAsync(accepted));
        await AssertUntouchedActiveFlowAsync(other);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task FlowAccess_AnotherIntegrationCannotUseTheCapabilityEvenInTheSameRealm(
        bool act, bool otherEnvironment)
    {
        var target = await RegisterAndStartFlowAsync(
            $"integration-target-{Guid.NewGuid():N}@example.com");
        using var otherClient = await CreateOtherFlowIntegrationAsync(otherEnvironment);
        var own = await RegisterFlowThroughAsync(otherClient);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var targetFlow = await db.AccessFlows.AsNoTracking().SingleAsync(item => item.Id == target.FlowId);
            var ownFlow = await db.AccessFlows.AsNoTracking().SingleAsync(item => item.Id == own.FlowId);
            Assert.Equal(targetFlow.RealmId, ownFlow.RealmId);
            Assert.NotEqual(targetFlow.IntegrationClientId, ownFlow.IntegrationClientId);
            Assert.Equal(otherEnvironment, targetFlow.AppEnvironmentId != ownFlow.AppEnvironmentId);
        }

        using var rejected = await SendScopedFlowRequestAsync(
            otherClient, target, act, [target.Capability], Guid.NewGuid());
        await AssertRejectedFlowAccessAsync(rejected);
        await AssertUntouchedActiveFlowAsync(target);
        await AssertUntouchedActiveFlowAsync(own, otherClient);

        // Idempotency belongs to each integration: the same id can name independent decisions.
        var sharedRequestId = Guid.NewGuid();
        using var targetCompletion = await SendScopedFlowRequestAsync(
            client, target, act: true, [target.Capability], sharedRequestId);
        var targetResult = await ReadSuccessfulResponseAsync(targetCompletion);
        using var ownCompletion = await SendScopedFlowRequestAsync(
            otherClient, own, act: true, [own.Capability], sharedRequestId);
        var ownResult = await ReadSuccessfulResponseAsync(ownCompletion);
        await AssertSingleProductSessionAsync(target, targetResult);
        await AssertSingleProductSessionAsync(own, ownResult);
        Assert.NotEqual(
            targetResult.GetProperty("issuedSession").GetProperty("sessionToken").GetString(),
            ownResult.GetProperty("issuedSession").GetProperty("sessionToken").GetString());
        await using var finalScope = api.Services.CreateAsyncScope();
        var finalDb = finalScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var requests = await finalDb.AccessFlowRequests.AsNoTracking().Where(
            item => item.RequestId == sharedRequestId).ToListAsync();
        Assert.Equal(2, requests.Count);
        Assert.Equal(2, requests.Select(item => item.IntegrationClientId).Distinct().Count());
        Assert.All(requests, item => Assert.Equal(AccessFlowRequestStatus.Committed, item.Status));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("altered")]
    [InlineData("other-integration")]
    [InlineData("other-environment")]
    public async Task FlowAccess_ExactReplayCannotDiscloseTheCompletedSessionWithoutOriginalAuthority(
        string presentation)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"private-flow-replay-{Guid.NewGuid():N}@example.com");
        var requestId = Guid.NewGuid();
        using var completion = await SendScopedFlowRequestAsync(
            client, registration, act: true, [registration.Capability], requestId);
        var completed = await ReadSuccessfulResponseAsync(completion);
        var before = await ReadIdentityBusinessStateAsync(registration.IdentityId);
        using var otherClient = presentation is "other-integration" or "other-environment"
            ? await CreateOtherFlowIntegrationAsync(presentation == "other-environment")
            : null;
        string[]? capabilities = presentation switch
        {
            "missing" => null,
            "altered" => [AlterCapability(registration.Capability)],
            _ => [registration.Capability],
        };

        using var rejected = await SendScopedFlowRequestAsync(
            otherClient ?? client, registration, act: true, capabilities, requestId);
        await AssertRejectedFlowAccessAsync(rejected);
        Assert.Equal(before, await ReadIdentityBusinessStateAsync(registration.IdentityId));
        await AssertFlowPersistenceAsync(registration, AccessFlowStatus.Completed, revision: 2);

        using var replay = await SendScopedFlowRequestAsync(
            client, registration, act: true, [registration.Capability], requestId);
        var replayed = await ReadSuccessfulResponseAsync(replay);
        Assert.Equal(completed.GetRawText(), replayed.GetRawText());
        await AssertSingleProductSessionAsync(registration, replayed);
        var session = await IntrospectFlowSessionAsync(
            replayed.GetProperty("issuedSession").GetProperty("sessionToken").GetString()!);
        Assert.True(session.GetProperty("active").GetBoolean());
        Assert.Equal(registration.IdentityId, session.GetProperty("identityId").GetGuid());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FlowAccess_UnauthorizedRequestCannotExpireTheFlowAsASideEffect(bool act)
    {
        var registration = await RegisterAndStartFlowAsync(
            $"private-flow-expiry-{Guid.NewGuid():N}@example.com");
        clock.Advance(FlowDuration);

        using var rejected = await SendScopedFlowRequestAsync(
            client, registration, act, [AlterCapability(registration.Capability)], Guid.NewGuid());
        await AssertRejectedFlowAccessAsync(rejected);
        // Even a read can expire a flow, so authority must precede that write.
        await AssertFlowPersistenceAsync(registration, AccessFlowStatus.Active, revision: 1);
        await AssertRegistrationStillPendingAsync(registration);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.Equal(1, await db.AccessFlowRequests.CountAsync(item => item.FlowId == registration.FlowId));
        }

        var expired = await GetFlowSnapshotAsync(registration);
        AssertExpiredSnapshot(expired, revision: 2);
        await AssertRegistrationStillPendingAsync(registration);
        using var restarted = await StartFlowAsync("continueRegistration", registration.SourceSessionToken);
        var replacement = await ReadStartedFlowAsync(
            restarted, registration.IdentityId, registration.SourceSessionToken);
        Assert.NotEqual(registration.FlowId, replacement.FlowId);
        var completed = await ExecuteActionAsync(replacement, replacement.Flow, "skipRegistration");
        await AssertSingleProductSessionAsync(registration, completed);
    }

    private static string AlterCapability(string capability) =>
        capability[..4] + (capability[4] == 'A' ? 'B' : 'A') + capability[5..];

    private static async Task<HttpResponseMessage> SendScopedFlowRequestAsync(
        HttpClient caller,
        StartedRegistration registration,
        bool act,
        string[]? capabilities,
        Guid requestId)
    {
        var path = $"/v1/access/flows/{registration.FlowId:D}";
        using var request = new HttpRequestMessage(
            act ? HttpMethod.Post : HttpMethod.Get, act ? $"{path}/actions" : path);
        if (capabilities is not null)
        {
            Assert.True(request.Headers.TryAddWithoutValidation(CapabilityHeader, capabilities));
        }
        if (act)
        {
            request.Content = JsonContent.Create(new
            {
                requestId,
                expectedRevision = registration.Flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(registration.Flow, "skipRegistration").GetProperty("id").GetGuid(),
                    type = "skipRegistration",
                },
            });
        }
        return await caller.SendAsync(request);
    }

    private static async Task AssertRejectedFlowAccessAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        Assert.Equal("flow-not-found", root.GetProperty("error").GetString());
        Assert.False(root.TryGetProperty("snapshot", out _));
        Assert.False(root.TryGetProperty("flowCapability", out _));
        Assert.False(root.TryGetProperty("issuedSession", out _));
    }

    private async Task AssertUntouchedActiveFlowAsync(
        StartedRegistration registration, HttpClient? caller = null)
    {
        using var response = await SendScopedFlowRequestAsync(
            caller ?? client, registration, act: false, [registration.Capability], Guid.NewGuid());
        var body = await ReadSuccessfulResponseAsync(response);
        Assert.Equal(registration.Flow.GetRawText(), body.GetProperty("snapshot").GetRawText());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("issuedSession").ValueKind);
        await AssertFlowPersistenceAsync(registration, AccessFlowStatus.Active, revision: 1);
        await AssertRegistrationStillPendingAsync(registration);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(1, await db.AccessFlowRequests.CountAsync(item => item.FlowId == registration.FlowId));
        Assert.Empty(await ReadFlowChallengesAsync(registration));
        Assert.Empty(api.PhoneSender.DeliveryAttempts);
    }

    private async Task<StartedRegistration> RegisterFlowThroughAsync(HttpClient caller)
    {
        using var registered = await caller.PostAsJsonAsync("/v1/auth/register",
            new { email = $"scoped-flow-{Guid.NewGuid():N}@example.com", password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, registered.StatusCode);
        using var body = JsonDocument.Parse(await registered.Content.ReadAsStringAsync());
        Assert.Equal("registration", body.RootElement.GetProperty("sessionPurpose").GetString());
        var identityId = body.RootElement.GetProperty("identityId").GetGuid();
        var sessionToken = body.RootElement.GetProperty("sessionToken").GetString();
        using var started = await StartFlowAsync(
            "continueRegistration", sessionToken, integrationClient: caller);
        return await ReadStartedFlowAsync(started, identityId, sessionToken);
    }

    private async Task<HttpClient> CreateOtherFlowIntegrationAsync(bool otherEnvironment)
    {
        string credential;
        if (!otherEnvironment)
        {
            (credential, _) = await RegisterSecondaryClientsAsync();
        }
        else
        {
            var command = CreateBootstrapCommand(topologySuffix);
            var app = Assert.Single(command.Apps);
            var environment = Assert.Single(app.Environments);
            var sibling = environment with { Key = "sibling", Name = "Sibling environment" };
            command = command with { Apps = [app with { Environments = [environment, sibling] }] };
            await using var scope = api.Services.CreateAsyncScope();
            var bootstrap = await scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>()
                .HandleAsync(command);
            var issued = Assert.Single(bootstrap.IssuedCredentials);
            Assert.EndsWith("/sibling/integration-clients/api", issued.IntegrationClientPath, StringComparison.Ordinal);
            credential = issued.Token;
        }
        var caller = api.CreateClient();
        caller.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        return caller;
    }
}
