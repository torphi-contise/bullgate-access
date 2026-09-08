using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed partial class AccessFlowEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private static readonly int[] ProtocolVersion1 = [1];
    private static readonly int[] ProtocolVersions1And2 = [1, 2];
    private const string CapabilityHeader = "Bullgate-Flow-Capability";
    private static readonly TimeSpan FlowDuration = TimeSpan.FromMinutes(30);

    // The clock starts at the real time (whole seconds, so timestamps survive the
    // PostgreSQL round trip) and only moves when a test advances it explicitly.
    private readonly AdjustableTimeProvider clock = new(
        DateTimeOffset.UnixEpoch.AddSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private const string ApplicationClientKey = "android-debug";
    private string topologySuffix = null!;

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
            topologySuffix = Guid.NewGuid().ToString("N");
            bootstrap = await handler.HandleAsync(CreateBootstrapCommand(topologySuffix));
        }

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
    public async Task ContinueRegistrationFlow_IsIdempotentAndPromotesTheSessionOnSkip()
    {
        var email = $"flow-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);

        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var registrationRoot = registrationBody.RootElement;
        var identityId = registrationRoot.GetProperty("identityId").GetGuid();
        var registrationToken = registrationRoot.GetProperty("sessionToken").GetString();
        Assert.Equal(
            "registration",
            registrationRoot.GetProperty("sessionPurpose").GetString());

        var startRequestId = Guid.NewGuid();
        var startBody = new
        {
            requestId = startRequestId,
            protocolVersions = new[] { 1 },
            intent = "continueRegistration",
            applicationClientKey = ApplicationClientKey,
            sessionToken = registrationToken,
        };
        var started = await client.PostAsJsonAsync("/v1/access/flows", startBody);
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);

        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var startedRoot = startedBody.RootElement;
        var capability = startedRoot.GetProperty("flowCapability").GetString();
        var snapshot = startedRoot.GetProperty("snapshot");
        var flowId = snapshot.GetProperty("flowId").GetGuid();
        var action = FindAction(snapshot, "skipRegistration");
        var actionId = action.GetProperty("id").GetGuid();
        Assert.StartsWith("bgf_", capability, StringComparison.Ordinal);
        Assert.Equal(1, snapshot.GetProperty("revision").GetInt32());
        Assert.Equal("active", snapshot.GetProperty("status").GetString());
        Assert.Equal("skipRegistration", action.GetProperty("type").GetString());

        var startRetry = await client.PostAsJsonAsync("/v1/access/flows", startBody);
        Assert.Equal(HttpStatusCode.Created, startRetry.StatusCode);
        using (var retryBody = JsonDocument.Parse(
            await startRetry.Content.ReadAsStringAsync()))
        {
            var retryRoot = retryBody.RootElement;
            Assert.Equal(
                capability,
                retryRoot.GetProperty("flowCapability").GetString());
            Assert.Equal(
                flowId,
                retryRoot.GetProperty("snapshot").GetProperty("flowId").GetGuid());
            Assert.Equal(
                actionId,
                FindAction(
                    retryRoot.GetProperty("snapshot"),
                    "skipRegistration")
                    .GetProperty("id")
                    .GetGuid());
        }

        var conflictingStart = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = startRequestId,
                protocolVersions = ProtocolVersions1And2,
                intent = "continueRegistration",
                applicationClientKey = ApplicationClientKey,
                sessionToken = registrationToken,
            });
        Assert.Equal(HttpStatusCode.Conflict, conflictingStart.StatusCode);

        using (var wrongCapability = await SendWithCapabilityAsync(
            HttpMethod.Get,
            $"/v1/access/flows/{flowId:D}",
            "bgf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            null))
        {
            Assert.Equal(HttpStatusCode.NotFound, wrongCapability.StatusCode);
        }

        using (var getResponse = await SendWithCapabilityAsync(
            HttpMethod.Get,
            $"/v1/access/flows/{flowId:D}",
            capability,
            null))
        {
            Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        }

        var actionRequestId = Guid.NewGuid();
        var actionBody = new
        {
            requestId = actionRequestId,
            expectedRevision = 1,
            action = new { id = actionId, type = "skipRegistration" },
        };
        using var completed = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            actionBody);
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);

        using var completedBody = JsonDocument.Parse(
            await completed.Content.ReadAsStringAsync());
        var completedRoot = completedBody.RootElement;
        var completedSnapshot = completedRoot.GetProperty("snapshot");
        var issuedSession = completedRoot.GetProperty("issuedSession");
        var productSessionToken = issuedSession.GetProperty("sessionToken").GetString();
        var productSessionId = issuedSession.GetProperty("sessionId").GetGuid();
        Assert.Equal(2, completedSnapshot.GetProperty("revision").GetInt32());
        Assert.Equal("completed", completedSnapshot.GetProperty("status").GetString());
        Assert.Equal(
            "skipped",
            completedSnapshot.GetProperty("result").GetProperty("outcome").GetString());
        Assert.Equal("product", issuedSession.GetProperty("purpose").GetString());

        using var actionRetry = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            actionBody);
        Assert.Equal(HttpStatusCode.OK, actionRetry.StatusCode);
        using (var actionRetryBody = JsonDocument.Parse(
            await actionRetry.Content.ReadAsStringAsync()))
        {
            var retrySession = actionRetryBody.RootElement.GetProperty("issuedSession");
            Assert.Equal(
                productSessionToken,
                retrySession.GetProperty("sessionToken").GetString());
            Assert.Equal(
                productSessionId,
                retrySession.GetProperty("sessionId").GetGuid());
        }

        var oldIntrospection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = registrationToken });
        using (var oldBody = JsonDocument.Parse(
            await oldIntrospection.Content.ReadAsStringAsync()))
        {
            Assert.False(oldBody.RootElement.GetProperty("active").GetBoolean());
        }

        var productIntrospection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = productSessionToken });
        using (var productBody = JsonDocument.Parse(
            await productIntrospection.Content.ReadAsStringAsync()))
        {
            var root = productBody.RootElement;
            Assert.True(root.GetProperty("active").GetBoolean());
            Assert.Equal(identityId, root.GetProperty("identityId").GetGuid());
            Assert.Equal("product", root.GetProperty("sessionPurpose").GetString());
        }

        var login = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using (var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "product",
                loginBody.RootElement.GetProperty("sessionPurpose").GetString());
        }

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var context = await dbContext.RegistrationContexts
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(RegistrationContextStatus.Completed, context.Status);
    }

    [Fact]
    public async Task PhoneWithoutVerification_IsSubmittedAndStoredAsUnverified()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneRequired: true,
            phoneVerificationEnabled: false));
        var registration = await RegisterAndStartFlowAsync(
            $"unverified-phone-{Guid.NewGuid():N}@example.com");

        Assert.Equal(
            "collectPhone",
            registration.Flow.GetProperty("step").GetProperty("type").GetString());
        var submit = FindAction(registration.Flow, "submitPhone");
        Assert.DoesNotContain(
            registration.Flow.GetProperty("actions").EnumerateArray(),
            action => string.Equals(
                action.GetProperty("type").GetString(),
                "skipRegistration",
                StringComparison.Ordinal));

        using var response = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = registration.Flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = submit.GetProperty("id").GetGuid(),
                    type = "submitPhone",
                    input = new { phone = "+5511976695464" },
                },
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        Assert.Equal(
            "completed",
            root.GetProperty("snapshot").GetProperty("status").GetString());
        Assert.Equal(
            "phoneCollected",
            root.GetProperty("snapshot").GetProperty("result").GetProperty("outcome").GetString());
        Assert.Equal(
            "product",
            root.GetProperty("issuedSession").GetProperty("purpose").GetString());

        var sessionToken = root.GetProperty("issuedSession")
            .GetProperty("sessionToken")
            .GetString();
        using (var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken }))
        {
            Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
            using var introspectionBody = JsonDocument.Parse(
                await introspection.Content.ReadAsStringAsync());
            var session = introspectionBody.RootElement;
            Assert.Equal(
                "+5511976695464",
                session.GetProperty("phone").GetString());
            Assert.Equal(
                JsonValueKind.Null,
                session.GetProperty("phoneVerifiedAt").ValueKind);
        }

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var phone = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(
            identifier => identifier.IdentityId == registration.IdentityId
                && identifier.Scheme == IdentifierScheme.Phone);
        Assert.Equal("+5511976695464", phone.NormalizedValue);
        Assert.Null(phone.VerifiedAt);
        Assert.Null(phone.VerificationMethod);
    }

    [Fact]
    public async Task ManagePhone_StartsWithoutInputAndReplacesThePhoneAndSession()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            phoneVerificationEnabled: false));
        var email = $"manage-phone-{Guid.NewGuid():N}@example.test";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement.GetProperty("identityId").GetGuid();
        var sourceSessionToken = registrationBody.RootElement
            .GetProperty("sessionToken")
            .GetString();
        Assert.Equal(
            "product",
            registrationBody.RootElement.GetProperty("sessionPurpose").GetString());

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identity = await dbContext.Identities.AsNoTracking().SingleAsync(
                item => item.Id == identityId);
            var now = clock.GetUtcNow();
            dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
                Guid.CreateVersion7(now),
                identityId,
                identity.RealmId,
                IdentifierScheme.Phone,
                "+5511988880001",
                now,
                now,
                "seed"));
            await dbContext.SaveChangesAsync();
        }
        var recoveryArtifacts = await SeedActiveRecoveryArtifactsAsync(
            identityId,
            "+5511988880001");

        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneRequired: true,
            phoneVerificationEnabled: false));
        var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = ProtocolVersion1,
                intent = "managePhone",
                applicationClientKey = ApplicationClientKey,
                sessionToken = sourceSessionToken,
            });

        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var startedRoot = startedBody.RootElement;
        var capability = startedRoot.GetProperty("flowCapability").GetString();
        var snapshot = startedRoot.GetProperty("snapshot");
        var flowId = snapshot.GetProperty("flowId").GetGuid();
        Assert.Equal("managePhone", snapshot.GetProperty("intent").GetString());
        Assert.Equal(
            "collectPhone",
            snapshot.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(["submitPhone"], ActionTypes(snapshot));

        var submit = FindAction(snapshot, "submitPhone");
        using var completed = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = snapshot.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = submit.GetProperty("id").GetGuid(),
                    type = "submitPhone",
                    input = new { phone = "+5511977770002" },
                },
            });

        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);
        using var completedBody = JsonDocument.Parse(
            await completed.Content.ReadAsStringAsync());
        var completedRoot = completedBody.RootElement;
        Assert.Equal(
            "phoneChanged",
            completedRoot.GetProperty("snapshot")
                .GetProperty("result")
                .GetProperty("outcome")
                .GetString());
        var replacementToken = completedRoot.GetProperty("issuedSession")
            .GetProperty("sessionToken")
            .GetString();
        Assert.Equal(
            "product",
            completedRoot.GetProperty("issuedSession").GetProperty("purpose").GetString());

        using (var oldSession = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = sourceSessionToken }))
        {
            oldSession.EnsureSuccessStatusCode();
            using var body = JsonDocument.Parse(await oldSession.Content.ReadAsStringAsync());
            Assert.False(body.RootElement.GetProperty("active").GetBoolean());
        }
        using (var newSession = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = replacementToken }))
        {
            newSession.EnsureSuccessStatusCode();
            using var body = JsonDocument.Parse(await newSession.Content.ReadAsStringAsync());
            Assert.True(body.RootElement.GetProperty("active").GetBoolean());
            Assert.Equal(
                "+5511977770002",
                body.RootElement.GetProperty("phone").GetString());
        }

        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        var storedFlow = await verification.AccessFlows.AsNoTracking().SingleAsync(
            flow => flow.Id == flowId);
        Assert.Null(storedFlow.RegistrationContextId);
        var phone = await verification.IdentityIdentifiers.AsNoTracking().SingleAsync(
            identifier => identifier.IdentityId == identityId
                && identifier.Scheme == IdentifierScheme.Phone);
        Assert.Equal("+5511977770002", phone.NormalizedValue);
        Assert.Null(phone.VerifiedAt);
        await AssertRecoveryArtifactsInvalidatedAsync(
            verification,
            recoveryArtifacts);
    }

    [Fact]
    public async Task ManagePhone_WithVerificationReusesThePhoneProofMachine()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            phoneVerificationEnabled: false));
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"manage-phone-proof-{Guid.NewGuid():N}@example.test",
                password = "password-123",
            });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement.GetProperty("identityId").GetGuid();
        var sourceSessionToken = registrationBody.RootElement
            .GetProperty("sessionToken")
            .GetString();

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identity = await dbContext.Identities.AsNoTracking().SingleAsync(
                item => item.Id == identityId);
            var now = clock.GetUtcNow();
            dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
                Guid.CreateVersion7(now),
                identityId,
                identity.RealmId,
                IdentifierScheme.Phone,
                "+5511988880003",
                now,
                now,
                "seed"));
            await dbContext.SaveChangesAsync();
        }
        var recoveryArtifacts = await SeedActiveRecoveryArtifactsAsync(
            identityId,
            "+5511988880003");

        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneRequired: true));
        var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = ProtocolVersion1,
                intent = "managePhone",
                applicationClientKey = ApplicationClientKey,
                sessionToken = sourceSessionToken,
            });
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var startedRoot = startedBody.RootElement;
        var capability = startedRoot.GetProperty("flowCapability").GetString()!;
        var collect = startedRoot.GetProperty("snapshot").Clone();
        var flowId = collect.GetProperty("flowId").GetGuid();
        Assert.Equal(["requestPhoneVerification"], ActionTypes(collect));
        var managed = new StartedRegistration(identityId, flowId, capability, collect);

        var requested = await ExecuteActionAsync(
            managed,
            collect,
            "requestPhoneVerification",
            new { phone = "+15555550123" });
        var verify = requested.GetProperty("snapshot").Clone();
        Assert.Equal(
            "verifyPhone",
            verify.GetProperty("step").GetProperty("type").GetString());
        Assert.DoesNotContain("skipRegistration", ActionTypes(verify));

        var completed = await ExecuteActionAsync(
            managed,
            verify,
            "confirmPhoneVerification",
            new { code = "123456" });
        Assert.Equal(
            "completed",
            completed.GetProperty("snapshot").GetProperty("status").GetString());
        Assert.Equal(
            "phoneVerified",
            completed.GetProperty("snapshot")
                .GetProperty("result")
                .GetProperty("outcome")
                .GetString());
        Assert.Equal(
            "product",
            completed.GetProperty("issuedSession").GetProperty("purpose").GetString());

        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        var phone = await verification.IdentityIdentifiers.AsNoTracking().SingleAsync(
            identifier => identifier.IdentityId == identityId
                && identifier.Scheme == IdentifierScheme.Phone);
        Assert.Equal("+15555550123", phone.NormalizedValue);
        Assert.NotNull(phone.VerifiedAt);
        Assert.Equal("sms", phone.VerificationMethod);
        var proof = await verification.IdentityProofs.AsNoTracking().SingleAsync(
            item => item.IdentityId == identityId
                && item.Type == ProofChallengeType.PhonePossession);
        Assert.Equal(flowId, proof.AccessFlowId);
        Assert.Equal(phone.Id, proof.SubjectIdentifierId);
        await AssertRecoveryArtifactsInvalidatedAsync(
            verification,
            recoveryArtifacts);
    }

    [Fact]
    public async Task SkipRegistration_RejectsAFlowWhoseSourceSessionWasRevoked()
    {
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"revoked-{Guid.NewGuid():N}@example.com",
                password = "password-123",
            });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var registrationToken = registrationBody.RootElement
            .GetProperty("sessionToken")
            .GetString();

        var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = ProtocolVersion1,
                intent = "continueRegistration",
                applicationClientKey = ApplicationClientKey,
                sessionToken = registrationToken,
            });
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var startedRoot = startedBody.RootElement;
        var capability = startedRoot.GetProperty("flowCapability").GetString();
        var snapshot = startedRoot.GetProperty("snapshot");
        var flowId = snapshot.GetProperty("flowId").GetGuid();
        var action = FindAction(snapshot, "skipRegistration");

        var revoke = await client.PostAsJsonAsync(
            "/v1/auth/session/revoke",
            new { sessionToken = registrationToken });
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        using var rejected = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = 1,
                action = new
                {
                    id = action.GetProperty("id").GetGuid(),
                    type = action.GetProperty("type").GetString(),
                },
            });
        Assert.Equal(HttpStatusCode.Conflict, rejected.StatusCode);
        using var rejectedBody = JsonDocument.Parse(
            await rejected.Content.ReadAsStringAsync());
        Assert.Equal(
            "registration-not-pending",
            rejectedBody.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task PhonePossession_PersistsProofAndReplaysCompletedConfirmation()
    {
        var email = $"phone-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var registrationRoot = registrationBody.RootElement;
        var identityId = registrationRoot.GetProperty("identityId").GetGuid();
        var registrationToken = registrationRoot.GetProperty("sessionToken").GetString();

        var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = ProtocolVersion1,
                intent = "continueRegistration",
                applicationClientKey = ApplicationClientKey,
                sessionToken = registrationToken,
            });
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var startedRoot = startedBody.RootElement;
        var capability = startedRoot.GetProperty("flowCapability").GetString();
        var initial = startedRoot.GetProperty("snapshot");
        var flowId = initial.GetProperty("flowId").GetGuid();
        Assert.Equal(
            "collectPhone",
            initial.GetProperty("step").GetProperty("type").GetString());

        var verificationRequestId = Guid.NewGuid();
        using var requested = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            new
            {
                requestId = verificationRequestId,
                expectedRevision = 1,
                action = new
                {
                    id = FindAction(initial, "requestPhoneVerification")
                        .GetProperty("id")
                        .GetGuid(),
                    type = "requestPhoneVerification",
                    input = new { phone = "+15555550123" },
                },
            });
        Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        using var requestedBody = JsonDocument.Parse(
            await requested.Content.ReadAsStringAsync());
        var verification = requestedBody.RootElement.GetProperty("snapshot");
        Assert.Equal(2, verification.GetProperty("revision").GetInt32());
        Assert.Equal(
            "verifyPhone",
            verification.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(
            "+15*****0123",
            verification.GetProperty("step").GetProperty("destination").GetString());

        using var failed = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = 2,
                action = new
                {
                    id = FindAction(verification, "confirmPhoneVerification")
                        .GetProperty("id")
                        .GetGuid(),
                    type = "confirmPhoneVerification",
                    input = new { code = "000000" },
                },
            });
        Assert.Equal(HttpStatusCode.OK, failed.StatusCode);
        using var failedBody = JsonDocument.Parse(await failed.Content.ReadAsStringAsync());
        var retry = failedBody.RootElement.GetProperty("snapshot");
        Assert.Equal(3, retry.GetProperty("revision").GetInt32());
        Assert.Equal(
            "phone-verification-invalid-code",
            retry.GetProperty("feedback").GetProperty("code").GetString());

        var confirmationAction = FindAction(retry, "confirmPhoneVerification");
        var confirmationRequestId = confirmationAction.GetProperty("id").GetGuid();
        var confirmationBody = new
        {
            requestId = confirmationRequestId,
            expectedRevision = 3,
            action = new
            {
                id = confirmationAction.GetProperty("id").GetGuid(),
                type = "confirmPhoneVerification",
                input = new { code = "123456" },
            },
        };
        using var confirmed = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            confirmationBody);
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        using var confirmedBody = JsonDocument.Parse(
            await confirmed.Content.ReadAsStringAsync());
        var confirmedRoot = confirmedBody.RootElement;
        Assert.Equal(
            "completed",
            confirmedRoot.GetProperty("snapshot").GetProperty("status").GetString());
        Assert.Equal(
            "phoneVerified",
            confirmedRoot.GetProperty("snapshot")
                .GetProperty("result")
                .GetProperty("outcome")
                .GetString());
        Assert.Equal(
            "product",
            confirmedRoot.GetProperty("issuedSession").GetProperty("purpose").GetString());

        var productSessionToken = confirmedRoot.GetProperty("issuedSession")
            .GetProperty("sessionToken")
            .GetString();
        using (var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = productSessionToken }))
        {
            Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
            using var introspectionBody = JsonDocument.Parse(
                await introspection.Content.ReadAsStringAsync());
            var session = introspectionBody.RootElement;
            Assert.Equal(
                "+15555550123",
                session.GetProperty("phone").GetString());
            Assert.NotEqual(
                JsonValueKind.Null,
                session.GetProperty("phoneVerifiedAt").ValueKind);
        }

        using var confirmedRetry = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flowId:D}/actions",
            capability,
            confirmationBody);
        Assert.Equal(HttpStatusCode.OK, confirmedRetry.StatusCode);
        using var confirmedRetryBody = JsonDocument.Parse(
            await confirmedRetry.Content.ReadAsStringAsync());
        var confirmedRetryRoot = confirmedRetryBody.RootElement;
        Assert.Equal(
            confirmedRoot.GetProperty("snapshot").GetRawText(),
            confirmedRetryRoot.GetProperty("snapshot").GetRawText());
        Assert.Equal(
            confirmedRoot.GetProperty("issuedSession").GetProperty("sessionId").GetGuid(),
            confirmedRetryRoot.GetProperty("issuedSession").GetProperty("sessionId").GetGuid());
        Assert.Equal(
            confirmedRoot.GetProperty("issuedSession").GetProperty("sessionToken").GetString(),
            confirmedRetryRoot.GetProperty("issuedSession").GetProperty("sessionToken").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var phone = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(
            identifier => identifier.IdentityId == identityId
                && identifier.Scheme == IdentifierScheme.Phone);
        Assert.Equal("+15555550123", phone.NormalizedValue);
        Assert.NotNull(phone.VerifiedAt);
        Assert.Equal("sms", phone.VerificationMethod);
        Assert.Equal(2, await dbContext.ProofAttempts.CountAsync());
        Assert.Single(await dbContext.IdentityProofs.AsNoTracking().ToListAsync());
        Assert.Single(await dbContext.IdentitySessions.AsNoTracking().Where(
            session => session.IdentityId == identityId
                && session.Purpose == IdentitySessionPurpose.Product).ToListAsync());
        var verificationRequest = await dbContext.AccessFlowRequests.AsNoTracking()
            .SingleAsync(request => request.RequestId == verificationRequestId);
        Assert.Equal(AccessFlowRequestStatus.Committed, verificationRequest.Status);
        Assert.Equal(2, verificationRequest.ResultRevision);
        var confirmationRequest = await dbContext.AccessFlowRequests.AsNoTracking()
            .SingleAsync(request => request.RequestId == confirmationRequestId);
        Assert.Equal(AccessFlowRequestStatus.Committed, confirmationRequest.Status);
        Assert.Equal(4, confirmationRequest.ResultRevision);
        var challenge = await dbContext.ProofChallenges.AsNoTracking().SingleAsync(
            item => item.IdentityId == identityId);
        Assert.Equal(ProofChallengeStatus.Verified, challenge.Status);
        Assert.Null(challenge.ProviderReference);
        Assert.Empty(api.PhoneSender.DeliveryAttempts);
        Assert.Empty(api.PhoneSender.ApprovalAttempts);
    }

    [Fact]
    public async Task PhoneDelivery_ReservesBeforeProviderAndBlocksConcurrentActionsUntilFinalized()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"delivery-gate-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654321";
        var initialRevision = registration.Flow.GetProperty("revision").GetInt32();
        var requestId = Guid.NewGuid();
        var action = FindAction(registration.Flow, "requestPhoneVerification");
        var gate = new AsyncOperationGate();
        api.PhoneSender.SendGate = gate;

        var deliveryTask = SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId,
                expectedRevision = initialRevision,
                action = new
                {
                    id = action.GetProperty("id").GetGuid(),
                    type = "requestPhoneVerification",
                    input = new { phone },
                },
            });

        using var gateDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await gate.WaitUntilEnteredAsync(gateDeadline.Token);
        try
        {
            await using (var pendingScope = api.Services.CreateAsyncScope())
            {
                var dbContext = pendingScope.ServiceProvider
                    .GetRequiredService<AccessDbContext>();
                var flow = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                    item => item.Id == registration.FlowId);
                Assert.Equal(initialRevision, flow.CurrentRevision);
                Assert.Equal(
                    1,
                    await dbContext.AccessFlowRevisions.AsNoTracking().CountAsync(
                        revision => revision.FlowId == registration.FlowId));

                var challenge = await dbContext.ProofChallenges.AsNoTracking().SingleAsync(
                    item => item.AccessFlowId == registration.FlowId);
                Assert.Equal(ProofChallengeStatus.PendingDelivery, challenge.Status);
                Assert.Null(challenge.ProviderReference);
                Assert.Null(challenge.CompletedAt);

                var pendingRequest = await dbContext.AccessFlowRequests.AsNoTracking()
                    .SingleAsync(request => request.RequestId == requestId);
                Assert.Equal(
                    AccessFlowRequestStatus.PendingExternal,
                    pendingRequest.Status);
                Assert.Null(pendingRequest.ResultRevision);
            }

            var visibleSnapshot = await GetFlowSnapshotAsync(registration);
            Assert.Equal(registration.Flow.GetRawText(), visibleSnapshot.GetRawText());

            using var concurrent = await SendWithCapabilityAsync(
                    HttpMethod.Post,
                    $"/v1/access/flows/{registration.FlowId:D}/actions",
                    registration.Capability,
                    new
                    {
                        requestId = Guid.NewGuid(),
                        expectedRevision = initialRevision,
                        action = new
                        {
                            id = action.GetProperty("id").GetGuid(),
                            type = "requestPhoneVerification",
                            input = new { phone },
                        },
                    })
                .WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, concurrent.StatusCode);
            using var concurrentBody = JsonDocument.Parse(
                await concurrent.Content.ReadAsStringAsync());
            Assert.Equal(
                "verification-delivery-unavailable",
                concurrentBody.RootElement.GetProperty("error").GetString());
        }
        finally
        {
            gate.Release();
        }

        using var delivered = await deliveryTask.WaitAsync(TimeSpan.FromSeconds(10));
        api.PhoneSender.SendGate = null;
        Assert.Equal(HttpStatusCode.OK, delivered.StatusCode);
        using var deliveredBody = JsonDocument.Parse(
            await delivered.Content.ReadAsStringAsync());
        var finalizedSnapshot = deliveredBody.RootElement.GetProperty("snapshot");
        Assert.Equal(
            initialRevision + 1,
            finalizedSnapshot.GetProperty("revision").GetInt32());
        Assert.Equal(
            "verifyPhone",
            finalizedSnapshot.GetProperty("step").GetProperty("type").GetString());

        await using var finalizedScope = api.Services.CreateAsyncScope();
        var finalizedDbContext = finalizedScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        var finalizedFlow = await finalizedDbContext.AccessFlows.AsNoTracking().SingleAsync(
            item => item.Id == registration.FlowId);
        Assert.Equal(initialRevision + 1, finalizedFlow.CurrentRevision);
        Assert.Equal(
            2,
            await finalizedDbContext.AccessFlowRevisions.AsNoTracking().CountAsync(
                revision => revision.FlowId == registration.FlowId));
        var finalizedChallenge = await finalizedDbContext.ProofChallenges.AsNoTracking()
            .SingleAsync(item => item.AccessFlowId == registration.FlowId);
        Assert.Equal(ProofChallengeStatus.Active, finalizedChallenge.Status);
        Assert.NotNull(finalizedChallenge.ProviderReference);
        Assert.Null(finalizedChallenge.CompletedAt);
        var finalizedRequest = await finalizedDbContext.AccessFlowRequests.AsNoTracking()
            .SingleAsync(request => request.RequestId == requestId);
        Assert.Equal(AccessFlowRequestStatus.Committed, finalizedRequest.Status);
        Assert.Equal(initialRevision + 1, finalizedRequest.ResultRevision);
    }

    [Fact]
    public async Task PhoneDeliveryFailure_LeavesTheFlowUnchangedAndAllowsANewRequest()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"delivery-failure-{Guid.NewGuid():N}@example.com");
        const string phone = "+5511987654322";
        var initialRevision = registration.Flow.GetProperty("revision").GetInt32();
        var action = FindAction(registration.Flow, "requestPhoneVerification");
        var failedRequestId = Guid.NewGuid();
        api.PhoneSender.RejectDelivery = true;

        using var failed = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId = failedRequestId,
                expectedRevision = initialRevision,
                action = new
                {
                    id = action.GetProperty("id").GetGuid(),
                    type = "requestPhoneVerification",
                    input = new { phone },
                },
            });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
        using (var failedBody = JsonDocument.Parse(
            await failed.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "verification-delivery-unavailable",
                failedBody.RootElement.GetProperty("error").GetString());
        }

        await using (var failedScope = api.Services.CreateAsyncScope())
        {
            var dbContext = failedScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var flow = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                item => item.Id == registration.FlowId);
            Assert.Equal(initialRevision, flow.CurrentRevision);
            Assert.Equal(
                1,
                await dbContext.AccessFlowRevisions.AsNoTracking().CountAsync(
                    revision => revision.FlowId == registration.FlowId));
            var challenge = await dbContext.ProofChallenges.AsNoTracking().SingleAsync(
                item => item.AccessFlowId == registration.FlowId);
            Assert.Equal(ProofChallengeStatus.DeliveryFailed, challenge.Status);
            Assert.NotNull(challenge.CompletedAt);
            var request = await dbContext.AccessFlowRequests.AsNoTracking().SingleAsync(
                item => item.RequestId == failedRequestId);
            Assert.Equal(AccessFlowRequestStatus.ExternalFailed, request.Status);
            Assert.Null(request.ResultRevision);
        }

        var visibleSnapshot = await GetFlowSnapshotAsync(registration);
        Assert.Equal(registration.Flow.GetRawText(), visibleSnapshot.GetRawText());

        api.PhoneSender.RejectDelivery = false;
        var retryRequestId = Guid.NewGuid();
        using var retried = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId = retryRequestId,
                expectedRevision = initialRevision,
                action = new
                {
                    id = action.GetProperty("id").GetGuid(),
                    type = "requestPhoneVerification",
                    input = new { phone },
                },
            });
        Assert.Equal(HttpStatusCode.OK, retried.StatusCode);
        using var retriedBody = JsonDocument.Parse(
            await retried.Content.ReadAsStringAsync());
        Assert.Equal(
            initialRevision + 1,
            retriedBody.RootElement.GetProperty("snapshot").GetProperty("revision").GetInt32());

        await using var retriedScope = api.Services.CreateAsyncScope();
        var retriedDbContext = retriedScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        var challenges = await retriedDbContext.ProofChallenges.AsNoTracking()
            .Where(item => item.AccessFlowId == registration.FlowId)
            .ToListAsync();
        Assert.Single(
            challenges,
            challenge => challenge.Status == ProofChallengeStatus.DeliveryFailed);
        Assert.Single(
            challenges,
            challenge => challenge.Status == ProofChallengeStatus.Active);
        var retryRequest = await retriedDbContext.AccessFlowRequests.AsNoTracking()
            .SingleAsync(request => request.RequestId == retryRequestId);
        Assert.Equal(AccessFlowRequestStatus.Committed, retryRequest.Status);
        Assert.Equal(initialRevision + 1, retryRequest.ResultRevision);
        Assert.Equal(2, api.PhoneSender.DeliveryAttempts.Count);
    }

    [Fact]
    public async Task PhonePossession_UsesLocalHashWithoutProviderApproval()
    {
        var email = $"provider-failure-{Guid.NewGuid():N}@example.com";
        var registration = await RegisterAndStartFlowAsync(email);
        const string phone = "+5511999999999";

        using var requested = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = registration.Flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(registration.Flow, "requestPhoneVerification")
                        .GetProperty("id")
                        .GetGuid(),
                    type = "requestPhoneVerification",
                    input = new { phone },
                },
            });
        Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        using var requestedBody = JsonDocument.Parse(
            await requested.Content.ReadAsStringAsync());
        var verification = requestedBody.RootElement.GetProperty("snapshot").Clone();
        var code = Assert.IsType<string>(api.PhoneSender.LastCode);
        api.PhoneSender.RejectApproval = true;

        using var confirmed = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = verification.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(verification, "confirmPhoneVerification")
                        .GetProperty("id")
                        .GetGuid(),
                    type = "confirmPhoneVerification",
                    input = new { code },
                },
            });
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        using var confirmedBody = JsonDocument.Parse(
            await confirmed.Content.ReadAsStringAsync());
        Assert.Equal(
            "completed",
            confirmedBody.RootElement
                .GetProperty("snapshot")
                .GetProperty("status")
                .GetString());
        Assert.Empty(api.PhoneSender.ApprovalAttempts);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var identifier = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(
            identifier => identifier.IdentityId == registration.IdentityId
                && identifier.Scheme == IdentifierScheme.Phone);
        Assert.NotNull(identifier.VerifiedAt);
        Assert.True(await dbContext.IdentityProofs.AsNoTracking().AnyAsync(
            proof => proof.IdentityId == registration.IdentityId));
        Assert.True(await dbContext.IdentitySessions.AsNoTracking().AnyAsync(
            session => session.IdentityId == registration.IdentityId
                && session.Purpose == IdentitySessionPurpose.Product));
        var challenge = await dbContext.ProofChallenges.AsNoTracking().SingleAsync(
            item => item.IdentityId == registration.IdentityId
                && item.DestinationValue == phone);
        Assert.Equal(ProofChallengeStatus.Verified, challenge.Status);
        Assert.NotNull(challenge.CompletedAt);
    }

    [Fact]
    public async Task PhoneConflict_MovesOnlyThePhoneAfterMatchingPreviousEmail()
    {
        var previousEmail = $"previous-{Guid.NewGuid():N}@example.com";
        var previous = await RegisterAndStartFlowAsync(previousEmail);
        var previousVerification = await RequestPhoneAsync(
            previous.Flow,
            previous.Capability);
        var previousCompleted = await ConfirmPhoneAsync(
            previousVerification,
            previous.Capability,
            "123456");
        Assert.Equal("completed", previousCompleted.GetProperty("status").GetString());
        DateTimeOffset previousVerificationAt;
        await using (var previousScope = api.Services.CreateAsyncScope())
        {
            var previousDbContext = previousScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            previousVerificationAt = (await previousDbContext.IdentityIdentifiers
                .AsNoTracking()
                .SingleAsync(identifier => identifier.IdentityId == previous.IdentityId
                    && identifier.Scheme == IdentifierScheme.Phone))
                .VerifiedAt!.Value;
        }

        var currentEmail = $"current-{Guid.NewGuid():N}@example.com";
        var current = await RegisterAndStartFlowAsync(currentEmail);
        var currentVerification = await RequestPhoneAsync(
            current.Flow,
            current.Capability);
        var conflict = await ConfirmPhoneAsync(
            currentVerification,
            current.Capability,
            "123456");
        Assert.Equal(
            "resolvePhoneConflict",
            conflict.GetProperty("step").GetProperty("type").GetString());
        Assert.NotNull(
            conflict.GetProperty("step").GetProperty("previousEmailHint").GetString());
        Assert.Equal(
            4,
            conflict.GetProperty("actions").GetArrayLength());

        var wrongResponse = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{current.FlowId:D}/actions",
            current.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = conflict.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(conflict, "transferPhoneToCurrentIdentity")
                        .GetProperty("id")
                        .GetGuid(),
                    type = "transferPhoneToCurrentIdentity",
                    input = new { previousEmail = "wrong@example.com" },
                },
            });
        Assert.Equal(HttpStatusCode.OK, wrongResponse.StatusCode);
        using var wrongBody = JsonDocument.Parse(
            await wrongResponse.Content.ReadAsStringAsync());
        var retry = wrongBody.RootElement.GetProperty("snapshot");
        Assert.Equal(
            "phone-conflict-email-mismatch",
            retry.GetProperty("feedback").GetProperty("code").GetString());
        var previousRecoveryArtifacts = await SeedActiveRecoveryArtifactsAsync(
            previous.IdentityId,
            "+15555550123");
        var currentRecoveryArtifacts = await SeedActiveRecoveryArtifactsAsync(
            current.IdentityId,
            "+15555550123");

        // The transfer re-verifies the phone at a later instant than the previous
        // verification; the clock only moves when told to.
        clock.Advance(TimeSpan.FromSeconds(1));
        var transferredResponse = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{current.FlowId:D}/actions",
            current.Capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = retry.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(retry, "transferPhoneToCurrentIdentity")
                        .GetProperty("id")
                        .GetGuid(),
                    type = "transferPhoneToCurrentIdentity",
                    input = new { previousEmail = previousEmail.ToUpperInvariant() },
                },
            });
        Assert.Equal(HttpStatusCode.OK, transferredResponse.StatusCode);
        using var transferredBody = JsonDocument.Parse(
            await transferredResponse.Content.ReadAsStringAsync());
        var transferredRoot = transferredBody.RootElement;
        var result = transferredRoot.GetProperty("snapshot").GetProperty("result");
        Assert.Equal("phoneTransferred", result.GetProperty("outcome").GetString());
        Assert.Equal(
            previous.IdentityId,
            result.GetProperty("previousIdentityId").GetGuid());
        Assert.Equal(
            current.IdentityId,
            result.GetProperty("currentIdentityId").GetGuid());
        Assert.Equal(
            current.IdentityId,
            transferredRoot.GetProperty("issuedSession").GetProperty("identityId").GetGuid());

        var transferredSessionToken = transferredRoot.GetProperty("issuedSession")
            .GetProperty("sessionToken")
            .GetString();
        using (var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = transferredSessionToken }))
        {
            Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
            using var introspectionBody = JsonDocument.Parse(
                await introspection.Content.ReadAsStringAsync());
            var session = introspectionBody.RootElement;
            Assert.Equal(
                "+15555550123",
                session.GetProperty("phone").GetString());
            Assert.NotEqual(
                JsonValueKind.Null,
                session.GetProperty("phoneVerifiedAt").ValueKind);
        }

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var phone = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(
            identifier => identifier.Scheme == IdentifierScheme.Phone
                && identifier.NormalizedValue == "+15555550123");
        Assert.Equal(current.IdentityId, phone.IdentityId);
        Assert.True(phone.VerifiedAt > previousVerificationAt);
        Assert.Equal("sms", phone.VerificationMethod);
        Assert.True(await dbContext.IdentityIdentifiers.AsNoTracking().AnyAsync(
            identifier => identifier.IdentityId == previous.IdentityId
                && identifier.Scheme == IdentifierScheme.Email
                && identifier.NormalizedValue == previousEmail));
        Assert.False(await dbContext.PhoneRegistrationConflicts
            .AsNoTracking()
            .AnyAsync());
        await AssertRecoveryArtifactsInvalidatedAsync(
            dbContext,
            previousRecoveryArtifacts);
        await AssertRecoveryArtifactsInvalidatedAsync(
            dbContext,
            currentRecoveryArtifacts);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PhoneConflict_OffersOnlyActionsAllowedByRequiredPolicy(
        bool phoneRequired)
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneRequired: phoneRequired));
        var journey = await StartPhoneConflictAsync();

        Assert.Equal(
            phoneRequired
                ? [
                    "confirmPhoneVerification",
                    "resendPhoneVerification",
                    "changePhone",
                ]
                : [
                    "confirmPhoneVerification",
                    "resendPhoneVerification",
                    "changePhone",
                    "skipRegistration",
                ],
            ActionTypes(journey.CurrentVerification));
        Assert.Equal(
            phoneRequired
                ? [
                    "transferPhoneToCurrentIdentity",
                    "recoverPreviousIdentity",
                    "changePhone",
                ]
                : [
                    "transferPhoneToCurrentIdentity",
                    "recoverPreviousIdentity",
                    "changePhone",
                    "skipRegistration",
                ],
            ActionTypes(journey.Conflict));
    }

    [Fact]
    public async Task ChangePhone_FromVerification_SupersedesTheChallengeAndCollectsAgain()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneRequired: true));
        var registration = await RegisterAndStartFlowAsync(
            $"change-verification-{Guid.NewGuid():N}@example.com");
        var verification = await RequestPhoneAsync(
            registration.Flow,
            registration.Capability);

        var changed = await ExecuteActionAsync(
            registration,
            verification,
            "changePhone");
        var snapshot = changed.GetProperty("snapshot");

        Assert.Equal("active", snapshot.GetProperty("status").GetString());
        Assert.Equal(
            "collectPhone",
            snapshot.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(
            ["requestPhoneVerification"],
            ActionTypes(snapshot));

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenge = await dbContext.ProofChallenges.AsNoTracking().SingleAsync(
            item => item.IdentityId == registration.IdentityId);
        Assert.Equal(ProofChallengeStatus.Superseded, challenge.Status);
        Assert.False(await dbContext.PhoneRegistrationConflicts
            .AsNoTracking()
            .AnyAsync());
    }

    [Fact]
    public async Task SkipRegistration_FromOptionalConflict_LeavesPhoneWithPreviousIdentity()
    {
        var journey = await StartPhoneConflictAsync();

        var completed = await ExecuteActionAsync(
            journey.Current,
            journey.Conflict,
            "skipRegistration");
        var snapshot = completed.GetProperty("snapshot");

        Assert.Equal("completed", snapshot.GetProperty("status").GetString());
        Assert.Equal(
            "skipped",
            snapshot.GetProperty("result").GetProperty("outcome").GetString());
        Assert.Equal(
            journey.Current.IdentityId,
            completed.GetProperty("issuedSession").GetProperty("identityId").GetGuid());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var phone = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(
            identifier => identifier.Scheme == IdentifierScheme.Phone
                && identifier.NormalizedValue == "+15555550123");
        Assert.Equal(journey.Previous.IdentityId, phone.IdentityId);
        Assert.False(await dbContext.PhoneRegistrationConflicts
            .AsNoTracking()
            .AnyAsync());
    }

    [Fact]
    public async Task PhoneConflict_FifthMismatchDisablesTransfer_AndReplayDoesNotIncrement()
    {
        var journey = await StartPhoneConflictAsync();
        var current = journey.Conflict;
        var fifthSource = default(JsonElement);
        var fifthRequestId = Guid.Empty;
        JsonElement fifthResult = default;

        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var source = current.Clone();
            var requestId = Guid.NewGuid();
            var result = await ExecuteActionAsync(
                journey.Current,
                source,
                "transferPhoneToCurrentIdentity",
                new { previousEmail = "wrong@example.com" },
                requestId);
            current = result.GetProperty("snapshot").Clone();

            Assert.Equal(
                attempt == 5
                    ? "phone-conflict-too-many-attempts"
                    : "phone-conflict-email-mismatch",
                current.GetProperty("feedback").GetProperty("code").GetString());

            if (attempt == 5)
            {
                fifthSource = source;
                fifthRequestId = requestId;
                fifthResult = result;
            }
        }

        Assert.Equal(
            ["recoverPreviousIdentity", "changePhone", "skipRegistration"],
            ActionTypes(current));
        Assert.DoesNotContain(
            ActionTypes(current),
            action => action is "transferPhoneToCurrentIdentity");

        var replay = await ExecuteActionAsync(
            journey.Current,
            fifthSource,
            "transferPhoneToCurrentIdentity",
            new { previousEmail = "wrong@example.com" },
            fifthRequestId);
        Assert.Equal(fifthResult.GetRawText(), replay.GetRawText());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var conflict = await dbContext.PhoneRegistrationConflicts
            .AsNoTracking()
            .SingleAsync();
        Assert.Equal(5, conflict.FailedEmailAttempts);
        Assert.NotNull(conflict.EmailResolutionExhaustedAt);
    }

    [Fact]
    public async Task ChangePhone_FromConflict_AllowsANewConflictWithFreshAttempts()
    {
        var journey = await StartPhoneConflictAsync();
        var firstFailure = await ExecuteActionAsync(
            journey.Current,
            journey.Conflict,
            "transferPhoneToCurrentIdentity",
            new { previousEmail = "wrong@example.com" });

        await using (var failureScope = api.Services.CreateAsyncScope())
        {
            var dbContext = failureScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            Assert.Equal(
                1,
                (await dbContext.PhoneRegistrationConflicts
                    .AsNoTracking()
                    .SingleAsync()).FailedEmailAttempts);
        }

        var changed = await ExecuteActionAsync(
            journey.Current,
            firstFailure.GetProperty("snapshot"),
            "changePhone");
        var collectPhone = changed.GetProperty("snapshot").Clone();
        Assert.Equal(
            "collectPhone",
            collectPhone.GetProperty("step").GetProperty("type").GetString());

        await using (var changedScope = api.Services.CreateAsyncScope())
        {
            var dbContext = changedScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            Assert.False(await dbContext.PhoneRegistrationConflicts
                .AsNoTracking()
                .AnyAsync());
        }

        var secondVerification = await RequestPhoneAsync(
            collectPhone,
            journey.Current.Capability);
        var secondConflict = await ConfirmPhoneAsync(
            secondVerification,
            journey.Current.Capability,
            "123456");
        Assert.Equal(
            "resolvePhoneConflict",
            secondConflict.GetProperty("step").GetProperty("type").GetString());

        await using var finalScope = api.Services.CreateAsyncScope();
        var finalDbContext = finalScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        var recreated = await finalDbContext.PhoneRegistrationConflicts
            .AsNoTracking()
            .SingleAsync();
        Assert.Equal(0, recreated.FailedEmailAttempts);
        Assert.Null(recreated.EmailResolutionExhaustedAt);
    }

    [Fact]
    public async Task VerifiedSms_TransfersAnUnverifiedPhoneWithoutCreatingConflict()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneRequired: true,
            phoneVerificationEnabled: false));
        var previous = await RegisterAndStartFlowAsync(
            $"unverified-owner-{Guid.NewGuid():N}@example.com");
        var submitted = await ExecuteActionAsync(
            previous,
            previous.Flow,
            "submitPhone",
            new { phone = "+15555550123" });
        Assert.Equal(
            "completed",
            submitted.GetProperty("snapshot").GetProperty("status").GetString());

        Guid phoneIdentifierId;
        await using (var previousScope = api.Services.CreateAsyncScope())
        {
            var dbContext = previousScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            var phone = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(
                identifier => identifier.IdentityId == previous.IdentityId
                    && identifier.Scheme == IdentifierScheme.Phone);
            phoneIdentifierId = phone.Id;
            Assert.Null(phone.VerifiedAt);
        }

        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneRequired: true));
        var current = await RegisterAndStartFlowAsync(
            $"verified-owner-{Guid.NewGuid():N}@example.com");
        var verification = await RequestPhoneAsync(current.Flow, current.Capability);
        var completed = await ConfirmPhoneAsync(
            verification,
            current.Capability,
            "123456");

        Assert.Equal("completed", completed.GetProperty("status").GetString());
        Assert.Equal(
            "phoneVerified",
            completed.GetProperty("result").GetProperty("outcome").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var finalDbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var transferred = await finalDbContext.IdentityIdentifiers
            .AsNoTracking()
            .SingleAsync(identifier => identifier.Id == phoneIdentifierId);
        Assert.Equal(current.IdentityId, transferred.IdentityId);
        Assert.NotNull(transferred.VerifiedAt);
        Assert.Equal("sms", transferred.VerificationMethod);
        Assert.False(await finalDbContext.PhoneRegistrationConflicts
            .AsNoTracking()
            .AnyAsync());
    }

    [Fact]
    public async Task ManagePhone_StartWithANewRequestIdResumesTheFlowAtItsCurrentStep()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            phoneVerificationEnabled: false));
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"manage-phone-resume-{Guid.NewGuid():N}@example.test",
                password = "password-123",
            });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement.GetProperty("identityId").GetGuid();
        var sourceSessionToken = registrationBody.RootElement
            .GetProperty("sessionToken")
            .GetString();
        Assert.Equal(
            "product",
            registrationBody.RootElement.GetProperty("sessionPurpose").GetString());

        await ConfigurePolicyAsync(TestAccessPolicies.Create(phoneRequired: true));
        using var started = await StartFlowAsync("managePhone", sourceSessionToken);
        var managed = await ReadStartedFlowAsync(started, identityId, sourceSessionToken);
        var requested = await ExecuteActionAsync(
            managed,
            managed.Flow,
            "requestPhoneVerification",
            new { phone = "+15555550123" });
        var verify = requested.GetProperty("snapshot").Clone();
        Assert.Equal(
            "verifyPhone",
            verify.GetProperty("step").GetProperty("type").GetString());

        // A new Start for the same session and intent resumes the active flow at
        // its current step instead of restarting it or failing.
        var resumeRequestId = Guid.NewGuid();
        using var resumedResponse = await StartFlowAsync(
            "managePhone",
            sourceSessionToken,
            resumeRequestId);
        var resumed = await ReadStartedFlowAsync(
            resumedResponse,
            identityId,
            sourceSessionToken);
        Assert.Equal(managed.FlowId, resumed.FlowId);
        Assert.Equal(verify.GetRawText(), resumed.Flow.GetRawText());
        Assert.StartsWith("bgf_", resumed.Capability, StringComparison.Ordinal);

        // The resumed Start is an ordinary idempotent request.
        using (var replayed = await StartFlowAsync(
            "managePhone",
            sourceSessionToken,
            resumeRequestId))
        {
            Assert.Equal(HttpStatusCode.Created, replayed.StatusCode);
            using var replayedBody = JsonDocument.Parse(
                await replayed.Content.ReadAsStringAsync());
            Assert.Equal(
                verify.GetRawText(),
                replayedBody.RootElement.GetProperty("snapshot").GetRawText());
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.Equal(
                1,
                await dbContext.AccessFlows.AsNoTracking().CountAsync(
                    flow => flow.IdentityId == identityId));
            var resumedRequest = await dbContext.AccessFlowRequests.AsNoTracking()
                .SingleAsync(request => request.RequestId == resumeRequestId);
            Assert.Equal(managed.FlowId, resumedRequest.FlowId);
            Assert.Equal(AccessFlowRequestKind.Start, resumedRequest.Kind);
            Assert.Equal(AccessFlowRequestStatus.Committed, resumedRequest.Status);
            Assert.Equal(
                verify.GetProperty("revision").GetInt32(),
                resumedRequest.ResultRevision);
        }

        // The re-issued capability drives the flow to completion.
        var completed = await ExecuteActionAsync(
            resumed,
            resumed.Flow,
            "confirmPhoneVerification",
            new { code = "123456" });
        Assert.Equal(
            "completed",
            completed.GetProperty("snapshot").GetProperty("status").GetString());
        Assert.Equal(
            "phoneVerified",
            completed.GetProperty("snapshot")
                .GetProperty("result")
                .GetProperty("outcome")
                .GetString());
        Assert.Equal(
            "product",
            completed.GetProperty("issuedSession").GetProperty("purpose").GetString());
    }

    [Fact]
    public async Task ContinueRegistration_StartWithANewRequestIdResumesAPendingPhoneConflict()
    {
        var scenario = await StartPhoneConflictAsync();
        var current = scenario.Current;

        var resumeRequestId = Guid.NewGuid();
        using var resumedResponse = await StartFlowAsync(
            "continueRegistration",
            current.SourceSessionToken,
            resumeRequestId);
        var resumed = await ReadStartedFlowAsync(
            resumedResponse,
            current.IdentityId,
            current.SourceSessionToken);
        Assert.Equal(current.FlowId, resumed.FlowId);
        Assert.Equal(scenario.Conflict.GetRawText(), resumed.Flow.GetRawText());
        Assert.Equal(
            "resolvePhoneConflict",
            resumed.Flow.GetProperty("step").GetProperty("type").GetString());

        // Same requestId and payload: exact replay. Same requestId, other payload:
        // conflict. Neither touches the flow.
        using (var replayed = await StartFlowAsync(
            "continueRegistration",
            current.SourceSessionToken,
            resumeRequestId))
        {
            Assert.Equal(HttpStatusCode.Created, replayed.StatusCode);
            using var replayedBody = JsonDocument.Parse(
                await replayed.Content.ReadAsStringAsync());
            Assert.Equal(
                scenario.Conflict.GetRawText(),
                replayedBody.RootElement.GetProperty("snapshot").GetRawText());
        }

        using (var conflicting = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = resumeRequestId,
                protocolVersions = ProtocolVersions1And2,
                intent = "continueRegistration",
                applicationClientKey = ApplicationClientKey,
                sessionToken = current.SourceSessionToken,
            }))
        {
            Assert.Equal(HttpStatusCode.Conflict, conflicting.StatusCode);
            using var conflictingBody = JsonDocument.Parse(
                await conflicting.Content.ReadAsStringAsync());
            Assert.Equal(
                "request-id-conflict",
                conflictingBody.RootElement.GetProperty("error").GetString());
        }

        string previousEmail;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var flow = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                item => item.Id == current.FlowId);
            Assert.Equal(AccessFlowStatus.Active, flow.Status);
            Assert.Equal(
                scenario.Conflict.GetProperty("revision").GetInt32(),
                flow.CurrentRevision);
            Assert.True(await dbContext.PhoneRegistrationConflicts.AsNoTracking().AnyAsync(
                conflict => conflict.AccessFlowId == current.FlowId));
            previousEmail = await dbContext.IdentityIdentifiers.AsNoTracking()
                .Where(identifier => identifier.IdentityId == scenario.Previous.IdentityId
                    && identifier.Scheme == IdentifierScheme.Email)
                .Select(identifier => identifier.NormalizedValue)
                .SingleAsync();
        }

        // The conflict is resolved with the capability issued by the resumed Start.
        var transferred = await ExecuteActionAsync(
            resumed,
            resumed.Flow,
            "transferPhoneToCurrentIdentity",
            new { previousEmail });
        var snapshot = transferred.GetProperty("snapshot");
        Assert.Equal("completed", snapshot.GetProperty("status").GetString());
        Assert.Equal(
            "phoneTransferred",
            snapshot.GetProperty("result").GetProperty("outcome").GetString());
        Assert.Equal(
            scenario.Previous.IdentityId,
            snapshot.GetProperty("result").GetProperty("previousIdentityId").GetGuid());
    }

    [Fact]
    public async Task Start_RejectsResumingAnActiveFlowFromAnotherIntegrationOrApplicationClient()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"client-divergence-{Guid.NewGuid():N}@example.com");
        var (otherCredential, otherApplicationClientKey) =
            await RegisterSecondaryClientsAsync();

        using (var otherClient = api.CreateClient())
        {
            otherClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", otherCredential);
            using var otherIntegration = await StartFlowAsync(
                "continueRegistration",
                registration.SourceSessionToken,
                integrationClient: otherClient);
            Assert.Equal(HttpStatusCode.Conflict, otherIntegration.StatusCode);
            using var otherIntegrationBody = JsonDocument.Parse(
                await otherIntegration.Content.ReadAsStringAsync());
            Assert.Equal(
                "integration-client-conflict",
                otherIntegrationBody.RootElement.GetProperty("error").GetString());
        }

        using (var otherApplication = await StartFlowAsync(
            "continueRegistration",
            registration.SourceSessionToken,
            applicationClientKey: otherApplicationClientKey))
        {
            Assert.Equal(HttpStatusCode.BadRequest, otherApplication.StatusCode);
            using var otherApplicationBody = JsonDocument.Parse(
                await otherApplication.Content.ReadAsStringAsync());
            Assert.Equal(
                "application-client-invalid",
                otherApplicationBody.RootElement.GetProperty("error").GetString());
            Assert.Equal(
                "applicationClientKey",
                otherApplicationBody.RootElement.GetProperty("field").GetString());
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var flow = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                item => item.IdentityId == registration.IdentityId);
            Assert.Equal(registration.FlowId, flow.Id);
            Assert.Equal(AccessFlowStatus.Active, flow.Status);
            Assert.Equal(1, flow.CurrentRevision);
            Assert.Equal(
                1,
                await dbContext.AccessFlowRequests.AsNoTracking().CountAsync(
                    request => request.FlowId == registration.FlowId));
        }

        // The original client pair still resumes the untouched flow.
        using var sameClients = await StartFlowAsync(
            "continueRegistration",
            registration.SourceSessionToken);
        var resumed = await ReadStartedFlowAsync(
            sameClients,
            registration.IdentityId,
            registration.SourceSessionToken);
        Assert.Equal(registration.FlowId, resumed.FlowId);
        Assert.Equal(registration.Flow.GetRawText(), resumed.Flow.GetRawText());
    }

    [Fact]
    public async Task Start_ExpiresAStaleFlowAndClosesItsPendingReservationBeforeReplacingIt()
    {
        var registration = await RegisterAndStartFlowAsync(
            $"expired-flow-{Guid.NewGuid():N}@example.com");
        var action = FindAction(registration.Flow, "requestPhoneVerification");
        var pendingRequestId = Guid.NewGuid();
        var gate = new AsyncOperationGate();
        api.PhoneSender.SendGate = gate;

        // The provider call stays in flight, leaving a committed reservation
        // (PendingExternal request + PendingDelivery challenge) behind.
        var deliveryTask = SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId = pendingRequestId,
                expectedRevision = registration.Flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = action.GetProperty("id").GetGuid(),
                    type = "requestPhoneVerification",
                    input = new { phone = "+5511987654330" },
                },
            });

        using var gateDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await gate.WaitUntilEnteredAsync(gateDeadline.Token);
        StartedRegistration replacement;
        DateTimeOffset expiredAt;
        try
        {
            await using (var pendingScope = api.Services.CreateAsyncScope())
            {
                var dbContext = pendingScope.ServiceProvider
                    .GetRequiredService<AccessDbContext>();
                var request = await dbContext.AccessFlowRequests.AsNoTracking().SingleAsync(
                    item => item.RequestId == pendingRequestId);
                Assert.Equal(AccessFlowRequestStatus.PendingExternal, request.Status);
                var challenge = await dbContext.ProofChallenges.AsNoTracking().SingleAsync(
                    item => item.AccessFlowId == registration.FlowId);
                Assert.Equal(ProofChallengeStatus.PendingDelivery, challenge.Status);
            }

            clock.Advance(FlowDuration + TimeSpan.FromSeconds(1));
            expiredAt = clock.GetUtcNow();

            using var replaced = await StartFlowAsync(
                "continueRegistration",
                registration.SourceSessionToken);
            replacement = await ReadStartedFlowAsync(
                replaced,
                registration.IdentityId,
                registration.SourceSessionToken);
            Assert.NotEqual(registration.FlowId, replacement.FlowId);
            Assert.Equal(1, replacement.Flow.GetProperty("revision").GetInt32());
            Assert.Equal("active", replacement.Flow.GetProperty("status").GetString());
            Assert.Equal(
                "collectPhone",
                replacement.Flow.GetProperty("step").GetProperty("type").GetString());

            await using (var expiredScope = api.Services.CreateAsyncScope())
            {
                var dbContext = expiredScope.ServiceProvider
                    .GetRequiredService<AccessDbContext>();
                var expired = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                    item => item.Id == registration.FlowId);
                Assert.Equal(AccessFlowStatus.Expired, expired.Status);
                Assert.Equal(2, expired.CurrentRevision);
                Assert.Equal(expiredAt, expired.CompletedAt);
                var terminal = await dbContext.AccessFlowRevisions.AsNoTracking().SingleAsync(
                    revision => revision.FlowId == registration.FlowId
                        && revision.Revision == 2);
                using (var terminalSnapshot = JsonDocument.Parse(terminal.SnapshotJson))
                {
                    Assert.Equal(
                        "expired",
                        terminalSnapshot.RootElement.GetProperty("status").GetString());
                    Assert.Equal(
                        "flowExpired",
                        terminalSnapshot.RootElement
                            .GetProperty("result")
                            .GetProperty("type")
                            .GetString());
                }
                var request = await dbContext.AccessFlowRequests.AsNoTracking().SingleAsync(
                    item => item.RequestId == pendingRequestId);
                Assert.Equal(AccessFlowRequestStatus.ExternalFailed, request.Status);
                Assert.Null(request.ResultRevision);
                var challenge = await dbContext.ProofChallenges.AsNoTracking().SingleAsync(
                    item => item.AccessFlowId == registration.FlowId);
                Assert.Equal(ProofChallengeStatus.DeliveryFailed, challenge.Status);
                Assert.Equal(expiredAt, challenge.CompletedAt);
                var created = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                    item => item.Id == replacement.FlowId);
                Assert.Equal(AccessFlowStatus.Active, created.Status);
                Assert.Equal(registration.IdentityId, created.IdentityId);
                Assert.Equal(expired.SourceSessionId, created.SourceSessionId);
            }
        }
        finally
        {
            gate.Release();
        }

        // The late provider result cannot revive the expired flow: the delivery is
        // reported as unavailable, the provider reference is cancelled and both
        // flows keep the state they had before the gate opened.
        using var late = await deliveryTask.WaitAsync(TimeSpan.FromSeconds(10));
        api.PhoneSender.SendGate = null;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, late.StatusCode);
        using (var lateBody = JsonDocument.Parse(await late.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "verification-delivery-unavailable",
                lateBody.RootElement.GetProperty("error").GetString());
        }
        Assert.Single(api.PhoneSender.CancellationAttempts);

        await using (var finalScope = api.Services.CreateAsyncScope())
        {
            var dbContext = finalScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var expired = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                item => item.Id == registration.FlowId);
            Assert.Equal(AccessFlowStatus.Expired, expired.Status);
            Assert.Equal(2, expired.CurrentRevision);
            Assert.Equal(
                2,
                await dbContext.AccessFlowRevisions.AsNoTracking().CountAsync(
                    revision => revision.FlowId == registration.FlowId));
            var challenge = await dbContext.ProofChallenges.AsNoTracking().SingleAsync(
                item => item.AccessFlowId == registration.FlowId);
            Assert.Equal(ProofChallengeStatus.DeliveryFailed, challenge.Status);
            var created = await dbContext.AccessFlows.AsNoTracking().SingleAsync(
                item => item.Id == replacement.FlowId);
            Assert.Equal(1, created.CurrentRevision);
            Assert.False(await dbContext.ProofChallenges.AsNoTracking().AnyAsync(
                item => item.AccessFlowId == replacement.FlowId));
        }

        // The replacement flow is fully usable.
        var verification = await RequestPhoneAsync(replacement.Flow, replacement.Capability);
        Assert.Equal(
            "verifyPhone",
            verification.GetProperty("step").GetProperty("type").GetString());
    }

    private async Task<StartedRegistration> RegisterAndStartFlowAsync(
        string email,
        IReadOnlyList<int>? protocolVersions = null)
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
            .GetString();

        var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = protocolVersions ?? ProtocolVersion1,
                intent = "continueRegistration",
                applicationClientKey = ApplicationClientKey,
                sessionToken = registrationToken,
            });
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var root = startedBody.RootElement;
        var flow = root.GetProperty("snapshot").Clone();
        return new StartedRegistration(
            identityId,
            flow.GetProperty("flowId").GetGuid(),
            root.GetProperty("flowCapability").GetString()!,
            flow,
            registrationToken);
    }

    private async Task<StartedPhoneConflict> StartPhoneConflictAsync()
    {
        var previous = await RegisterAndStartFlowAsync(
            $"previous-{Guid.NewGuid():N}@example.com");
        var previousVerification = await RequestPhoneAsync(
            previous.Flow,
            previous.Capability);
        var previousCompleted = await ConfirmPhoneAsync(
            previousVerification,
            previous.Capability,
            "123456");
        Assert.Equal("completed", previousCompleted.GetProperty("status").GetString());

        var current = await RegisterAndStartFlowAsync(
            $"current-{Guid.NewGuid():N}@example.com");
        var currentVerification = await RequestPhoneAsync(
            current.Flow,
            current.Capability);
        var conflict = await ConfirmPhoneAsync(
            currentVerification,
            current.Capability,
            "123456");
        Assert.Equal(
            "resolvePhoneConflict",
            conflict.GetProperty("step").GetProperty("type").GetString());

        return new StartedPhoneConflict(
            previous,
            current,
            currentVerification,
            conflict);
    }

    private async Task<JsonElement> ExecuteActionAsync(
        StartedRegistration registration,
        JsonElement snapshot,
        string actionType,
        object? input = null,
        Guid? requestId = null)
    {
        using var response = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{registration.FlowId:D}/actions",
            registration.Capability,
            new
            {
                requestId = requestId ?? Guid.NewGuid(),
                expectedRevision = snapshot.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(snapshot, actionType).GetProperty("id").GetGuid(),
                    type = actionType,
                    input,
                },
            });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.Clone();
    }

    private async Task<JsonElement> RequestPhoneAsync(
        JsonElement flow,
        string capability,
        string phone = "+15555550123")
    {
        var response = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flow.GetProperty("flowId").GetGuid():D}/actions",
            capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(flow, "requestPhoneVerification")
                        .GetProperty("id")
                        .GetGuid(),
                    type = "requestPhoneVerification",
                    input = new { phone },
                },
            });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("snapshot").Clone();
    }

    private async Task<JsonElement> ConfirmPhoneAsync(
        JsonElement flow,
        string capability,
        string code)
    {
        var response = await SendWithCapabilityAsync(
            HttpMethod.Post,
            $"/v1/access/flows/{flow.GetProperty("flowId").GetGuid():D}/actions",
            capability,
            new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = flow.GetProperty("revision").GetInt32(),
                action = new
                {
                    id = FindAction(flow, "confirmPhoneVerification")
                        .GetProperty("id")
                        .GetGuid(),
                    type = "confirmPhoneVerification",
                    input = new { code },
                },
            });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("snapshot").Clone();
    }

    private async Task<HttpResponseMessage> SendWithCapabilityAsync(
        HttpMethod method,
        string path,
        string? capability,
        object? body)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.TryAddWithoutValidation(CapabilityHeader, capability);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await client.SendAsync(request);
    }

    private async Task<JsonElement> GetFlowSnapshotAsync(
        StartedRegistration registration)
    {
        using var response = await SendWithCapabilityAsync(
            HttpMethod.Get,
            $"/v1/access/flows/{registration.FlowId:D}",
            registration.Capability,
            null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("snapshot").Clone();
    }

    private Task<HttpResponseMessage> StartFlowAsync(
        string intent,
        string? sessionToken,
        Guid? requestId = null,
        string? applicationClientKey = null,
        HttpClient? integrationClient = null) =>
        (integrationClient ?? client).PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = requestId ?? Guid.NewGuid(),
                protocolVersions = ProtocolVersion1,
                intent,
                applicationClientKey = applicationClientKey ?? ApplicationClientKey,
                sessionToken,
            });

    private static async Task<StartedRegistration> ReadStartedFlowAsync(
        HttpResponseMessage response,
        Guid identityId,
        string? sourceSessionToken)
    {
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        var flow = root.GetProperty("snapshot").Clone();
        return new StartedRegistration(
            identityId,
            flow.GetProperty("flowId").GetGuid(),
            root.GetProperty("flowCapability").GetString()!,
            flow,
            sourceSessionToken);
    }

    // Adds a second integration client and application client to the test
    // environment; only the new integration client receives a credential.
    private async Task<(string Credential, string ApplicationClientKey)>
        RegisterSecondaryClientsAsync()
    {
        await using var scope = api.Services.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
        var result = await handler.HandleAsync(
            CreateBootstrapCommand(topologySuffix, includeSecondaryClients: true));
        var credential = Assert.Single(result.IssuedCredentials);
        return (credential.Token, "android-release");
    }

    private async Task<RecoveryArtifacts> SeedActiveRecoveryArtifactsAsync(
        Guid identityId,
        string phone)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var appEnvironmentId = await dbContext.IdentitySessions.AsNoTracking()
            .Where(session => session.IdentityId == identityId)
            .Select(session => session.AppEnvironmentId)
            .Distinct()
            .SingleAsync();
        var now = clock.GetUtcNow();
        var tokenId = Guid.CreateVersion7(now);
        var challengeId = Guid.CreateVersion7(now);
        dbContext.PasswordResetTokens.Add(new PasswordResetToken(
            tokenId,
            identityId,
            appEnvironmentId,
            RandomNumberGenerator.GetBytes(IdentityLimits.PasswordResetTokenHashLength),
            now,
            now.AddMinutes(30)));
        var challenge = new PhonePasswordResetChallenge(
            challengeId,
            identityId,
            appEnvironmentId,
            phone,
            RandomNumberGenerator.GetBytes(
                IdentityLimits.PhonePasswordResetCodeHashLength),
            5,
            now,
            now.AddMinutes(10),
            now.AddMinutes(1));
        challenge.Activate("test-recovery-reference");
        dbContext.PhonePasswordResetChallenges.Add(challenge);
        await dbContext.SaveChangesAsync();
        return new RecoveryArtifacts(tokenId, challengeId);
    }

    private static async Task AssertRecoveryArtifactsInvalidatedAsync(
        AccessDbContext dbContext,
        RecoveryArtifacts artifacts)
    {
        var token = await dbContext.PasswordResetTokens.AsNoTracking().SingleAsync(
            item => item.Id == artifacts.PasswordResetTokenId);
        Assert.NotNull(token.UsedAt);
        var challenge = await dbContext.PhonePasswordResetChallenges.AsNoTracking()
            .SingleAsync(item => item.Id == artifacts.PhoneChallengeId);
        Assert.Equal(
            PhonePasswordResetChallengeStatus.Superseded,
            challenge.Status);
        Assert.NotNull(challenge.CompletedAt);
    }

    private async Task ConfigurePolicyAsync(AppAccessPolicy policy)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
        var result = await handler.HandleAsync(CreateBootstrapCommand(topologySuffix, policy));
        Assert.Empty(result.IssuedCredentials);
    }

    private static JsonElement FindAction(JsonElement snapshot, string type) =>
        Assert.Single(
            snapshot.GetProperty("actions").EnumerateArray(),
            action => string.Equals(
                action.GetProperty("type").GetString(),
                type,
                StringComparison.Ordinal));

    private static string[] ActionTypes(JsonElement snapshot) =>
        snapshot.GetProperty("actions")
            .EnumerateArray()
            .Select(action => action.GetProperty("type").GetString()!)
            .ToArray();

    private static BootstrapTopologyCommand CreateBootstrapCommand(
        string suffix,
        AppAccessPolicy? accessPolicy = null,
        bool includeSecondaryClients = false)
    {
        var environmentAccessPolicy = accessPolicy ?? TestAccessPolicies.Create();
        List<BootstrapIntegrationClientDefinition> integrationClients =
        [
            new BootstrapIntegrationClientDefinition(
                "api",
                "API",
                [
                    AccessPermission.ExecuteFlows,
                    AccessPermission.IntrospectSessions,
                    AccessPermission.RevokeCurrentSession,
                    AccessPermission.ManageCurrentIdentity,
                ]),
        ];
        List<BootstrapApplicationClientDefinition> applicationClients =
        [
            new BootstrapApplicationClientDefinition(
                "android-debug",
                "Android debug",
                ApplicationClientPlatform.Android,
                "app.baybo",
                "sha256:fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
                "92TvTC0UfaA",
                JsonSerializer.SerializeToElement(new { })),
        ];
        if (includeSecondaryClients)
        {
            integrationClients.Add(new BootstrapIntegrationClientDefinition(
                "other-api",
                "Other API",
                [AccessPermission.ExecuteFlows]));
            applicationClients.Add(new BootstrapApplicationClientDefinition(
                "android-release",
                "Android release",
                ApplicationClientPlatform.Android,
                "app.baybo",
                "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
                "92TvTC0UfaB",
                JsonSerializer.SerializeToElement(new { })));
        }

        return new BootstrapTopologyCommand(
            $"access-flow-{suffix}",
            "Access flow tests",
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
                            environmentAccessPolicy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(environmentAccessPolicy),
                            TestEnvironmentConfigurations.DevelopmentBypass(
                                environmentAccessPolicy),
                            integrationClients,
                            applicationClients),
                    ]),
            ]);
    }

    private sealed record StartedRegistration(
        Guid IdentityId,
        Guid FlowId,
        string Capability,
        JsonElement Flow,
        string? SourceSessionToken = null);

    private sealed record StartedPhoneConflict(
        StartedRegistration Previous,
        StartedRegistration Current,
        JsonElement CurrentVerification,
        JsonElement Conflict);

    private sealed record RecoveryArtifacts(
        Guid PasswordResetTokenId,
        Guid PhoneChallengeId);
}
