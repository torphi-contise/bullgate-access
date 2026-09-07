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

public sealed class FlowExecutionPermissionEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private const string Phone = "+5511987654321";
    private const string RecoveryUrl = "https://example.test/reset-password";
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private HttpClient allowedClient = null!;
    private HttpClient forbiddenClient = null!;
    private Guid environmentId;
    private Guid realmId;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await db.Database.EnsureCreatedAsync();
        var bootstrap = await scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>()
            .HandleAsync(CreateBootstrapCommand(Guid.NewGuid().ToString("N")));
        environmentId = bootstrap.Resources.Single(item => item.Type == "environment").Id;
        realmId = bootstrap.Resources.Single(item => item.Type == "realm").Id;
        client = CreateClient(bootstrap, "full");
        allowedClient = CreateClient(bootstrap, "execution-only");
        forbiddenClient = CreateClient(bootstrap, "without-execution");
    }

    public async Task DisposeAsync()
    {
        forbiddenClient.Dispose();
        allowedClient.Dispose();
        client.Dispose();
        await api.DisposeAsync();
    }

    [Fact]
    public async Task ApplicationConfiguration_RequiresExecutionPermissionEvenWithAValidClientKey()
    {
        const string path = "/v1/config/application-clients/android-debug";

        using var forbidden = await forbiddenClient.GetAsync(path);

        await AssertForbiddenAsync(forbidden);
        using var allowed = await allowedClient.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        using var body = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync());
        var applicationClient = body.RootElement.GetProperty("client");
        Assert.Equal("android-debug", applicationClient.GetProperty("key").GetString());
        Assert.Equal("app.baybo", applicationClient.GetProperty("applicationId").GetString());
        Assert.Equal("92TvTC0UfaA", applicationClient.GetProperty("smsRetrieverAppHash").GetString());
    }

    [Fact]
    public async Task Register_RequiresExecutionPermissionBeforeCreatingAnIdentity()
    {
        var email = $"register-permission-{Guid.NewGuid():N}@example.test";
        var request = new { email, password = "password-123" };

        using var forbidden = await forbiddenClient.PostAsJsonAsync("/v1/auth/register", request);

        await AssertForbiddenAsync(forbidden);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.Identities.AnyAsync(item => item.RealmId == realmId));
            Assert.False(await db.IdentitySessions.AnyAsync(item => item.AppEnvironmentId == environmentId));
        }
        using var allowed = await allowedClient.PostAsJsonAsync("/v1/auth/register", request);
        Assert.Equal(HttpStatusCode.Created, allowed.StatusCode);
        var account = await ReadAccountAsync(allowed, email);
        await AssertSessionActiveAsync(account.Token, true);
        Assert.Equal(account.IdentityId, (await LoginAsync(email, "password-123")).IdentityId);
    }

    [Fact]
    public async Task Login_RequiresExecutionPermissionBeforeIssuingAnotherSession()
    {
        var account = await RegisterAsync();
        var request = new { email = account.Email, password = "password-123" };

        using var forbidden = await forbiddenClient.PostAsJsonAsync("/v1/auth/login", request);

        await AssertForbiddenAsync(forbidden);
        await AssertSessionCountAsync(account.IdentityId, 1);
        using var allowed = await allowedClient.PostAsJsonAsync("/v1/auth/login", request);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        var login = await ReadAccountAsync(allowed, account.Email);
        Assert.Equal(account.IdentityId, login.IdentityId);
        Assert.NotEqual(account.Token, login.Token);
        await AssertSessionCountAsync(account.IdentityId, 2);
        await AssertSessionActiveAsync(account.Token, true);
        await AssertSessionActiveAsync(login.Token, true);
    }

    [Theory]
    [InlineData("google")]
    [InlineData("apple")]
    public async Task SocialLogin_RequiresExecutionPermissionBeforeCreatingProviderCredentials(string provider)
    {
        object assertion = provider == "google"
            ? new { idToken = "google-token" }
            : new { identityToken = "apple-token" };

        using var forbidden = await forbiddenClient.PostAsJsonAsync($"/v1/auth/{provider}", assertion);

        await AssertForbiddenAsync(forbidden);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.Identities.AnyAsync(item => item.RealmId == realmId));
            Assert.False(await db.SocialCredentials.AnyAsync(item => item.RealmId == realmId));
        }
        using var allowed = await allowedClient.PostAsJsonAsync($"/v1/auth/{provider}", assertion);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        using var body = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync());
        var identityId = body.RootElement.GetProperty("identityId").GetGuid();
        var token = Assert.IsType<string>(body.RootElement.GetProperty("sessionToken").GetString());
        await AssertSessionActiveAsync(token, true);
        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var credential = await verification.SocialCredentials.AsNoTracking()
            .SingleAsync(item => item.RealmId == realmId);
        Assert.Equal(identityId, credential.IdentityId);
        Assert.Equal(provider, credential.Provider);
    }

    [Fact]
    public async Task EmailRecovery_RequiresExecutionPermissionBeforeSendingOrIssuingAToken()
    {
        var account = await RegisterAsync();
        var request = new { email = account.Email };

        using var forbidden = await forbiddenClient.PostAsJsonAsync("/v1/auth/password/recovery/email", request);

        await AssertForbiddenAsync(forbidden);
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        await AssertNoResetTokensAsync(account.IdentityId);
        using var allowed = await allowedClient.PostAsJsonAsync("/v1/auth/password/recovery/email", request);
        Assert.Equal(HttpStatusCode.Accepted, allowed.StatusCode);
        var delivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        var token = Uri.UnescapeDataString(new Uri(delivery.ResetUrl).Query["?token=".Length..]);
        using var reset = await allowedClient.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset", new { token, newPassword = "recovered-password" });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
        Assert.Equal(account.IdentityId, (await LoginAsync(account.Email, "recovered-password")).IdentityId);
    }

    [Fact]
    public async Task Reset_RequiresExecutionPermissionBeforeConsumingTheTokenOrChangingCredentials()
    {
        var account = await RegisterAsync();
        PasswordResetIssueResult issued;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            issued = await scope.ServiceProvider.GetRequiredService<PasswordResetService>()
                .IssueAsync(account.IdentityId, environmentId);
            Assert.True(issued.Succeeded);
        }
        var request = new { token = issued.Token, newPassword = "recovered-password" };

        using var forbidden = await forbiddenClient.PostAsJsonAsync("/v1/auth/password/recovery/reset", request);

        await AssertForbiddenAsync(forbidden);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var token = await db.PasswordResetTokens.AsNoTracking().SingleAsync(item => item.Id == issued.TokenId);
            Assert.Null(token.UsedAt);
        }
        await AssertSessionActiveAsync(account.Token, true);
        Assert.Equal(account.IdentityId, (await LoginAsync(account.Email, "password-123")).IdentityId);
        using var allowed = await allowedClient.PostAsJsonAsync("/v1/auth/password/recovery/reset", request);
        Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);
        await AssertSessionActiveAsync(account.Token, false);
        Assert.Equal(account.IdentityId, (await LoginAsync(account.Email, "recovered-password")).IdentityId);
        using var oldLogin = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = account.Email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldLogin.StatusCode);
    }

    [Fact]
    public async Task PhoneRecovery_RequiresExecutionPermissionBeforeSendingAChallenge()
    {
        var account = await RegisterPhoneOwnerAsync();
        var request = new { phone = Phone, applicationClientKey = "android-debug" };

        using var forbidden = await forbiddenClient.PostAsJsonAsync("/v1/auth/password/recovery/phone", request);

        await AssertForbiddenAsync(forbidden);
        Assert.Empty(api.PhoneSender.DeliveryAttempts);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.PhonePasswordResetChallenges.AnyAsync(item => item.IdentityId == account.IdentityId));
        }
        using var allowed = await allowedClient.PostAsJsonAsync("/v1/auth/password/recovery/phone", request);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal(Phone, Assert.Single(api.PhoneSender.DeliveryAttempts).Phone);
        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenge = await verification.PhonePasswordResetChallenges.AsNoTracking()
            .SingleAsync(item => item.IdentityId == account.IdentityId);
        Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
    }

    [Fact]
    public async Task PhoneConfirmation_RequiresExecutionPermissionBeforeConsumingTheCode()
    {
        var account = await RegisterPhoneOwnerAsync();
        using var requested = await allowedClient.PostAsJsonAsync(
            "/v1/auth/password/recovery/phone", new { phone = Phone, applicationClientKey = "android-debug" });
        Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        var request = new { phone = Phone, code = Assert.IsType<string>(api.PhoneSender.LastCode) };

        using var forbidden = await forbiddenClient.PostAsJsonAsync("/v1/auth/password/recovery/phone/confirm", request);

        await AssertForbiddenAsync(forbidden);
        Assert.Empty(api.PhoneSender.ApprovalAttempts);
        await AssertNoResetTokensAsync(account.IdentityId);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var challenge = await db.PhonePasswordResetChallenges.AsNoTracking()
                .SingleAsync(item => item.IdentityId == account.IdentityId);
            Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
            Assert.Equal(0, challenge.Attempts);
        }
        using var allowed = await allowedClient.PostAsJsonAsync("/v1/auth/password/recovery/phone/confirm", request);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Single(api.PhoneSender.ApprovalAttempts);
        using var body = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync());
        var token = body.RootElement.GetProperty("token").GetString();
        using var reset = await allowedClient.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset", new { token, newPassword = "phone-recovered-password" });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
        Assert.Equal(account.IdentityId, (await LoginAsync(account.Email, "phone-recovered-password")).IdentityId);
    }

    [Fact]
    public async Task StartFlow_RequiresExecutionPermissionBeforePersistingTheJourney()
    {
        var account = await RegisterAsync();
        var request = CreateStartRequest(account.Token);

        using var forbidden = await forbiddenClient.PostAsJsonAsync("/v1/access/flows", request);

        await AssertForbiddenAsync(forbidden);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.AccessFlows.AnyAsync(item => item.IdentityId == account.IdentityId));
        }
        using var allowed = await allowedClient.PostAsJsonAsync("/v1/access/flows", request);
        Assert.Equal(HttpStatusCode.Created, allowed.StatusCode);
        using var body = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync());
        var snapshot = body.RootElement.GetProperty("snapshot");
        Assert.Equal("active", snapshot.GetProperty("status").GetString());
        await AssertFlowUnchangedAsync(snapshot, account.IdentityId);
    }

    [Fact]
    public async Task GetFlow_RequiresExecutionPermissionEvenWithAValidCapability()
    {
        var account = await RegisterAsync();
        var flow = await StartFlowAsync(account.Token);
        var snapshot = flow.GetProperty("snapshot");

        using var forbidden = await SendFlowRequestAsync(forbiddenClient, flow, HttpMethod.Get);

        await AssertForbiddenAsync(forbidden);
        await AssertFlowUnchangedAsync(snapshot, account.IdentityId);
        using var allowed = await SendFlowRequestAsync(allowedClient, flow, HttpMethod.Get);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        using var body = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync());
        var received = body.RootElement.GetProperty("snapshot");
        Assert.Equal(snapshot.GetProperty("flowId").GetGuid(), received.GetProperty("flowId").GetGuid());
        Assert.Equal(snapshot.GetProperty("revision").GetInt32(), received.GetProperty("revision").GetInt32());
    }

    [Fact]
    public async Task ActOnFlow_RequiresExecutionPermissionBeforeCompletingRegistration()
    {
        var account = await RegisterAsync();
        var flow = await StartFlowAsync(account.Token);
        var snapshot = flow.GetProperty("snapshot");
        var skip = Assert.Single(snapshot.GetProperty("actions").EnumerateArray(),
            item => item.GetProperty("type").GetString() == "skipRegistration");
        var requestId = Guid.NewGuid();
        var request = new
        {
            requestId,
            expectedRevision = snapshot.GetProperty("revision").GetInt32(),
            action = new { id = skip.GetProperty("id").GetGuid(), type = "skipRegistration" },
        };

        using var forbidden = await SendFlowRequestAsync(forbiddenClient, flow, HttpMethod.Post, request);

        await AssertForbiddenAsync(forbidden);
        await AssertFlowUnchangedAsync(snapshot, account.IdentityId);
        await AssertSessionActiveAsync(account.Token, true);
        await AssertSessionCountAsync(account.IdentityId, 1);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.AccessFlowRequests.AnyAsync(item => item.RequestId == requestId));
        }
        using var allowed = await SendFlowRequestAsync(allowedClient, flow, HttpMethod.Post, request);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        using var body = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync());
        var completed = body.RootElement.GetProperty("snapshot");
        Assert.Equal("completed", completed.GetProperty("status").GetString());
        Assert.Equal("skipped", completed.GetProperty("result").GetProperty("outcome").GetString());
        Assert.Equal(snapshot.GetProperty("revision").GetInt32() + 1, completed.GetProperty("revision").GetInt32());
        var issuedSession = body.RootElement.GetProperty("issuedSession");
        Assert.Equal("product", issuedSession.GetProperty("purpose").GetString());
        await AssertSessionActiveAsync(Assert.IsType<string>(issuedSession.GetProperty("sessionToken").GetString()), true);
        await AssertSessionActiveAsync(account.Token, false);
    }

    private HttpClient CreateClient(BootstrapTopologyResult bootstrap, string key)
    {
        var credential = bootstrap.IssuedCredentials.Single(item =>
            item.IntegrationClientPath.EndsWith($"/integration-clients/{key}", StringComparison.Ordinal));
        var result = api.CreateClient();
        result.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential.Token);
        return result;
    }

    private async Task<AccountSession> RegisterAsync()
    {
        var email = $"execution-permission-{Guid.NewGuid():N}@example.test";
        using var response = await client.PostAsJsonAsync("/v1/auth/register", new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await ReadAccountAsync(response, email);
    }

    private async Task<AccountSession> RegisterPhoneOwnerAsync()
    {
        var account = await RegisterAsync();
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var now = DateTimeOffset.UtcNow;
        db.IdentityIdentifiers.Add(new IdentityIdentifier(
            Guid.CreateVersion7(now), account.IdentityId, realmId, IdentifierScheme.Phone,
            Phone, now, now, "test:phone"));
        await db.SaveChangesAsync();
        return account;
    }

    private async Task<AccountSession> LoginAsync(string email, string password)
    {
        using var response = await client.PostAsJsonAsync("/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadAccountAsync(response, email);
    }

    private static async Task<AccountSession> ReadAccountAsync(HttpResponseMessage response, string email)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return new AccountSession(body.RootElement.GetProperty("identityId").GetGuid(), email,
            Assert.IsType<string>(body.RootElement.GetProperty("sessionToken").GetString()));
    }

    private async Task AssertSessionActiveAsync(string token, bool expected)
    {
        using var response = await client.PostAsJsonAsync("/v1/auth/session/introspect", new { sessionToken = token });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(expected, body.RootElement.GetProperty("active").GetBoolean());
    }

    private async Task AssertSessionCountAsync(Guid identityId, int expected)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(expected, await db.IdentitySessions.CountAsync(item => item.IdentityId == identityId));
    }

    private async Task AssertNoResetTokensAsync(Guid identityId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await db.PasswordResetTokens.AnyAsync(item => item.IdentityId == identityId));
    }

    private async Task AssertFlowUnchangedAsync(JsonElement snapshot, Guid identityId)
    {
        var flowId = snapshot.GetProperty("flowId").GetGuid();
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var flow = await db.AccessFlows.AsNoTracking().SingleAsync(item => item.Id == flowId);
        Assert.Equal(identityId, flow.IdentityId);
        Assert.Equal(AccessFlowStatus.Active, flow.Status);
        Assert.Equal(snapshot.GetProperty("revision").GetInt32(), flow.CurrentRevision);
    }

    private async Task<JsonElement> StartFlowAsync(string token)
    {
        using var response = await allowedClient.PostAsJsonAsync("/v1/access/flows", CreateStartRequest(token));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.Clone();
    }

    private static object CreateStartRequest(string token) => new
    {
        requestId = Guid.NewGuid(),
        protocolVersions = new[] { 1 },
        intent = "continueRegistration",
        applicationClientKey = "android-debug",
        sessionToken = token,
    };

    private static async Task<HttpResponseMessage> SendFlowRequestAsync(
        HttpClient caller, JsonElement flow, HttpMethod method, object? body = null)
    {
        var flowId = flow.GetProperty("snapshot").GetProperty("flowId").GetGuid();
        var path = $"/v1/access/flows/{flowId:D}" + (method == HttpMethod.Post ? "/actions" : "");
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Add("Bullgate-Flow-Capability", flow.GetProperty("flowCapability").GetString());
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        return await caller.SendAsync(request);
    }

    private static async Task AssertForbiddenAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
    }

    private static BootstrapTopologyCommand CreateBootstrapCommand(string suffix)
    {
        var policy = TestAccessPolicies.Create(googleEnabled: true, appleEnabled: true);
        return new BootstrapTopologyCommand(
            $"execution-permissions-{suffix}", "Execution permission tests",
            [
                new BootstrapAppDefinition("app", "App",
                    [new BootstrapRealmDefinition("realm", "Realm")],
                    [
                        new BootstrapEnvironmentDefinition("tests", "Tests", "realm", policy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(RecoveryUrl),
                            TestEnvironmentConfigurations.Providers(policy, RecoveryUrl),
                            TestEnvironmentConfigurations.DevelopmentBypass(policy),
                            [
                                new("full", "Full", AccessPermission.All),
                                new("execution-only", "Execution only", [AccessPermission.ExecuteFlows]),
                                new("without-execution", "Without execution",
                                    AccessPermission.All.Except([AccessPermission.ExecuteFlows]).ToArray()),
                            ],
                            [
                                new BootstrapApplicationClientDefinition("android-debug", "Android debug",
                                    ApplicationClientPlatform.Android, "app.baybo",
                                    "sha256:fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
                                    "92TvTC0UfaA", JsonSerializer.SerializeToElement(new { })),
                            ]),
                    ]),
            ]);
    }

    private sealed record AccountSession(Guid IdentityId, string Email, string Token);
}
