using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bullgate.Access.Application.Administration;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class AccessAdministrationEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private AccessAdministrationTestHost host = null!;
    public async Task InitializeAsync() { host = new(database.ConnectionString); await host.InitializeAsync(); }
    public Task DisposeAsync() => host.DisposeAsync().AsTask();

    [Fact]
    public async Task Capabilities_RequireOnlyServiceAuthorityAndExposeExactlyFiveKeys()
    {
        using var response = await host.Admin.GetAsync("/admin/v1/capabilities");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, body.GetProperty("contractVersion").GetInt32());
        Assert.Equal(AccessPermission.Administrative, body.GetProperty("permissions").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal(2, body.EnumerateObject().Count());
    }

    [Theory]
    [InlineData("")] [InlineData("invalid")] [InlineData("00")]
    public async Task InvalidInstallationHash_DisablesAdminWithoutFallback(string hash)
    {
        await using var api = host.Api.WithWebHostBuilder(builder => builder.UseSetting("Bullgate:Admin:CredentialSha256", hash));
        using var client = api.CreateClient(new() { BaseAddress = new("https://localhost") });
        client.DefaultRequestHeaders.Authorization = new("BullgateAdmin", host.Secret);
        using var response = await client.GetAsync("/admin/v1/capabilities");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ConsumerBearer_AndAdminServiceCannotCrossCallerBoundaries()
    {
        using var response = await host.Consumer.GetAsync("https://localhost/admin/v1/capabilities");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var denied = await host.Admin.PostAsJsonAsync("/v1/auth/session/introspect", new { sessionToken = "not-authority" });
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    public async Task WrongOrNoncanonicalServiceSecret_IsRejected(string token)
    {
        using var client = host.Api.CreateClient(new() { BaseAddress = new("https://localhost") });
        client.DefaultRequestHeaders.Authorization = new("BullgateAdmin", token);
        using var response = await client.GetAsync("/admin/v1/capabilities");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RepeatedAuthorization_AndNonTlsNonLoopbackTransport_AreRejected()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/admin/v1/capabilities");
        request.Headers.TryAddWithoutValidation("Authorization", new[] { $"BullgateAdmin {host.Secret}", $"BullgateAdmin {host.Secret}" });
        using var response = await host.Admin.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var insecure = host.Api.CreateClient(new() { BaseAddress = new("http://example.test") });
        insecure.DefaultRequestHeaders.Authorization = new("BullgateAdmin", host.Secret);
        using var insecureResponse = await insecure.GetAsync("/admin/v1/capabilities");
        Assert.Equal(HttpStatusCode.Unauthorized, insecureResponse.StatusCode);
    }

    [Theory]
    [InlineData(null)] [InlineData("invalid")]
    [InlineData("{}")] [InlineData("{\"operatorId\":\"o\",\"sessionId\":\"s\",\"scopeId\":\"c\",\"permission\":\"access:identities:list\",\"extra\":true}")]
    [InlineData("{\"operatorId\":\"\",\"sessionId\":\"s\",\"scopeId\":\"c\",\"permission\":\"access:identities:list\"}")]
    public async Task MissingMalformedOrUntrustedContext_IsUnauthorized(string? context)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/admin/v1/realms/{host.RealmId}/identities");
        if (context is not null) request.Headers.Add("X-Bullgate-Admin-Context", WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(context)));
        using var response = await host.Admin.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task WrongFunction_IsForbiddenAndMismatchedRealmIsNotFound()
    {
        var user = await host.RegisterAsync();
        using var forbidden = await host.SendAsync(HttpMethod.Delete, host.IdentityPath(user.Id), AccessPermission.ReadIdentities, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        using var missing = await host.SendAsync(HttpMethod.Get, $"/admin/v1/realms/{Guid.NewGuid()}/identities/{user.Id}", AccessPermission.ReadIdentities);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        await using var scope = host.Api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.True(await db.Identities.AnyAsync(identity => identity.Id == user.Id));
        Assert.False(await db.AdminOperations.AnyAsync(operation => operation.TargetId == user.Id));
    }

    [Fact]
    public async Task Directory_IsBoundedStableAndExactlyFilteredWithoutSecretFields()
    {
        var user = await host.RegisterAsync();
        await using (var scope = host.Api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.Identities.AddRange(Enumerable.Range(0, 29).Select(_ => new Identity(Guid.CreateVersion7(), host.RealmId, now)));
            db.IdentityIdentifiers.Add(new(Guid.CreateVersion7(), user.Id, host.RealmId, IdentifierScheme.Phone, "+5511999990001", now, now, "test"));
            await db.SaveChangesAsync();
        }
        var path = $"/admin/v1/realms/{host.RealmId}/identities";
        using var first = await host.SendAsync(HttpMethod.Get, path, AccessPermission.ListIdentities);
        first.EnsureSuccessStatusCode();
        var page = (await first.Content.ReadFromJsonAsync<AdminPage<AdminIdentity>>())!;
        Assert.Equal(25, page.Items.Count);
        Assert.NotNull(page.NextCursor);
        using var next = await host.SendAsync(HttpMethod.Get, path + "?cursor=" + Uri.EscapeDataString(page.NextCursor), AccessPermission.ListIdentities);
        var second = (await next.Content.ReadFromJsonAsync<AdminPage<AdminIdentity>>())!;
        Assert.Equal(5, second.Items.Count);
        Assert.Empty(page.Items.Select(item => item.Id).Intersect(second.Items.Select(item => item.Id)));
        foreach (var filter in new[] { "identityId=" + user.Id, "email=" + Uri.EscapeDataString(user.Email), "phone=%2B5511999990001" })
        {
            using var exact = await host.SendAsync(HttpMethod.Get, path + "?" + filter, AccessPermission.ListIdentities);
            exact.EnsureSuccessStatusCode();
            var selected = Assert.Single((await exact.Content.ReadFromJsonAsync<AdminPage<AdminIdentity>>())!.Items);
            Assert.Equal(user.Id, selected.Id);
            Assert.False(selected.Email!.Verified);
            Assert.True(selected.Phone!.Verified);
        }
        using var tooLarge = await host.SendAsync(HttpMethod.Get, path + "?pageSize=51", AccessPermission.ListIdentities);
        Assert.Equal(HttpStatusCode.BadRequest, tooLarge.StatusCode);
        using var detail = await host.SendAsync(HttpMethod.Get, host.IdentityPath(user.Id), AccessPermission.ReadIdentities);
        var json = await detail.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(new[] { "id", "realmId", "lifecycle", "createdAt", "email", "phone" }, json.EnumerateObject().Select(property => property.Name));
    }

    [Fact]
    public async Task Revoke_CutsProductAndRegistrationSessionsAcrossEnvironmentsAndAllowsNewLogin()
    {
        var user = await host.RegisterAsync();
        using var login = await host.SecondaryConsumer.PostAsJsonAsync("/v1/auth/login", new { email = user.Email, password = "password-123" });
        login.EnsureSuccessStatusCode();
        var secondaryToken = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("sessionToken").GetString()!;
        await using (var scope = host.Api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.IdentitySessions.Add(new(Guid.CreateVersion7(), user.Id, host.EnvironmentId, IdentitySessionPurpose.Registration,
                RandomNumberGenerator.GetBytes(32), now, now.AddDays(1)));
            await db.SaveChangesAsync();
        }
        var id = Guid.NewGuid();
        using var revoked = await host.SendAsync(HttpMethod.Post, host.IdentityPath(user.Id) + "/sessions/revoke", AccessPermission.RevokeAllSessions, id);
        revoked.EnsureSuccessStatusCode();
        var result = (await revoked.Content.ReadFromJsonAsync<AdminOperationResult>())!;
        Assert.Equal(3, result.RevokedSessions);
        foreach (var pair in new[] { (host.Consumer, user.Token), (host.SecondaryConsumer, secondaryToken) })
        {
            using var introspection = await pair.Item1.PostAsJsonAsync("/v1/auth/session/introspect", new { sessionToken = pair.Item2 });
            Assert.False((await introspection.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean());
        }
        using var newLogin = await host.Consumer.PostAsJsonAsync("/v1/auth/login", new { email = user.Email, password = "password-123" });
        newLogin.EnsureSuccessStatusCode();
        var newToken = (await newLogin.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("sessionToken").GetString();
        using var replay = await host.SendAsync(HttpMethod.Post, host.IdentityPath(user.Id) + "/sessions/revoke", AccessPermission.RevokeAllSessions, id,
            context: AccessAdministrationTestHost.Context(AccessPermission.RevokeAllSessions) with { SessionId = "fresh-session" });
        Assert.Equal(result, await replay.Content.ReadFromJsonAsync<AdminOperationResult>());
        using var active = await host.Consumer.PostAsJsonAsync("/v1/auth/session/introspect", new { sessionToken = newToken });
        Assert.True((await active.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Configuration_ReplacesTypedPolicyClientsAndPublicProjectionWithoutLeakingSecrets()
    {
        var revision = await host.RevisionAsync();
        var policy = TestAccessPolicies.Create(phoneEnabled: false, phoneVerificationEnabled: false, passwordEnabled: false);
        var configuration = host.Configuration with
        {
            AccessPolicy = policy,
            RecoveryPolicy = TestEnvironmentConfigurations.RecoveryPolicy("https://example.test/reset"),
            Providers = new(new("smtp.example.test", 587, "user", "not-a-real-secret", "sender@example.test", "Test", true, false), null, null, null),
            PublicConfiguration = new(2, JsonSerializer.SerializeToElement(new { message = "updated" })),
            ApplicationClients = [host.Configuration.ApplicationClients[0] with { Name = "Updated Web", PublicConfiguration = JsonSerializer.SerializeToElement(new { theme = "new" }) }],
        };
        var id = Guid.NewGuid();
        using var response = await host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration, id, configuration, revision);
        response.EnsureSuccessStatusCode();
        var result = (await response.Content.ReadFromJsonAsync<AdminOperationResult>())!;
        Assert.NotEqual(revision, result.Revision);
        Assert.Equal(result.Revision, response.Headers.ETag!.ToString());
        Assert.DoesNotContain("not-a-real-secret", await response.Content.ReadAsStringAsync());
        using var publicResponse = await host.Consumer.GetAsync("/v1/config/application-clients/web");
        publicResponse.EnsureSuccessStatusCode();
        var body = await publicResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, body.GetProperty("configurationVersion").GetInt32());
        Assert.Equal("updated", body.GetProperty("common").GetProperty("message").GetString());
        Assert.Equal("Updated Web", body.GetProperty("client").GetProperty("name").GetString());
        await using var scope = host.Api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False((await db.AppEnvironments.SingleAsync(item => item.Id == host.EnvironmentId)).PasswordAuthenticatorEnabled);
        var receipt = await db.AdminOperations.SingleAsync(item => item.OperationId == id);
        Assert.DoesNotContain("not-a-real-secret", receipt.ResultJson);
        Assert.Equal(32, receipt.RequestFingerprint.Length);
        using var replay = await host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration, id, configuration, revision);
        Assert.Equal(result, await replay.Content.ReadFromJsonAsync<AdminOperationResult>());
        using var stale = await host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration, Guid.NewGuid(), configuration, revision);
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        using var conflict = await host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration, id, host.Configuration, revision);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
    }

    [Theory]
    [InlineData("missing-section")] [InlineData("unknown-property")] [InlineData("null-clients")]
    [InlineData("new-integration-client")] [InlineData("changed-permissions")] [InlineData("new-application-client")]
    [InlineData("invalid-limits")] [InlineData("missing-revision")]
    public async Task Configuration_RejectsInvalidDocumentOrLifecycleChangesWithoutPartialSave(string scenario)
    {
        var revision = await host.RevisionAsync();
        var body = JsonSerializer.SerializeToNode(host.Configuration, AccessAdministrationTestHost.Json)!.AsObject();
        switch (scenario)
        {
            case "missing-section": body.Remove("providers"); break;
            case "unknown-property": body["secret-misspelling"] = "must-not-echo"; break;
            case "null-clients": body["applicationClients"] = null; break;
            case "new-integration-client": body["integrationClients"]![0]!["key"] = "new-client"; break;
            case "changed-permissions": body["integrationClients"]![0]!["permissions"] = new JsonArray(AccessPermission.ReadIdentities); break;
            case "new-application-client": body["applicationClients"]![0]!["key"] = "new-client"; break;
            case "invalid-limits": body["verificationPolicy"]!["maxAttempts"] = 0; break;
        }
        var id = Guid.NewGuid();
        using var response = await host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration, id, body,
            scenario == "missing-revision" ? null : revision);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("must-not-echo", await response.Content.ReadAsStringAsync());
        Assert.Equal(revision, await host.RevisionAsync());
        await using var scope = host.Api.Services.CreateAsyncScope();
        Assert.False(await scope.ServiceProvider.GetRequiredService<AccessDbContext>().AdminOperations.AnyAsync(item => item.OperationId == id));
    }
}
