using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class AccountPermissionEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private BootstrapTopologyResult bootstrap = null!;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await dbContext.Database.EnsureCreatedAsync();
        bootstrap = await scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>()
            .HandleAsync(CreateBootstrapCommand(Guid.NewGuid().ToString("N")));
        client = CreateClient("full");
    }

    public async Task DisposeAsync()
    {
        client.Dispose();
        await api.DisposeAsync();
    }

    [Theory]
    [InlineData("without-introspection")]
    [InlineData("no-permissions")]
    public async Task Introspect_RequiresItsExactPermissionBeforeRevealingIdentity(
        string forbiddenClientKey)
    {
        var account = await RegisterAsync();
        using var forbiddenClient = CreateClient(forbiddenClientKey);

        using var forbidden = await forbiddenClient.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = account.Token });

        await AssertForbiddenAsync(forbidden);
        using var allowedClient = CreateClient("introspection-only");
        using var allowed = await allowedClient.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = account.Token });
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        using var body = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.GetProperty("active").GetBoolean());
        Assert.Equal(account.IdentityId, body.RootElement.GetProperty("identityId").GetGuid());
        Assert.Equal(account.Email, body.RootElement.GetProperty("email").GetString());
    }

    [Fact]
    public async Task Revoke_RequiresCurrentSessionPermissionEvenWhenRevokeAllIsGranted()
    {
        var account = await RegisterAsync();
        var otherSession = await LoginAsync(account.Email, "password-123");
        using var forbiddenClient = CreateClient("without-revoke");

        using var forbidden = await forbiddenClient.PostAsJsonAsync(
            "/v1/auth/session/revoke",
            new { sessionToken = account.Token });

        await AssertForbiddenAsync(forbidden);
        await AssertSessionActiveAsync(account.Token, true);
        await AssertSessionActiveAsync(otherSession.Token, true);

        using var allowedClient = CreateClient("revoke-only");
        using var allowed = await allowedClient.PostAsJsonAsync(
            "/v1/auth/session/revoke",
            new { sessionToken = account.Token });
        Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);
        await AssertSessionActiveAsync(account.Token, false);
        await AssertSessionActiveAsync(otherSession.Token, true);
    }

    [Fact]
    public async Task ChangePassword_RequiresManagePermissionBeforeChangingCredentialOrSessions()
    {
        var account = await RegisterAsync();
        var otherSession = await LoginAsync(account.Email, "password-123");
        var request = new
        {
            sessionToken = account.Token,
            currentPassword = "password-123",
            newPassword = "replacement-password",
        };
        using var forbiddenClient = CreateClient("without-management");
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var originalHash = await dbContext.PasswordCredentials.AsNoTracking()
            .Where(credential => credential.IdentityId == account.IdentityId)
            .Select(credential => credential.PasswordHash)
            .SingleAsync();

        using var forbidden = await forbiddenClient.PostAsJsonAsync(
            "/v1/account/password",
            request);

        await AssertForbiddenAsync(forbidden);
        var preservedHash = await dbContext.PasswordCredentials.AsNoTracking()
            .Where(credential => credential.IdentityId == account.IdentityId)
            .Select(credential => credential.PasswordHash)
            .SingleAsync();
        Assert.Equal(originalHash, preservedHash);
        await AssertSessionActiveAsync(account.Token, true);
        await AssertSessionActiveAsync(otherSession.Token, true);

        using var allowedClient = CreateClient("management-only");
        using var allowed = await allowedClient.PostAsJsonAsync(
            "/v1/account/password",
            request);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        var login = await LoginAsync(account.Email, request.newPassword);
        Assert.Equal(account.IdentityId, login.IdentityId);
        await AssertSessionActiveAsync(account.Token, true);
        await AssertSessionActiveAsync(otherSession.Token, false);
    }

    [Fact]
    public async Task ChangeEmail_RequiresManagePermissionBeforeReplacingTheLoginAddress()
    {
        var account = await RegisterAsync();
        var request = new
        {
            sessionToken = account.Token,
            email = $"replacement-{Guid.NewGuid():N}@example.test",
        };
        using var forbiddenClient = CreateClient("without-management");

        using var forbidden = await forbiddenClient.PutAsJsonAsync("/v1/account/email", request);

        await AssertForbiddenAsync(forbidden);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var originalEmail = await dbContext.IdentityIdentifiers.AsNoTracking()
            .Where(identifier => identifier.IdentityId == account.IdentityId
                && identifier.Scheme == IdentifierScheme.Email)
            .Select(identifier => identifier.NormalizedValue)
            .SingleAsync();
        Assert.Equal(account.Email, originalEmail);
        await AssertSessionActiveAsync(account.Token, true);

        using var allowedClient = CreateClient("management-only");
        using var allowed = await allowedClient.PutAsJsonAsync("/v1/account/email", request);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        var login = await LoginAsync(request.email, "password-123");
        Assert.Equal(account.IdentityId, login.IdentityId);
    }

    [Fact]
    public async Task DeleteAccount_RequiresManagePermissionBeforeRemovingAccountData()
    {
        var account = await RegisterAsync();
        using var forbiddenClient = CreateClient("without-management");

        using var forbidden = await DeleteAsync(forbiddenClient, account.Token);

        await AssertForbiddenAsync(forbidden);
        await AssertSessionActiveAsync(account.Token, true);
        var login = await LoginAsync(account.Email, "password-123");
        Assert.Equal(account.IdentityId, login.IdentityId);

        using var allowedClient = CreateClient("management-only");
        using var allowed = await DeleteAsync(allowedClient, account.Token);
        Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);
        await AssertSessionActiveAsync(account.Token, false);
        await AssertSessionActiveAsync(login.Token, false);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.Identities.AnyAsync(
            identity => identity.Id == account.IdentityId));
    }

    [Theory]
    [InlineData("google", SocialProvider.Google)]
    [InlineData("apple", SocialProvider.Apple)]
    public async Task LinkProvider_RequiresManagePermissionBeforeAddingAnAuthenticator(
        string provider,
        string expectedProvider)
    {
        var account = await RegisterAsync();
        var request = CreateProviderRequest(provider, account.Token);
        using var forbiddenClient = CreateClient("without-management");

        using var forbidden = await forbiddenClient.PostAsJsonAsync(
            $"/v1/account/social/{provider}/link",
            request);

        await AssertForbiddenAsync(forbidden);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.SocialCredentials.AnyAsync(
            credential => credential.IdentityId == account.IdentityId));

        using var allowedClient = CreateClient("management-only");
        using var allowed = await allowedClient.PostAsJsonAsync(
            $"/v1/account/social/{provider}/link",
            request);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        var credential = await dbContext.SocialCredentials.AsNoTracking()
            .SingleAsync(item => item.IdentityId == account.IdentityId);
        Assert.Equal(expectedProvider, credential.Provider);
        await AssertSessionActiveAsync(account.Token, true);
    }

    [Theory]
    [InlineData("google", SocialProvider.Google)]
    [InlineData("apple", SocialProvider.Apple)]
    public async Task UnlinkProvider_RequiresManagePermissionBeforeRemovingAnAuthenticator(
        string provider,
        string expectedProvider)
    {
        var account = await RegisterAsync();
        using var linked = await client.PostAsJsonAsync(
            $"/v1/account/social/{provider}/link",
            CreateProviderRequest(provider, account.Token));
        Assert.Equal(HttpStatusCode.OK, linked.StatusCode);
        using var forbiddenClient = CreateClient("without-management");

        using var forbidden = await forbiddenClient.PostAsJsonAsync(
            $"/v1/account/social/{provider}/unlink",
            new { sessionToken = account.Token });

        await AssertForbiddenAsync(forbidden);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var preserved = await dbContext.SocialCredentials.AsNoTracking()
            .SingleAsync(credential => credential.IdentityId == account.IdentityId);
        Assert.Equal(expectedProvider, preserved.Provider);
        await AssertSessionActiveAsync(account.Token, true);

        using var allowedClient = CreateClient("management-only");
        using var allowed = await allowedClient.PostAsJsonAsync(
            $"/v1/account/social/{provider}/unlink",
            new { sessionToken = account.Token });
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.False(await dbContext.SocialCredentials.AnyAsync(
            credential => credential.IdentityId == account.IdentityId));
        var login = await LoginAsync(account.Email, "password-123");
        Assert.Equal(account.IdentityId, login.IdentityId);
    }

    [Theory]
    [InlineData("POST", "/v1/auth/session/introspect")]
    [InlineData("POST", "/v1/auth/session/revoke")]
    [InlineData("POST", "/v1/account/password")]
    [InlineData("PUT", "/v1/account/email")]
    [InlineData("DELETE", "/v1/account")]
    public async Task AccountSessionCannotReplaceTheIntegrationCredential(
        string method,
        string path)
    {
        var account = await RegisterAsync();
        using var caller = api.CreateClient();
        caller.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", account.Token);
        var payload = path switch
        {
            "/v1/account/password" => (object)new
            {
                sessionToken = account.Token,
                currentPassword = "password-123",
                newPassword = "rejected-password",
            },
            "/v1/account/email" => new
            {
                sessionToken = account.Token,
                email = $"rejected-{Guid.NewGuid():N}@example.test",
            },
            _ => new { sessionToken = account.Token },
        };
        using var request = new HttpRequestMessage(new HttpMethod(method), path)
        {
            Content = JsonContent.Create(payload),
        };

        using var response = await caller.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        await AssertSessionActiveAsync(account.Token, true);
        var login = await LoginAsync(account.Email, "password-123");
        Assert.Equal(account.IdentityId, login.IdentityId);
    }

    private HttpClient CreateClient(string key)
    {
        var credential = Assert.Single(bootstrap.IssuedCredentials, item =>
            item.IntegrationClientPath.EndsWith(
                $"/integration-clients/{key}",
                StringComparison.Ordinal));
        var result = api.CreateClient();
        result.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", credential.Token);
        return result;
    }

    private async Task<AccountSession> RegisterAsync()
    {
        var email = $"permission-{Guid.NewGuid():N}@example.test";
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await ReadSessionAsync(response, email);
    }

    private async Task<AccountSession> LoginAsync(string email, string password)
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadSessionAsync(response, email);
    }

    private static async Task<AccountSession> ReadSessionAsync(
        HttpResponseMessage response,
        string email)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        Assert.Equal("product", root.GetProperty("sessionPurpose").GetString());
        return new AccountSession(
            root.GetProperty("identityId").GetGuid(),
            email,
            Assert.IsType<string>(root.GetProperty("sessionToken").GetString()));
    }

    private async Task AssertSessionActiveAsync(string token, bool expectedActive)
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = token });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(expectedActive, body.RootElement.GetProperty("active").GetBoolean());
    }

    private static async Task AssertForbiddenAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
    }

    private static async Task<HttpResponseMessage> DeleteAsync(
        HttpClient caller,
        string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, "/v1/account")
        {
            Content = JsonContent.Create(new { sessionToken = token }),
        };
        return await caller.SendAsync(request);
    }

    private static object CreateProviderRequest(string provider, string token) =>
        provider switch
        {
            "google" => new { sessionToken = token, idToken = "google-token" },
            "apple" => new { sessionToken = token, identityToken = "apple-token" },
            _ => throw new ArgumentOutOfRangeException(nameof(provider)),
        };

    private static BootstrapTopologyCommand CreateBootstrapCommand(string suffix)
    {
        var policy = TestAccessPolicies.Create(
            phoneEnabled: false,
            phoneVerificationEnabled: false,
            googleEnabled: true,
            appleEnabled: true);
        var clients = new BootstrapIntegrationClientDefinition[]
        {
            new("full", "Full", AccessPermission.All),
            new("no-permissions", "No permissions", []),
            new("introspection-only", "Introspection only", [AccessPermission.IntrospectSessions]),
            new("revoke-only", "Revoke only", [AccessPermission.RevokeCurrentSession]),
            new("management-only", "Management only", [AccessPermission.ManageCurrentIdentity]),
            new("without-introspection", "Without introspection",
                AccessPermission.All.Except([AccessPermission.IntrospectSessions]).ToArray()),
            new("without-revoke", "Without revoke",
                AccessPermission.All.Except([AccessPermission.RevokeCurrentSession]).ToArray()),
            new("without-management", "Without management",
                AccessPermission.All.Except([AccessPermission.ManageCurrentIdentity]).ToArray()),
        };

        return new BootstrapTopologyCommand(
            $"permissions-{suffix}",
            "Permission tests",
            [
                new BootstrapAppDefinition(
                    "app",
                    "App",
                    [new BootstrapRealmDefinition("realm", "Realm")],
                    [
                        new BootstrapEnvironmentDefinition(
                            "tests",
                            "Tests",
                            "realm",
                            policy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(policy),
                            TestEnvironmentConfigurations.DevelopmentBypass(policy),
                            clients,
                            []),
                    ]),
            ]);
    }

    private sealed record AccountSession(Guid IdentityId, string Email, string Token);
}
