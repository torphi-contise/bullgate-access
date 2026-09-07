using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class SessionEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private readonly AdjustableTimeProvider clock = new(
        new DateTimeOffset(2026, 9, 6, 12, 0, 0, TimeSpan.Zero));
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private HttpClient secondaryClient = null!;
    private string topologySuffix = null!;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString, clock);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await dbContext.Database.EnsureCreatedAsync();
        topologySuffix = Guid.NewGuid().ToString("N");
        var bootstrap = await scope.ServiceProvider
            .GetRequiredService<BootstrapTopologyHandler>()
            .HandleAsync(CreateBootstrapCommand(topologySuffix));

        client = CreateClient(bootstrap, "primary");
        secondaryClient = CreateClient(bootstrap, "secondary");
    }

    public async Task DisposeAsync()
    {
        secondaryClient.Dispose();
        client.Dispose();
        await api.DisposeAsync();
    }

    [Fact]
    public async Task Login_IssuesAnIndependentSessionWithItsOwnLifetimeAndHash()
    {
        var email = $"session-login-{Guid.NewGuid():N}@example.test";
        var registeredAt = clock.GetUtcNow();
        var registration = await RegisterAsync(email);
        clock.Advance(TimeSpan.FromDays(1));

        var login = await LoginAsync(client, email);

        Assert.Equal(registration.IdentityId, login.IdentityId);
        Assert.NotEqual(registration.Token, login.Token);
        Assert.Equal(registeredAt.AddDays(30), registration.ExpiresAt);
        Assert.Equal(clock.GetUtcNow().AddDays(30), login.ExpiresAt);
        var registrationState = await IntrospectAsync(client, registration.Token);
        var loginState = await IntrospectAsync(client, login.Token);
        Assert.True(registrationState.GetProperty("active").GetBoolean());
        Assert.True(loginState.GetProperty("active").GetBoolean());
        Assert.NotEqual(
            registrationState.GetProperty("sessionId").GetGuid(),
            loginState.GetProperty("sessionId").GetGuid());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var sessions = await dbContext.IdentitySessions.AsNoTracking()
            .Where(session => session.IdentityId == registration.IdentityId)
            .OrderBy(session => session.CreatedAt)
            .ToArrayAsync();
        Assert.Equal(2, sessions.Length);
        Assert.Equal(HashToken(registration.Token), sessions[0].TokenHash);
        Assert.Equal(HashToken(login.Token), sessions[1].TokenHash);
        Assert.Equal(registeredAt, sessions[0].CreatedAt);
        Assert.Equal(clock.GetUtcNow(), sessions[1].CreatedAt);
        Assert.All(sessions, session => Assert.Null(session.RevokedAt));
    }

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(1, false)]
    public async Task Introspect_ExpiresAtTheExactDeadlineWithoutRenewingTheSession(
        int secondsFromExpiration,
        bool expectedActive)
    {
        var registration = await RegisterAsync(
            $"session-expiration-{Guid.NewGuid():N}@example.test");
        clock.Advance(
            registration.ExpiresAt.AddSeconds(secondsFromExpiration) - clock.GetUtcNow());

        var state = await IntrospectAsync(client, registration.Token);

        Assert.Equal(expectedActive, state.GetProperty("active").GetBoolean());
        if (expectedActive)
        {
            Assert.Equal(
                registration.IdentityId,
                state.GetProperty("identityId").GetGuid());
            Assert.Equal(
                registration.ExpiresAt,
                state.GetProperty("expiresAt").GetDateTimeOffset());
        }
        else
        {
            AssertInactiveWithoutIdentity(state);
        }

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var stored = await dbContext.IdentitySessions.AsNoTracking()
            .SingleAsync(session => session.IdentityId == registration.IdentityId);
        Assert.Equal(registration.ExpiresAt, stored.ExpiresAt);
        Assert.Null(stored.RevokedAt);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("bgs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Introspect_UnknownOrMalformedTokenRevealsNoIdentity(string? token)
    {
        var registration = await RegisterAsync(
            $"session-unknown-{Guid.NewGuid():N}@example.test");

        var state = await IntrospectAsync(client, token);

        AssertInactiveWithoutIdentity(state);
        var valid = await IntrospectAsync(client, registration.Token);
        Assert.True(valid.GetProperty("active").GetBoolean());
        Assert.Equal(registration.IdentityId, valid.GetProperty("identityId").GetGuid());
    }

    [Fact]
    public async Task Introspect_AbandonedIdentityIsInactiveEvenWithAnUnrevokedSession()
    {
        await using (var setupScope = api.Services.CreateAsyncScope())
        {
            await setupScope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>()
                .HandleAsync(CreateBootstrapCommand(topologySuffix, registrationRequired: true));
        }
        var registration = await RegisterAsync(
            $"session-abandoned-{Guid.NewGuid():N}@example.test");
        var initialState = await IntrospectAsync(client, registration.Token);
        Assert.True(initialState.GetProperty("active").GetBoolean());
        Assert.Equal("registration", initialState.GetProperty("sessionPurpose").GetString());
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identity = await dbContext.Identities
                .SingleAsync(item => item.Id == registration.IdentityId);
            identity.Abandon();
            await dbContext.SaveChangesAsync();
        }

        var state = await IntrospectAsync(client, registration.Token);

        AssertInactiveWithoutIdentity(state);
        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        var stored = await verification.IdentitySessions.AsNoTracking()
            .SingleAsync(session => session.IdentityId == registration.IdentityId);
        Assert.Null(stored.RevokedAt);
        Assert.True(stored.ExpiresAt > clock.GetUtcNow());
    }

    [Fact]
    public async Task Introspect_DeletedIdentityCannotAuthenticateWithEitherOldSession()
    {
        var email = $"session-deleted-{Guid.NewGuid():N}@example.test";
        var registration = await RegisterAsync(email);
        var login = await LoginAsync(client, email);
        using var request = new HttpRequestMessage(HttpMethod.Delete, "/v1/account")
        {
            Content = JsonContent.Create(new { sessionToken = registration.Token }),
        };
        using var deleted = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        AssertInactiveWithoutIdentity(await IntrospectAsync(client, registration.Token));
        AssertInactiveWithoutIdentity(await IntrospectAsync(client, login.Token));
    }

    [Fact]
    public async Task Introspect_EnvironmentCannotReadAnotherEnvironmentsSessionInTheSameRealm()
    {
        var email = $"session-scope-{Guid.NewGuid():N}@example.test";
        var primary = await RegisterAsync(email);
        var secondary = await LoginAsync(secondaryClient, email);
        Assert.Equal(primary.IdentityId, secondary.IdentityId);

        AssertInactiveWithoutIdentity(await IntrospectAsync(secondaryClient, primary.Token));
        AssertInactiveWithoutIdentity(await IntrospectAsync(client, secondary.Token));
        var primaryState = await IntrospectAsync(client, primary.Token);
        var secondaryState = await IntrospectAsync(secondaryClient, secondary.Token);
        Assert.True(primaryState.GetProperty("active").GetBoolean());
        Assert.True(secondaryState.GetProperty("active").GetBoolean());
        Assert.Equal(primary.IdentityId, primaryState.GetProperty("identityId").GetGuid());
        Assert.Equal(primary.IdentityId, secondaryState.GetProperty("identityId").GetGuid());
    }

    [Fact]
    public async Task Introspect_ExistingSessionsReadTheCurrentEmailAfterItChanges()
    {
        var email = $"session-contact-{Guid.NewGuid():N}@example.test";
        var registration = await RegisterAsync(email);
        var otherSession = await LoginAsync(client, email);
        var changedEmail = $"session-current-{Guid.NewGuid():N}@example.test";
        using var changed = await client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken = registration.Token, email = changedEmail });
        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);

        var state = await IntrospectAsync(client, otherSession.Token);

        Assert.True(state.GetProperty("active").GetBoolean());
        Assert.Equal(registration.IdentityId, state.GetProperty("identityId").GetGuid());
        Assert.Equal(changedEmail, state.GetProperty("email").GetString());
        Assert.Equal("product", state.GetProperty("sessionPurpose").GetString());
        Assert.True(state.GetProperty("hasPassword").GetBoolean());
        Assert.Equal(otherSession.ExpiresAt, state.GetProperty("expiresAt").GetDateTimeOffset());
    }

    [Fact]
    public async Task Revoke_EndsOnlyThePresentedSessionAndKeepsOtherLoginsActive()
    {
        var email = $"session-logout-{Guid.NewGuid():N}@example.test";
        var presented = await RegisterAsync(email);
        var sameIdentity = await LoginAsync(client, email);
        var otherIdentity = await RegisterAsync(
            $"session-other-{Guid.NewGuid():N}@example.test");

        await RevokeAsync(client, presented.Token);

        AssertInactiveWithoutIdentity(await IntrospectAsync(client, presented.Token));
        var sameIdentityState = await IntrospectAsync(client, sameIdentity.Token);
        var otherIdentityState = await IntrospectAsync(client, otherIdentity.Token);
        Assert.True(sameIdentityState.GetProperty("active").GetBoolean());
        Assert.True(otherIdentityState.GetProperty("active").GetBoolean());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var sessions = await dbContext.IdentitySessions.AsNoTracking()
            .Where(session => session.IdentityId == presented.IdentityId
                || session.IdentityId == otherIdentity.IdentityId)
            .ToArrayAsync();
        Assert.Equal(3, sessions.Length);
        var revoked = Assert.Single(sessions, session => session.RevokedAt is not null);
        Assert.Equal(HashToken(presented.Token), revoked.TokenHash);
        Assert.Equal(clock.GetUtcNow(), revoked.RevokedAt);
    }

    [Fact]
    public async Task Revoke_RepeatingLogoutPreservesTheOriginalRevocationTime()
    {
        var registration = await RegisterAsync(
            $"session-repeat-{Guid.NewGuid():N}@example.test");
        var firstRevokedAt = clock.GetUtcNow();
        await RevokeAsync(client, registration.Token);
        clock.Advance(TimeSpan.FromMinutes(5));

        await RevokeAsync(client, registration.Token);

        AssertInactiveWithoutIdentity(await IntrospectAsync(client, registration.Token));
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var stored = await dbContext.IdentitySessions.AsNoTracking()
            .SingleAsync(session => session.IdentityId == registration.IdentityId);
        Assert.Equal(firstRevokedAt, stored.RevokedAt);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("bgs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Revoke_UnknownOrMalformedTokenIsNeutralAndKeepsValidSessions(string? token)
    {
        var registration = await RegisterAsync(
            $"session-neutral-{Guid.NewGuid():N}@example.test");

        await RevokeAsync(client, token);

        var state = await IntrospectAsync(client, registration.Token);
        Assert.True(state.GetProperty("active").GetBoolean());
        Assert.Equal(registration.IdentityId, state.GetProperty("identityId").GetGuid());
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var stored = await dbContext.IdentitySessions.AsNoTracking()
            .SingleAsync(session => session.IdentityId == registration.IdentityId);
        Assert.Null(stored.RevokedAt);
    }

    [Fact]
    public async Task Revoke_EnvironmentCannotEndAnotherEnvironmentsSessionInTheSameRealm()
    {
        var email = $"session-logout-scope-{Guid.NewGuid():N}@example.test";
        var primary = await RegisterAsync(email);
        var secondary = await LoginAsync(secondaryClient, email);
        Assert.Equal(primary.IdentityId, secondary.IdentityId);

        await RevokeAsync(secondaryClient, primary.Token);

        var primaryState = await IntrospectAsync(client, primary.Token);
        var secondaryState = await IntrospectAsync(secondaryClient, secondary.Token);
        Assert.True(primaryState.GetProperty("active").GetBoolean());
        Assert.True(secondaryState.GetProperty("active").GetBoolean());

        await RevokeAsync(client, primary.Token);
        AssertInactiveWithoutIdentity(await IntrospectAsync(client, primary.Token));
        secondaryState = await IntrospectAsync(secondaryClient, secondary.Token);
        Assert.True(secondaryState.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task ChangeEmail_RequiresASessionFromTheCallingEnvironmentEvenInTheSameRealm()
    {
        var email = $"email-scope-{Guid.NewGuid():N}@example.test";
        var primary = await RegisterAsync(email);
        var secondary = await LoginAsync(secondaryClient, email);
        Assert.Equal(primary.IdentityId, secondary.IdentityId);

        using var response = await secondaryClient.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken = primary.Token, email = $"changed-{Guid.NewGuid():N}@example.test" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var error = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("session-inactive", error.RootElement.GetProperty("error").GetString());
        Assert.True((await IntrospectAsync(client, primary.Token)).GetProperty("active").GetBoolean());
        Assert.True((await IntrospectAsync(secondaryClient, secondary.Token)).GetProperty("active").GetBoolean());
        Assert.Equal(primary.IdentityId, (await LoginAsync(client, email)).IdentityId);
        Assert.Equal(primary.IdentityId, (await LoginAsync(secondaryClient, email)).IdentityId);
    }

    [Fact]
    public async Task DeleteAccount_RequiresASessionFromTheCallingEnvironmentEvenInTheSameRealm()
    {
        var email = $"deletion-scope-{Guid.NewGuid():N}@example.test";
        var primary = await RegisterAsync(email);
        var secondary = await LoginAsync(secondaryClient, email);
        Assert.Equal(primary.IdentityId, secondary.IdentityId);
        using var request = new HttpRequestMessage(HttpMethod.Delete, "/v1/account")
        {
            Content = JsonContent.Create(new { sessionToken = primary.Token }),
        };

        using var response = await secondaryClient.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var error = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("session-inactive", error.RootElement.GetProperty("error").GetString());
        Assert.True((await IntrospectAsync(client, primary.Token)).GetProperty("active").GetBoolean());
        Assert.True((await IntrospectAsync(secondaryClient, secondary.Token)).GetProperty("active").GetBoolean());
        Assert.Equal(primary.IdentityId, (await LoginAsync(client, email)).IdentityId);
        Assert.Equal(primary.IdentityId, (await LoginAsync(secondaryClient, email)).IdentityId);
    }

    private HttpClient CreateClient(BootstrapTopologyResult bootstrap, string environment)
    {
        var credential = Assert.Single(bootstrap.IssuedCredentials, item =>
            item.IntegrationClientPath.EndsWith(
                $"/{environment}/integration-clients/api",
                StringComparison.Ordinal));
        var result = api.CreateClient();
        result.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", credential.Token);
        return result;
    }

    private async Task<IssuedSession> RegisterAsync(string email)
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await ReadIssuedSessionAsync(response);
    }

    private static async Task<IssuedSession> LoginAsync(HttpClient targetClient, string email)
    {
        using var response = await targetClient.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadIssuedSessionAsync(response);
    }

    private static async Task<IssuedSession> ReadIssuedSessionAsync(HttpResponseMessage response)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        return new IssuedSession(
            root.GetProperty("identityId").GetGuid(),
            Assert.IsType<string>(root.GetProperty("sessionToken").GetString()),
            root.GetProperty("sessionExpiresAt").GetDateTimeOffset());
    }

    private static async Task<JsonElement> IntrospectAsync(HttpClient targetClient, string? token)
    {
        using var response = await targetClient.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = token });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.Clone();
    }

    private static async Task RevokeAsync(HttpClient targetClient, string? token)
    {
        using var response = await targetClient.PostAsJsonAsync(
            "/v1/auth/session/revoke",
            new { sessionToken = token });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
    }

    private static void AssertInactiveWithoutIdentity(JsonElement state)
    {
        Assert.False(state.GetProperty("active").GetBoolean());
        foreach (var field in new[]
        {
            "identityId", "sessionId", "email", "phone", "phoneVerifiedAt",
            "expiresAt", "sessionPurpose", "googleEmail", "appleEmail",
        })
        {
            Assert.True(
                !state.TryGetProperty(field, out var value) || value.ValueKind == JsonValueKind.Null,
                $"Inactive session exposed {field}.");
        }
        Assert.False(state.GetProperty("hasPassword").GetBoolean());
        Assert.False(state.GetProperty("hasGoogle").GetBoolean());
        Assert.False(state.GetProperty("hasApple").GetBoolean());
    }

    private static byte[] HashToken(string token) =>
        SHA256.HashData(Encoding.ASCII.GetBytes(token));

    private static BootstrapTopologyCommand CreateBootstrapCommand(
        string suffix,
        bool registrationRequired = false)
    {
        var policy = TestAccessPolicies.Create(
            phoneEnabled: registrationRequired,
            phoneRequired: registrationRequired,
            phoneVerificationEnabled: registrationRequired);
        var environments = new[] { "primary", "secondary" }
            .Select(key => new BootstrapEnvironmentDefinition(
                key,
                key,
                "shared",
                policy,
                TestEnvironmentConfigurations.VerificationPolicy,
                TestEnvironmentConfigurations.RecoveryPolicy(),
                TestEnvironmentConfigurations.Providers(policy),
                TestEnvironmentConfigurations.DevelopmentBypass(policy),
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
                ],
                []))
            .ToArray();

        return new BootstrapTopologyCommand(
            $"sessions-{suffix}",
            "Session tests",
            [
                new BootstrapAppDefinition(
                    "app",
                    "Session app",
                    [new BootstrapRealmDefinition("shared", "Shared identities")],
                    environments),
            ]);
    }

    private sealed record IssuedSession(Guid IdentityId, string Token, DateTimeOffset ExpiresAt);
}
