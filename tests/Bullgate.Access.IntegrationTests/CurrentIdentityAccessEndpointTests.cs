using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Bullgate.Access.IntegrationTests;

public sealed class CurrentIdentityAccessEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private AccessApiFactory api = null!;
    private HttpClient client = null!;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await dbContext.Database.EnsureCreatedAsync();
        }

        BootstrapTopologyResult bootstrap;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            bootstrap = await handler.HandleAsync(CreateBootstrapCommand(
                Guid.NewGuid().ToString("N")));
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
    public async Task ChangePassword_ReplacesCredentialAndRevokesOtherSessions()
    {
        var email = $"password-{Guid.NewGuid():N}@example.test";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        var currentToken = await ReadSessionTokenAsync(registration);

        var secondLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        var secondToken = await ReadSessionTokenAsync(secondLogin);

        var changed = await client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken = currentToken,
                currentPassword = "password-123",
                newPassword = "new-password-456",
            });

        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        using (var body = JsonDocument.Parse(await changed.Content.ReadAsStringAsync()))
        {
            Assert.True(body.RootElement.GetProperty("hasPassword").GetBoolean());
            Assert.Equal("product", body.RootElement.GetProperty("sessionPurpose").GetString());
        }
        Assert.True(await IsSessionActiveAsync(currentToken));
        Assert.False(await IsSessionActiveAsync(secondToken));

        var oldPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldPassword.StatusCode);
        var newPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "new-password-456" });
        Assert.Equal(HttpStatusCode.OK, newPassword.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_AddsPasswordToSocialIdentityAndPreservesProvider()
    {
        var email = $"password-social-{Guid.NewGuid():N}@example.test";
        var subject = $"password-social-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(email, subject, "Password Social User");
        var currentLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        var currentToken = await ReadSessionTokenAsync(currentLogin);
        using var currentBody = JsonDocument.Parse(
            await currentLogin.Content.ReadAsStringAsync());
        var identityId = currentBody.RootElement.GetProperty("identityId").GetGuid();
        var secondLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        var secondToken = await ReadSessionTokenAsync(secondLogin);

        var changed = await client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken = currentToken,
                newPassword = "first-password-123",
            });

        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        using (var body = JsonDocument.Parse(await changed.Content.ReadAsStringAsync()))
        {
            Assert.Equal(identityId, body.RootElement.GetProperty("identityId").GetGuid());
            Assert.True(body.RootElement.GetProperty("hasPassword").GetBoolean());
            Assert.True(body.RootElement.GetProperty("hasGoogle").GetBoolean());
            Assert.Equal(email, body.RootElement.GetProperty("googleEmail").GetString());
        }
        Assert.True(await IsSessionActiveAsync(currentToken));
        Assert.False(await IsSessionActiveAsync(secondToken));

        var passwordLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "first-password-123" });
        Assert.Equal(HttpStatusCode.OK, passwordLogin.StatusCode);
        using (var body = JsonDocument.Parse(await passwordLogin.Content.ReadAsStringAsync()))
        {
            Assert.Equal(identityId, body.RootElement.GetProperty("identityId").GetGuid());
            Assert.True(body.RootElement.GetProperty("hasGoogle").GetBoolean());
        }

        var providerLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        Assert.Equal(HttpStatusCode.OK, providerLogin.StatusCode);
        using var providerBody = JsonDocument.Parse(
            await providerLogin.Content.ReadAsStringAsync());
        Assert.Equal(
            identityId,
            providerBody.RootElement.GetProperty("identityId").GetGuid());
    }

    [Theory]
    [InlineData(null, "current-password-required")]
    [InlineData("wrong-password", "current-password-wrong")]
    public async Task ChangePassword_RejectsMissingOrWrongCurrentPasswordWithoutChangingCredential(
        string? currentPassword,
        string expectedError)
    {
        var email = $"password-current-{Guid.NewGuid():N}@example.test";
        var (_, sessionToken, _) = await RegisterPasswordIdentityAsync(client, email);

        var response = await client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                currentPassword,
                newPassword = "rejected-password-456",
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(expectedError, body.RootElement.GetProperty("error").GetString());
            Assert.Equal("currentPassword", body.RootElement.GetProperty("field").GetString());
        }
        Assert.True(await IsSessionActiveAsync(sessionToken));

        var originalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, originalLogin.StatusCode);
        var rejectedLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "rejected-password-456" });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedLogin.StatusCode);
    }

    [Theory]
    [InlineData(null, "missing-fields")]
    [InlineData("short", "password-too-short")]
    public async Task ChangePassword_RejectsInvalidNewPasswordWithoutChangingCredential(
        string? newPassword,
        string expectedError)
    {
        var email = $"password-invalid-new-{Guid.NewGuid():N}@example.test";
        var (_, sessionToken, _) = await RegisterPasswordIdentityAsync(client, email);

        var response = await client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                currentPassword = "password-123",
                newPassword,
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(expectedError, body.RootElement.GetProperty("error").GetString());
            Assert.Equal("newPassword", body.RootElement.GetProperty("field").GetString());
        }
        Assert.True(await IsSessionActiveAsync(sessionToken));
        var originalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, originalLogin.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("bgs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task ChangePassword_RejectsMissingMalformedOrUnknownSession(
        string? sessionToken)
    {
        var email = $"password-session-{Guid.NewGuid():N}@example.test";
        await RegisterPasswordIdentityAsync(client, email);

        var response = await client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                currentPassword = "password-123",
                newPassword = "rejected-password-456",
            });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        var originalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, originalLogin.StatusCode);
        var rejectedLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "rejected-password-456" });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedLogin.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_SessionFromAnotherEnvironmentCannotChangeCredential()
    {
        var email = $"password-environment-{Guid.NewGuid():N}@example.test";
        var (_, sessionToken, _) = await RegisterPasswordIdentityAsync(client, email);
        var otherBootstrap = await BootstrapAsync(Guid.NewGuid().ToString("N"));
        using var otherClient = api.CreateClient();
        otherClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(otherBootstrap.IssuedCredentials).Token);

        var response = await otherClient.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                currentPassword = "password-123",
                newPassword = "rejected-password-456",
            });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        Assert.True(await IsSessionActiveAsync(sessionToken));
        var originalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, originalLogin.StatusCode);
        var rejectedLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "rejected-password-456" });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedLogin.StatusCode);
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("expired")]
    public async Task ChangePassword_RevokedOrExpiredSessionCannotChangeCredential(
        string sessionState)
    {
        var email = $"password-inactive-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, _) = await RegisterPasswordIdentityAsync(client, email);
        if (sessionState == "revoked")
        {
            var revoke = await client.PostAsJsonAsync(
                "/v1/auth/session/revoke",
                new { sessionToken });
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        }
        else if (sessionState == "expired")
        {
            await using var expirationScope = api.Services.CreateAsyncScope();
            var dbContext = expirationScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            var createdAt = await dbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .Select(session => session.CreatedAt)
                .SingleAsync();
            await dbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    session => session.ExpiresAt,
                    createdAt.Add(TimeSpan.FromMilliseconds(1))));
        }
        else
        {
            throw new ArgumentOutOfRangeException(
                nameof(sessionState),
                sessionState,
                null);
        }

        var response = await client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                currentPassword = "password-123",
                newPassword = "rejected-password-456",
            });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        var originalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, originalLogin.StatusCode);
        var rejectedLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "rejected-password-456" });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedLogin.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_RegistrationSessionCannotChangeCredential()
    {
        var bootstrap = await BootstrapAsync(
            Guid.NewGuid().ToString("N"),
            TestAccessPolicies.Create(phoneRequired: true));
        using var registrationClient = api.CreateClient();
        registrationClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(bootstrap.IssuedCredentials).Token);
        var email = $"password-registration-{Guid.NewGuid():N}@example.test";
        var (_, sessionToken, sessionPurpose) =
            await RegisterPasswordIdentityAsync(registrationClient, email);
        Assert.Equal("registration", sessionPurpose);

        var response = await registrationClient.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                currentPassword = "password-123",
                newPassword = "rejected-password-456",
            });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "session-purpose-invalid",
                body.RootElement.GetProperty("error").GetString());
        }
        var originalLogin = await registrationClient.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, originalLogin.StatusCode);
        var rejectedLogin = await registrationClient.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "rejected-password-456" });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedLogin.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_DisabledPasswordAuthenticatorCannotBeAddedToSocialIdentity()
    {
        var bootstrap = await BootstrapAsync(
            Guid.NewGuid().ToString("N"),
            TestAccessPolicies.Create(
                phoneEnabled: false,
                passwordEnabled: false,
                googleEnabled: true));
        using var socialClient = api.CreateClient();
        socialClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(bootstrap.IssuedCredentials).Token);
        var email = $"password-disabled-{Guid.NewGuid():N}@example.test";
        var subject = $"password-disabled-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(email, subject, "Password Disabled User");
        var socialLogin = await socialClient.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        var sessionToken = await ReadSessionTokenAsync(socialLogin);
        using var socialBody = JsonDocument.Parse(
            await socialLogin.Content.ReadAsStringAsync());
        var identityId = socialBody.RootElement.GetProperty("identityId").GetGuid();

        var response = await socialClient.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                newPassword = "rejected-password-456",
            });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "authenticator-disabled",
                body.RootElement.GetProperty("error").GetString());
        }
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await dbContext.PasswordCredentials.AsNoTracking().AnyAsync(
                credential => credential.IdentityId == identityId));
        }
        var providerLogin = await socialClient.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        Assert.Equal(HttpStatusCode.OK, providerLogin.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_ConcurrentReplacementsAllowOnlyOneWinner()
    {
        var email = $"password-concurrent-{Guid.NewGuid():N}@example.test";
        var (_, firstToken, _) = await RegisterPasswordIdentityAsync(client, email);
        var secondLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        var secondToken = await ReadSessionTokenAsync(secondLogin);

        var responses = await RacePasswordChangesAsync(
            (firstToken, "password-123", "first-concurrent-password"),
            (secondToken, "password-123", "second-concurrent-password"));

        var successfulIndex = Array.FindIndex(
            responses,
            response => response.StatusCode == HttpStatusCode.OK);
        Assert.NotEqual(-1, successfulIndex);
        var conflictedIndex = 1 - successfulIndex;
        Assert.Equal(HttpStatusCode.Conflict, responses[conflictedIndex].StatusCode);
        using (var body = JsonDocument.Parse(
            await responses[conflictedIndex].Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "password-change-conflict",
                body.RootElement.GetProperty("error").GetString());
        }

        var sessionTokens = new[] { firstToken, secondToken };
        Assert.True(await IsSessionActiveAsync(sessionTokens[successfulIndex]));
        Assert.False(await IsSessionActiveAsync(sessionTokens[conflictedIndex]));
        var oldPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldPassword.StatusCode);

        var newPasswords = new[]
        {
            "first-concurrent-password",
            "second-concurrent-password",
        };
        var successfulPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = newPasswords[successfulIndex] });
        Assert.Equal(HttpStatusCode.OK, successfulPassword.StatusCode);
        var rejectedPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = newPasswords[conflictedIndex] });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedPassword.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_ConcurrentFirstPasswordsAllowOnlyOneWinner()
    {
        var email = $"password-concurrent-social-{Guid.NewGuid():N}@example.test";
        var subject = $"password-concurrent-social-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(email, subject, "Concurrent Password User");
        var firstLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        var firstToken = await ReadSessionTokenAsync(firstLogin);
        using var firstBody = JsonDocument.Parse(
            await firstLogin.Content.ReadAsStringAsync());
        var identityId = firstBody.RootElement.GetProperty("identityId").GetGuid();
        var secondLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        var secondToken = await ReadSessionTokenAsync(secondLogin);

        var responses = await RacePasswordChangesAsync(
            (firstToken, null, "first-social-password"),
            (secondToken, null, "second-social-password"));

        var successfulIndex = Array.FindIndex(
            responses,
            response => response.StatusCode == HttpStatusCode.OK);
        Assert.NotEqual(-1, successfulIndex);
        var conflictedIndex = 1 - successfulIndex;
        Assert.Equal(HttpStatusCode.Conflict, responses[conflictedIndex].StatusCode);
        using (var body = JsonDocument.Parse(
            await responses[conflictedIndex].Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "password-change-conflict",
                body.RootElement.GetProperty("error").GetString());
        }

        var newPasswords = new[] { "first-social-password", "second-social-password" };
        var successfulPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = newPasswords[successfulIndex] });
        Assert.Equal(HttpStatusCode.OK, successfulPassword.StatusCode);
        using (var body = JsonDocument.Parse(
            await successfulPassword.Content.ReadAsStringAsync()))
        {
            Assert.Equal(identityId, body.RootElement.GetProperty("identityId").GetGuid());
            Assert.True(body.RootElement.GetProperty("hasGoogle").GetBoolean());
        }
        var rejectedPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = newPasswords[conflictedIndex] });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedPassword.StatusCode);
        var providerLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        Assert.Equal(HttpStatusCode.OK, providerLogin.StatusCode);
    }

    [Fact]
    public async Task SocialManagement_LinksAndUnlinksWithoutChangingThePrimaryEmail()
    {
        var email = $"social-management-{Guid.NewGuid():N}@example.test";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        var sessionToken = await ReadSessionTokenAsync(registration);
        api.GoogleValidator.Assertion = new(
            $"google-{Guid.NewGuid():N}@example.test",
            $"google-subject-{Guid.NewGuid():N}",
            "Google User");
        api.AppleValidator.Assertion = new(
            $"apple-{Guid.NewGuid():N}@example.test",
            $"apple-subject-{Guid.NewGuid():N}",
            null);

        var google = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });
        Assert.Equal(HttpStatusCode.OK, google.StatusCode);
        using (var body = JsonDocument.Parse(await google.Content.ReadAsStringAsync()))
        {
            Assert.Equal(email, body.RootElement.GetProperty("email").GetString());
            Assert.True(body.RootElement.GetProperty("hasGoogle").GetBoolean());
            Assert.Equal(
                api.GoogleValidator.Assertion.Email.ToLowerInvariant(),
                body.RootElement.GetProperty("googleEmail").GetString());
        }

        var apple = await client.PostAsJsonAsync(
            "/v1/account/social/apple/link",
            new { sessionToken, identityToken = "apple-token" });
        Assert.Equal(HttpStatusCode.OK, apple.StatusCode);
        using (var body = JsonDocument.Parse(await apple.Content.ReadAsStringAsync()))
        {
            Assert.True(body.RootElement.GetProperty("hasGoogle").GetBoolean());
            Assert.True(body.RootElement.GetProperty("hasApple").GetBoolean());
        }

        var unlinkGoogle = await client.PostAsJsonAsync(
            "/v1/account/social/google/unlink",
            new { sessionToken });
        Assert.Equal(HttpStatusCode.OK, unlinkGoogle.StatusCode);
        using (var body = JsonDocument.Parse(await unlinkGoogle.Content.ReadAsStringAsync()))
        {
            Assert.False(body.RootElement.GetProperty("hasGoogle").GetBoolean());
            Assert.True(body.RootElement.GetProperty("hasApple").GetBoolean());
            Assert.True(body.RootElement.GetProperty("hasPassword").GetBoolean());
        }
    }

    [Theory]
    [InlineData(null, HttpStatusCode.BadRequest, "missing-token")]
    [InlineData("invalid", HttpStatusCode.Unauthorized, "invalid-token")]
    public async Task SocialManagement_RejectsMissingOrInvalidGoogleAccessTokenWithoutLinking(
        string? accessToken,
        HttpStatusCode expectedStatus,
        string expectedError)
    {
        var email = $"social-access-error-{Guid.NewGuid():N}@example.test";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        var sessionToken = await ReadSessionTokenAsync(registration);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement.GetProperty("identityId").GetGuid();

        var response = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, accessToken });

        Assert.Equal(expectedStatus, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(expectedError, body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == identityId));
    }

    [Fact]
    public async Task SocialManagement_AccessTokenLinksGoogleCredential()
    {
        var primaryEmail = $"social-access-link-{Guid.NewGuid():N}@example.test";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = primaryEmail, password = "password-123" });
        var sessionToken = await ReadSessionTokenAsync(registration);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement.GetProperty("identityId").GetGuid();
        var providerEmail = $"google-access-link-{Guid.NewGuid():N}@example.test";
        var subject = $"google-access-link-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(providerEmail, subject, "Google Access User");

        var linked = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, accessToken = "google-access-token" });

        Assert.Equal(HttpStatusCode.OK, linked.StatusCode);
        using var body = JsonDocument.Parse(await linked.Content.ReadAsStringAsync());
        Assert.Equal(primaryEmail, body.RootElement.GetProperty("email").GetString());
        Assert.True(body.RootElement.GetProperty("hasPassword").GetBoolean());
        Assert.True(body.RootElement.GetProperty("hasGoogle").GetBoolean());
        Assert.Equal(providerEmail, body.RootElement.GetProperty("googleEmail").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var credential = await dbContext.SocialCredentials
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(SocialProvider.Google, credential.Provider);
        Assert.Equal(subject, credential.Subject);
        Assert.Equal(providerEmail, credential.Email);
    }

    [Theory]
    [InlineData(null, HttpStatusCode.BadRequest, "missing-token")]
    [InlineData("invalid", HttpStatusCode.Unauthorized, "invalid-token")]
    public async Task SocialManagement_RejectsMissingOrInvalidAppleIdentityTokenWithoutLinking(
        string? identityToken,
        HttpStatusCode expectedStatus,
        string expectedError)
    {
        var (identityId, sessionToken, _) = await RegisterPasswordIdentityAsync(
            client,
            $"apple-link-error-{Guid.NewGuid():N}@example.test");

        var response = await client.PostAsJsonAsync(
            "/v1/account/social/apple/link",
            new { sessionToken, identityToken });

        Assert.Equal(expectedStatus, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(expectedError, body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == identityId));
    }

    [Theory]
    [InlineData("google")]
    [InlineData("apple")]
    public async Task SocialManagement_DisabledProviderCannotBeLinked(string provider)
    {
        var bootstrap = await BootstrapAsync(
            Guid.NewGuid().ToString("N"),
            TestAccessPolicies.Create(
                phoneEnabled: false,
                googleEnabled: false,
                appleEnabled: false));
        using var disabledProviderClient = api.CreateClient();
        disabledProviderClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(bootstrap.IssuedCredentials).Token);
        var (identityId, sessionToken, _) = await RegisterPasswordIdentityAsync(
            disabledProviderClient,
            $"disabled-{provider}-{Guid.NewGuid():N}@example.test");

        using var response = provider switch
        {
            SocialProvider.Google => await disabledProviderClient.PostAsJsonAsync(
                "/v1/account/social/google/link",
                new { sessionToken, idToken = "google-token" }),
            SocialProvider.Apple => await disabledProviderClient.PostAsJsonAsync(
                "/v1/account/social/apple/link",
                new { sessionToken, identityToken = "apple-token" }),
            _ => throw new ArgumentOutOfRangeException(nameof(provider), provider, null),
        };

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "authenticator-disabled",
            body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == identityId));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("malformed")]
    [InlineData("unknown")]
    public async Task SocialManagement_RejectsMissingMalformedOrUnknownSessionBeforeLinking(
        string sessionKind)
    {
        var subject = $"unauthorized-link-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"unauthorized-link-{Guid.NewGuid():N}@example.test",
            subject,
            "Unauthorized Link");
        var sessionToken = sessionKind switch
        {
            "missing" => null,
            "malformed" => "invalid",
            "unknown" => "bgs_" + new string('A', 43),
            _ => throw new ArgumentOutOfRangeException(nameof(sessionKind), sessionKind, null),
        };

        var response = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.Subject == subject));
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("expired")]
    public async Task SocialManagement_RevokedOrExpiredSessionCannotLinkGoogleCredential(
        string sessionState)
    {
        var (identityId, sessionToken, _) = await RegisterPasswordIdentityAsync(
            client,
            $"inactive-link-{Guid.NewGuid():N}@example.test");
        if (sessionState == "revoked")
        {
            var revoke = await client.PostAsJsonAsync(
                "/v1/auth/session/revoke",
                new { sessionToken });
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        }
        else if (sessionState == "expired")
        {
            await using var expirationScope = api.Services.CreateAsyncScope();
            var expirationDbContext = expirationScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            var createdAt = await expirationDbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .Select(session => session.CreatedAt)
                .SingleAsync();
            await expirationDbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    session => session.ExpiresAt,
                    createdAt.Add(TimeSpan.FromMilliseconds(1))));
        }
        else
        {
            throw new ArgumentOutOfRangeException(
                nameof(sessionState),
                sessionState,
                null);
        }

        var subject = $"inactive-link-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"inactive-link-google-{Guid.NewGuid():N}@example.test",
            subject,
            "Inactive Link");
        var response = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());

        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await verification.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == identityId));
    }

    [Fact]
    public async Task SocialManagement_RegistrationSessionCannotLinkGoogleCredential()
    {
        var bootstrap = await BootstrapAsync(
            Guid.NewGuid().ToString("N"),
            TestAccessPolicies.Create(
                phoneRequired: true,
                googleEnabled: true));
        using var registrationClient = api.CreateClient();
        registrationClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(bootstrap.IssuedCredentials).Token);
        var (identityId, sessionToken, sessionPurpose) =
            await RegisterPasswordIdentityAsync(
                registrationClient,
                $"registration-link-{Guid.NewGuid():N}@example.test");
        Assert.Equal("registration", sessionPurpose);
        var subject = $"registration-link-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"registration-link-google-{Guid.NewGuid():N}@example.test",
            subject,
            "Registration Link");

        var response = await registrationClient.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "session-purpose-invalid",
            body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == identityId));
    }

    [Fact]
    public async Task SocialManagement_RevokedSessionCannotUnlinkGoogleCredential()
    {
        var (identityId, sessionToken, _) = await RegisterPasswordIdentityAsync(
            client,
            $"revoked-unlink-{Guid.NewGuid():N}@example.test");
        var subject = $"revoked-unlink-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"revoked-unlink-google-{Guid.NewGuid():N}@example.test",
            subject,
            "Revoked Unlink");
        var linked = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });
        linked.EnsureSuccessStatusCode();
        var revoke = await client.PostAsJsonAsync(
            "/v1/auth/session/revoke",
            new { sessionToken });
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        var response = await client.PostAsJsonAsync(
            "/v1/account/social/google/unlink",
            new { sessionToken });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.True(await dbContext.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == identityId
                && credential.Provider == SocialProvider.Google
                && credential.Subject == subject));
    }

    [Fact]
    public async Task SocialManagement_ReturnsProviderNotLinkedWithoutChangingAuthenticators()
    {
        var (identityId, sessionToken, _) = await RegisterPasswordIdentityAsync(
            client,
            $"provider-not-linked-{Guid.NewGuid():N}@example.test");

        var response = await client.PostAsJsonAsync(
            "/v1/account/social/google/unlink",
            new { sessionToken });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("provider-not-linked", body.RootElement.GetProperty("error").GetString());
        Assert.True(await IsSessionActiveAsync(sessionToken));

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.True(await dbContext.PasswordCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == identityId));
        Assert.False(await dbContext.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == identityId));
    }

    [Fact]
    public async Task SocialManagement_DoesNotRemoveTheLastAuthenticator()
    {
        api.GoogleValidator.Assertion = new(
            $"only-google-{Guid.NewGuid():N}@example.test",
            $"only-google-subject-{Guid.NewGuid():N}",
            "Google User");
        var login = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        var sessionToken = await ReadSessionTokenAsync(login);

        var unlink = await client.PostAsJsonAsync(
            "/v1/account/social/google/unlink",
            new { sessionToken });

        Assert.Equal(HttpStatusCode.Conflict, unlink.StatusCode);
        using var body = JsonDocument.Parse(await unlink.Content.ReadAsStringAsync());
        Assert.Equal("last-authenticator", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task SocialManagement_ReplayingSameCredentialIsIdempotentAndRefreshesProviderEmail()
    {
        var primaryEmail = $"social-replay-{Guid.NewGuid():N}@example.test";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = primaryEmail, password = "password-123" });
        var sessionToken = await ReadSessionTokenAsync(registration);
        var subject = $"google-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"old-google-{Guid.NewGuid():N}@example.test",
            subject,
            "Google User");

        var first = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });
        first.EnsureSuccessStatusCode();

        var updatedProviderEmail = $"new-google-{Guid.NewGuid():N}@example.test";
        api.GoogleValidator.Assertion = new(
            updatedProviderEmail.ToUpperInvariant(),
            subject,
            "Google User");
        var replay = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });

        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        using var body = JsonDocument.Parse(await replay.Content.ReadAsStringAsync());
        Assert.Equal(primaryEmail, body.RootElement.GetProperty("email").GetString());
        Assert.Equal(
            updatedProviderEmail,
            body.RootElement.GetProperty("googleEmail").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var credential = await dbContext.SocialCredentials.AsNoTracking().SingleAsync(
            item => item.Provider == SocialProvider.Google && item.Subject == subject);
        Assert.Equal(updatedProviderEmail, credential.Email);
    }

    [Fact]
    public async Task SocialManagement_DoesNotReplaceLinkedProviderWithDifferentSubject()
    {
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"provider-replacement-{Guid.NewGuid():N}@example.test",
                password = "password-123",
            });
        var sessionToken = await ReadSessionTokenAsync(registration);
        var originalSubject = $"original-google-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"google-{Guid.NewGuid():N}@example.test",
            originalSubject,
            "Google User");
        var linked = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });
        linked.EnsureSuccessStatusCode();

        api.GoogleValidator.Assertion = new(
            $"replacement-{Guid.NewGuid():N}@example.test",
            $"replacement-google-subject-{Guid.NewGuid():N}",
            "Replacement User");
        var replacement = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken, idToken = "google-token" });

        Assert.Equal(HttpStatusCode.Conflict, replacement.StatusCode);
        using var body = JsonDocument.Parse(await replacement.Content.ReadAsStringAsync());
        Assert.Equal(
            "provider-already-linked",
            body.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var credential = await dbContext.SocialCredentials.AsNoTracking().SingleAsync(
            item => item.Provider == SocialProvider.Google
                && item.Subject == originalSubject);
        Assert.Equal(originalSubject, credential.Subject);
    }

    [Fact]
    public async Task SocialManagement_DoesNotLinkCredentialOwnedByAnotherIdentity()
    {
        var sharedSubject = $"owned-google-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"owner-{Guid.NewGuid():N}@example.test",
            sharedSubject,
            "Credential Owner");
        var ownerLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        ownerLogin.EnsureSuccessStatusCode();
        using var ownerBody = JsonDocument.Parse(
            await ownerLogin.Content.ReadAsStringAsync());
        var ownerIdentityId = ownerBody.RootElement.GetProperty("identityId").GetGuid();

        var claimantRegistration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"claimant-{Guid.NewGuid():N}@example.test",
                password = "password-123",
            });
        var claimantToken = await ReadSessionTokenAsync(claimantRegistration);
        using var claimantBody = JsonDocument.Parse(
            await claimantRegistration.Content.ReadAsStringAsync());
        var claimantIdentityId = claimantBody.RootElement.GetProperty("identityId").GetGuid();

        var link = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken = claimantToken, idToken = "google-token" });

        Assert.Equal(HttpStatusCode.Conflict, link.StatusCode);
        using var error = JsonDocument.Parse(await link.Content.ReadAsStringAsync());
        Assert.Equal("email-taken", error.RootElement.GetProperty("error").GetString());
        Assert.Equal("email", error.RootElement.GetProperty("field").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var credential = await dbContext.SocialCredentials.AsNoTracking().SingleAsync(
            item => item.Provider == SocialProvider.Google
                && item.Subject == sharedSubject);
        Assert.Equal(ownerIdentityId, credential.IdentityId);
        Assert.NotEqual(claimantIdentityId, credential.IdentityId);
    }

    [Fact]
    public async Task SocialManagement_ConcurrentClaimsAllowOnlyOneCredentialOwner()
    {
        var firstRegistration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"first-claimant-{Guid.NewGuid():N}@example.test",
                password = "password-123",
            });
        var firstToken = await ReadSessionTokenAsync(firstRegistration);
        using var firstBody = JsonDocument.Parse(
            await firstRegistration.Content.ReadAsStringAsync());
        var firstIdentityId = firstBody.RootElement.GetProperty("identityId").GetGuid();

        var secondRegistration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"second-claimant-{Guid.NewGuid():N}@example.test",
                password = "password-123",
            });
        var secondToken = await ReadSessionTokenAsync(secondRegistration);
        using var secondBody = JsonDocument.Parse(
            await secondRegistration.Content.ReadAsStringAsync());
        var secondIdentityId = secondBody.RootElement.GetProperty("identityId").GetGuid();

        var sharedSubject = $"concurrent-google-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"concurrent-owner-{Guid.NewGuid():N}@example.test",
            sharedSubject,
            "Concurrent Owner");

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var lockConnection = new NpgsqlConnection(database.ConnectionString);
        await lockConnection.OpenAsync(timeout.Token);
        await using var lockTransaction = await lockConnection.BeginTransactionAsync(
            cancellationToken: timeout.Token);
        await using (var lockCommand = lockConnection.CreateCommand())
        {
            lockCommand.Transaction = lockTransaction;
            lockCommand.CommandText = "LOCK TABLE social_credentials IN SHARE MODE;";
            await lockCommand.ExecuteNonQueryAsync(timeout.Token);
        }

        var firstClaim = client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken = firstToken, idToken = "google-token" },
            timeout.Token);
        var secondClaim = client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken = secondToken, idToken = "google-token" },
            timeout.Token);
        await WaitForBlockedSocialCredentialInsertsAsync(
            expectedCount: 2,
            cancellationToken: timeout.Token);
        await lockTransaction.CommitAsync(timeout.Token);
        var responses = await Task.WhenAll(firstClaim, secondClaim);

        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
        var rejected = Assert.Single(
            responses,
            response => response.StatusCode == HttpStatusCode.Conflict);
        using var rejectedBody = JsonDocument.Parse(
            await rejected.Content.ReadAsStringAsync());
        Assert.Equal(
            "email-taken",
            rejectedBody.RootElement.GetProperty("error").GetString());
        Assert.Equal(
            "email",
            rejectedBody.RootElement.GetProperty("field").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var credential = await dbContext.SocialCredentials.AsNoTracking().SingleAsync(
            item => item.Provider == SocialProvider.Google
                && item.Subject == sharedSubject);
        Assert.Contains(
            credential.IdentityId,
            new[] { firstIdentityId, secondIdentityId });
    }

    [Fact]
    public async Task SocialManagement_ConcurrentUnlinksKeepOneAuthenticator()
    {
        api.GoogleValidator.Assertion = new(
            $"concurrent-google-{Guid.NewGuid():N}@example.test",
            $"concurrent-google-subject-{Guid.NewGuid():N}",
            "Concurrent User");
        var login = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        var sessionToken = await ReadSessionTokenAsync(login);
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        var identityId = loginBody.RootElement.GetProperty("identityId").GetGuid();

        api.AppleValidator.Assertion = new(
            $"concurrent-apple-{Guid.NewGuid():N}@example.test",
            $"concurrent-apple-subject-{Guid.NewGuid():N}",
            null);
        var linked = await client.PostAsJsonAsync(
            "/v1/account/social/apple/link",
            new { sessionToken, identityToken = "apple-token" });
        linked.EnsureSuccessStatusCode();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var responses = await Task.WhenAll(
            client.PostAsJsonAsync(
                "/v1/account/social/google/unlink",
                new { sessionToken },
                timeout.Token),
            client.PostAsJsonAsync(
                "/v1/account/social/apple/unlink",
                new { sessionToken },
                timeout.Token));

        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
        var rejected = Assert.Single(
            responses,
            response => response.StatusCode == HttpStatusCode.Conflict);
        using var rejectedBody = JsonDocument.Parse(
            await rejected.Content.ReadAsStringAsync());
        Assert.Equal(
            "last-authenticator",
            rejectedBody.RootElement.GetProperty("error").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(
            1,
            await dbContext.SocialCredentials.AsNoTracking().CountAsync(
                credential => credential.IdentityId == identityId));
    }

    [Fact]
    public async Task SocialAuthentication_AllowsSameProviderSubjectInDifferentRealms()
    {
        var sharedSubject = $"cross-realm-google-subject-{Guid.NewGuid():N}";
        api.GoogleValidator.Assertion = new(
            $"cross-realm-{Guid.NewGuid():N}@example.test",
            sharedSubject,
            "Cross Realm User");

        var suffix = Guid.NewGuid().ToString("N");
        var bootstrap = await BootstrapAsync(
            CreateRealmIsolationBootstrapCommand(suffix));
        var appPath = $"social-realm-isolation-{suffix}/baybo-{suffix}";
        using var firstRealmClient = api.CreateClient();
        firstRealmClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                FindCredential(
                    bootstrap,
                    $"{appPath}/first/integration-clients/api"));
        using var secondRealmClient = api.CreateClient();
        secondRealmClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                FindCredential(
                    bootstrap,
                    $"{appPath}/second/integration-clients/api"));

        var primaryLogin = await firstRealmClient.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        primaryLogin.EnsureSuccessStatusCode();
        using var primaryBody = JsonDocument.Parse(
            await primaryLogin.Content.ReadAsStringAsync());
        var primaryIdentityId = primaryBody.RootElement.GetProperty("identityId").GetGuid();
        Assert.True(primaryBody.RootElement.GetProperty("isNew").GetBoolean());

        var otherLogin = await secondRealmClient.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        otherLogin.EnsureSuccessStatusCode();
        using var otherBody = JsonDocument.Parse(
            await otherLogin.Content.ReadAsStringAsync());
        var otherIdentityId = otherBody.RootElement.GetProperty("identityId").GetGuid();
        Assert.True(otherBody.RootElement.GetProperty("isNew").GetBoolean());
        Assert.NotEqual(primaryIdentityId, otherIdentityId);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var credentials = await dbContext.SocialCredentials
            .AsNoTracking()
            .Where(item => item.Provider == SocialProvider.Google
                && item.Subject == sharedSubject)
            .OrderBy(item => item.IdentityId)
            .ToListAsync();

        Assert.Equal(2, credentials.Count);
        Assert.NotEqual(credentials[0].RealmId, credentials[1].RealmId);
        Assert.Equal(
            new[] { primaryIdentityId, otherIdentityId }.Order(),
            credentials.Select(item => item.IdentityId));
    }

    [Fact]
    public async Task ChangeEmail_NormalizesAddressAndMovesPasswordLogin()
    {
        var originalEmail = $"email-change-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, _) =
            await RegisterPasswordIdentityAsync(client, originalEmail);
        var expectedEmail = $"changed-{Guid.NewGuid():N}@example.invalid";

        var response = await client.PutAsJsonAsync(
            "/v1/account/email",
            new
            {
                sessionToken,
                email = $"  {expectedEmail.ToUpperInvariant()}  ",
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(identityId, body.RootElement.GetProperty("identityId").GetGuid());
            Assert.Equal(expectedEmail, body.RootElement.GetProperty("email").GetString());
            Assert.Equal("product", body.RootElement.GetProperty("sessionPurpose").GetString());
        }
        Assert.True(await IsSessionActiveAsync(sessionToken));

        using var originalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = originalEmail, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, originalLogin.StatusCode);
        using var changedLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = expectedEmail, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, changedLogin.StatusCode);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var identifier = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(
            item => item.IdentityId == identityId
                && item.Scheme == IdentifierScheme.Email);
        Assert.Equal(expectedEmail, identifier.NormalizedValue);
        Assert.Null(identifier.VerifiedAt);
        Assert.Null(identifier.VerificationMethod);
    }

    [Fact]
    public async Task ChangeEmail_RepeatingCurrentAddressIsIdempotent()
    {
        var email = $"email-repeat-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, _) =
            await RegisterPasswordIdentityAsync(client, email);

        var response = await client.PutAsJsonAsync(
            "/v1/account/email",
            new
            {
                sessionToken,
                email = $"  {email.ToUpperInvariant()}  ",
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(identityId, body.RootElement.GetProperty("identityId").GetGuid());
        Assert.Equal(email, body.RootElement.GetProperty("email").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Single(await dbContext.IdentityIdentifiers.AsNoTracking()
            .Where(identifier => identifier.IdentityId == identityId
                && identifier.Scheme == IdentifierScheme.Email)
            .ToArrayAsync());
    }

    [Fact]
    public async Task ChangeEmail_OnSocialIdentityPreservesProviderLogin()
    {
        var providerEmail = $"email-social-{Guid.NewGuid():N}@example.test";
        api.GoogleValidator.Assertion = new(
            providerEmail,
            $"email-social-subject-{Guid.NewGuid():N}",
            "Email Social User");
        using var socialLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        socialLogin.EnsureSuccessStatusCode();
        using var socialLoginBody = JsonDocument.Parse(
            await socialLogin.Content.ReadAsStringAsync());
        var identityId = socialLoginBody.RootElement.GetProperty("identityId").GetGuid();
        var sessionToken = socialLoginBody.RootElement.GetProperty("sessionToken").GetString();
        var changedEmail = $"changed-social-{Guid.NewGuid():N}@example.invalid";

        await using (var beforeScope = api.Services.CreateAsyncScope())
        {
            var db = beforeScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identifier = await db.IdentityIdentifiers.AsNoTracking().SingleAsync(item =>
                item.IdentityId == identityId && item.Scheme == IdentifierScheme.Email);
            Assert.NotNull(identifier.VerifiedAt);
            Assert.NotNull(identifier.VerificationMethod);
        }

        using var response = await client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken, email = changedEmail });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(changedEmail, body.RootElement.GetProperty("email").GetString());
            Assert.False(body.RootElement.GetProperty("hasPassword").GetBoolean());
            Assert.True(body.RootElement.GetProperty("hasGoogle").GetBoolean());
            Assert.Equal(
                providerEmail,
                body.RootElement.GetProperty("googleEmail").GetString());
        }

        using var providerLogin = await client.PostAsJsonAsync(
            "/v1/auth/google",
            new { idToken = "google-token" });
        Assert.Equal(HttpStatusCode.OK, providerLogin.StatusCode);
        using var providerLoginBody = JsonDocument.Parse(
            await providerLogin.Content.ReadAsStringAsync());
        Assert.Equal(
            identityId,
            providerLoginBody.RootElement.GetProperty("identityId").GetGuid());
        Assert.Equal(
            changedEmail,
            providerLoginBody.RootElement.GetProperty("email").GetString());

        await using var afterScope = api.Services.CreateAsyncScope();
        var verification = afterScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var changedIdentifier = await verification.IdentityIdentifiers.AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId && item.Scheme == IdentifierScheme.Email);
        Assert.Equal(changedEmail, changedIdentifier.NormalizedValue);
        Assert.Null(changedIdentifier.VerifiedAt);
        Assert.Null(changedIdentifier.VerificationMethod);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-email")]
    public async Task ChangeEmail_InvalidAddressLeavesCurrentAddressUsable(string? invalidEmail)
    {
        var email = $"email-invalid-{Guid.NewGuid():N}@example.test";
        var (_, sessionToken, _) = await RegisterPasswordIdentityAsync(client, email);

        var response = await client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken, email = invalidEmail });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("invalid-email", body.RootElement.GetProperty("error").GetString());
            Assert.Equal("email", body.RootElement.GetProperty("field").GetString());
        }
        using var login = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task ChangeEmail_AddressOwnedByAnotherIdentityReturnsConflict()
    {
        var currentEmail = $"email-owner-{Guid.NewGuid():N}@example.test";
        var (_, sessionToken, _) =
            await RegisterPasswordIdentityAsync(client, currentEmail);
        var occupiedEmail = $"email-occupied-{Guid.NewGuid():N}@example.test";
        await RegisterPasswordIdentityAsync(client, occupiedEmail);

        var response = await client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken, email = occupiedEmail.ToUpperInvariant() });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("email-taken", body.RootElement.GetProperty("error").GetString());
            Assert.Equal("email", body.RootElement.GetProperty("field").GetString());
        }
        using var currentLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = currentEmail, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, currentLogin.StatusCode);
        using var occupiedLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = occupiedEmail, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, occupiedLogin.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("bgs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task ChangeEmail_MissingMalformedOrUnknownSessionCannotChangeAddress(
        string? sessionToken)
    {
        var email = $"email-session-{Guid.NewGuid():N}@example.test";
        await RegisterPasswordIdentityAsync(client, email);
        var rejectedEmail = $"rejected-{Guid.NewGuid():N}@example.invalid";

        var response = await client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken, email = rejectedEmail });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        using var originalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, originalLogin.StatusCode);
        using var rejectedLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = rejectedEmail, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedLogin.StatusCode);
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("expired")]
    public async Task ChangeEmail_RevokedOrExpiredSessionCannotChangeAddress(
        string sessionState)
    {
        var email = $"email-inactive-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, _) =
            await RegisterPasswordIdentityAsync(client, email);
        if (sessionState == "revoked")
        {
            using var revoke = await client.PostAsJsonAsync(
                "/v1/auth/session/revoke",
                new { sessionToken });
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        }
        else if (sessionState == "expired")
        {
            await using var expirationScope = api.Services.CreateAsyncScope();
            var dbContext = expirationScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            var createdAt = await dbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .Select(session => session.CreatedAt)
                .SingleAsync();
            await dbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    session => session.ExpiresAt,
                    createdAt.Add(TimeSpan.FromMilliseconds(1))));
        }
        else
        {
            throw new ArgumentOutOfRangeException(
                nameof(sessionState),
                sessionState,
                null);
        }

        var rejectedEmail = $"rejected-inactive-{Guid.NewGuid():N}@example.invalid";
        var response = await client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken, email = rejectedEmail });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        using var login = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task ChangeEmail_RegistrationSessionCannotChangeAddress()
    {
        var bootstrap = await BootstrapAsync(
            Guid.NewGuid().ToString("N"),
            TestAccessPolicies.Create(phoneRequired: true));
        using var registrationClient = api.CreateClient();
        registrationClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(bootstrap.IssuedCredentials).Token);
        var email = $"email-registration-{Guid.NewGuid():N}@example.test";
        var (_, sessionToken, sessionPurpose) =
            await RegisterPasswordIdentityAsync(registrationClient, email);
        Assert.Equal("registration", sessionPurpose);

        var response = await registrationClient.PutAsJsonAsync(
            "/v1/account/email",
            new
            {
                sessionToken,
                email = $"rejected-registration-{Guid.NewGuid():N}@example.invalid",
            });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "session-purpose-invalid",
                body.RootElement.GetProperty("error").GetString());
        }
        using var login = await registrationClient.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task ChangeEmail_SessionFromAnotherScopeCannotChangeAddress()
    {
        var email = $"email-scope-{Guid.NewGuid():N}@example.test";
        var (_, sessionToken, _) = await RegisterPasswordIdentityAsync(client, email);
        var otherBootstrap = await BootstrapAsync(Guid.NewGuid().ToString("N"));
        using var otherClient = api.CreateClient();
        otherClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(otherBootstrap.IssuedCredentials).Token);
        var rejectedEmail = $"rejected-scope-{Guid.NewGuid():N}@example.invalid";

        var response = await otherClient.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken, email = rejectedEmail });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        using var originalLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, originalLogin.StatusCode);
    }

    [Fact]
    public async Task ChangeEmail_InvalidatesPendingPasswordRecoveries()
    {
        var originalEmail = $"email-recovery-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, _) =
            await RegisterPasswordIdentityAsync(client, originalEmail);
        Guid resetTokenId;
        Guid phoneRecoveryChallengeId;
        await using (var seedScope = api.Services.CreateAsyncScope())
        {
            var dbContext = seedScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            var now = DateTimeOffset.UtcNow;
            var appEnvironmentId = await dbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .Select(session => session.AppEnvironmentId)
                .SingleAsync();
            resetTokenId = Guid.CreateVersion7(now);
            phoneRecoveryChallengeId = Guid.CreateVersion7(now);
            dbContext.PasswordResetTokens.Add(new PasswordResetToken(
                resetTokenId,
                identityId,
                appEnvironmentId,
                RandomNumberGenerator.GetBytes(
                    IdentityLimits.PasswordResetTokenHashLength),
                now,
                now.AddMinutes(30)));
            var challenge = new PhonePasswordResetChallenge(
                phoneRecoveryChallengeId,
                identityId,
                appEnvironmentId,
                "+5511999990002",
                RandomNumberGenerator.GetBytes(
                    IdentityLimits.PhonePasswordResetCodeHashLength),
                5,
                now,
                now.AddMinutes(10),
                now.AddMinutes(1));
            challenge.Activate("provider-reference");
            dbContext.PhonePasswordResetChallenges.Add(challenge);
            await dbContext.SaveChangesAsync();
        }

        var response = await client.PutAsJsonAsync(
            "/v1/account/email",
            new
            {
                sessionToken,
                email = $"changed-recovery-{Guid.NewGuid():N}@example.invalid",
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await using var scope = api.Services.CreateAsyncScope();
        var verification = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var resetToken = await verification.PasswordResetTokens.AsNoTracking()
            .SingleAsync(token => token.Id == resetTokenId);
        Assert.NotNull(resetToken.UsedAt);
        var phoneRecovery = await verification.PhonePasswordResetChallenges
            .AsNoTracking()
            .SingleAsync(challenge => challenge.Id == phoneRecoveryChallengeId);
        Assert.Equal(
            PhonePasswordResetChallengeStatus.Superseded,
            phoneRecovery.Status);
        Assert.NotNull(phoneRecovery.CompletedAt);
    }

    [Fact]
    public async Task ChangeEmail_ConcurrentClaimsLeaveExactlyOneOwner()
    {
        var firstEmail = $"email-race-first-{Guid.NewGuid():N}@example.test";
        var (firstIdentityId, firstToken, _) =
            await RegisterPasswordIdentityAsync(client, firstEmail);
        var secondEmail = $"email-race-second-{Guid.NewGuid():N}@example.test";
        var (secondIdentityId, secondToken, _) =
            await RegisterPasswordIdentityAsync(client, secondEmail);
        var claimedEmail = $"email-race-claim-{Guid.NewGuid():N}@example.invalid";

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var blocker = new NpgsqlConnection(database.ConnectionString);
        await blocker.OpenAsync(timeout.Token);
        await using var transaction = await blocker.BeginTransactionAsync(timeout.Token);
        await using (var command = blocker.CreateCommand())
        {
            command.Transaction = transaction;
            // Both requests must reach the write before either can claim the address.
            command.CommandText = "LOCK TABLE identity_identifiers IN SHARE MODE";
            await command.ExecuteNonQueryAsync(timeout.Token);
        }
        var firstChange = client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken = firstToken, email = claimedEmail }, timeout.Token);
        var secondChange = client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken = secondToken, email = claimedEmail }, timeout.Token);
        await WaitForBlockedEmailChangesAsync(timeout.Token);
        await transaction.CommitAsync(timeout.Token);
        var responses = await Task.WhenAll(firstChange, secondChange);

        var winner = Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
        using var winnerBody = JsonDocument.Parse(
            await winner.Content.ReadAsStringAsync());
        var winningIdentityId = winnerBody.RootElement.GetProperty("identityId").GetGuid();
        Assert.Contains(winningIdentityId, new[] { firstIdentityId, secondIdentityId });
        var conflict = Assert.Single(
            responses,
            response => response.StatusCode == HttpStatusCode.Conflict);
        using (var conflictBody = JsonDocument.Parse(
            await conflict.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "email-taken",
                conflictBody.RootElement.GetProperty("error").GetString());
        }

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var owner = await dbContext.IdentityIdentifiers.AsNoTracking()
            .Where(identifier => identifier.Scheme == IdentifierScheme.Email
                && identifier.NormalizedValue == claimedEmail)
            .Select(identifier => identifier.IdentityId)
            .SingleAsync();
        Assert.Equal(winningIdentityId, owner);

        var losingIdentityId = winningIdentityId == firstIdentityId ? secondIdentityId : firstIdentityId;
        var losingEmail = winningIdentityId == firstIdentityId ? secondEmail : firstEmail;
        var winningOriginalEmail = winningIdentityId == firstIdentityId ? firstEmail : secondEmail;
        var loser = await dbContext.IdentityIdentifiers.AsNoTracking().SingleAsync(identifier =>
            identifier.IdentityId == losingIdentityId && identifier.Scheme == IdentifierScheme.Email);
        Assert.Equal(losingEmail, loser.NormalizedValue);
        foreach (var (email, expectedId) in new[] { (claimedEmail, winningIdentityId), (losingEmail, losingIdentityId) })
        {
            using var login = await client.PostAsJsonAsync(
                "/v1/auth/login", new { email, password = "password-123" });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            using var body = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
            Assert.Equal(expectedId, body.RootElement.GetProperty("identityId").GetGuid());
        }
        using var oldLogin = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = winningOriginalEmail, password = "password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldLogin.StatusCode);
        Assert.True(await IsSessionActiveAsync(firstToken));
        Assert.True(await IsSessionActiveAsync(secondToken));
    }

    private async Task WaitForBlockedEmailChangesAsync(CancellationToken cancellationToken)
    {
        await using var observer = new NpgsqlConnection(database.ConnectionString);
        await observer.OpenAsync(cancellationToken);
        while (true)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT count(*) FROM pg_stat_activity
                WHERE datname = current_database()
                  AND wait_event_type = 'Lock'
                  AND query ILIKE 'UPDATE identity_identifiers%';
                """;
            if (Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken)) >= 2)
            {
                return;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken);
        }
    }

    [Theory]
    [InlineData("same", HttpStatusCode.OK)]
    [InlineData("invalid", HttpStatusCode.BadRequest)]
    [InlineData("taken", HttpStatusCode.Conflict)]
    public async Task ChangeEmail_UnchangedAddressPreservesPendingRecoveries(
        string change,
        HttpStatusCode expectedStatus)
    {
        var originalEmail = $"preserved-recovery-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, _) = await RegisterPasswordIdentityAsync(client, originalEmail);
        var requestedEmail = change switch
        {
            "same" => $"  {originalEmail.ToUpperInvariant()}  ",
            "invalid" => "not-an-email",
            _ => $"taken-recovery-{Guid.NewGuid():N}@example.test",
        };
        if (change == "taken")
        {
            await RegisterPasswordIdentityAsync(client, requestedEmail);
        }
        PasswordResetIssueResult issued;
        DateTimeOffset originalTokenExpiration;
        Guid phoneChallengeId;
        await using (var seedScope = api.Services.CreateAsyncScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var environmentId = await db.IdentitySessions.Where(item => item.IdentityId == identityId)
                .Select(item => item.AppEnvironmentId).SingleAsync();
            issued = await seedScope.ServiceProvider.GetRequiredService<PasswordResetService>()
                .IssueAsync(identityId, environmentId);
            Assert.True(issued.Succeeded);
            originalTokenExpiration = await db.PasswordResetTokens.AsNoTracking()
                .Where(item => item.Id == issued.TokenId).Select(item => item.ExpiresAt).SingleAsync();
            var now = DateTimeOffset.UtcNow;
            phoneChallengeId = Guid.CreateVersion7(now);
            var challenge = new PhonePasswordResetChallenge(
                phoneChallengeId, identityId, environmentId, "+5511999990002",
                RandomNumberGenerator.GetBytes(IdentityLimits.PhonePasswordResetCodeHashLength),
                5, now, now.AddMinutes(10), now.AddMinutes(1));
            challenge.Activate("provider-reference");
            db.PhonePasswordResetChallenges.Add(challenge);
            await db.SaveChangesAsync();
        }

        using var response = await client.PutAsJsonAsync(
            "/v1/account/email", new { sessionToken, email = requestedEmail });

        Assert.Equal(expectedStatus, response.StatusCode);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var token = await db.PasswordResetTokens.AsNoTracking().SingleAsync(item => item.Id == issued.TokenId);
            Assert.Null(token.UsedAt);
            Assert.Equal(originalTokenExpiration, token.ExpiresAt);
            var challenge = await db.PhonePasswordResetChallenges.AsNoTracking()
                .SingleAsync(item => item.Id == phoneChallengeId);
            Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
            Assert.Null(challenge.CompletedAt);
            var identifier = await db.IdentityIdentifiers.AsNoTracking().SingleAsync(item =>
                item.IdentityId == identityId && item.Scheme == IdentifierScheme.Email);
            Assert.Equal(originalEmail, identifier.NormalizedValue);
        }
        Assert.True(await IsSessionActiveAsync(sessionToken));
        using var reset = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset", new { token = issued.Token, newPassword = "recovered-password" });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
        using var login = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = originalEmail, password = "recovered-password" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.Equal(identityId, loginBody.RootElement.GetProperty("identityId").GetGuid());
    }

    [Fact]
    public async Task IdentityIdentifier_RejectsASecondIdentifierOfTheSameScheme()
    {
        var email = $"identifier-owner-{Guid.NewGuid():N}@example.test";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        registration.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await registration.Content.ReadAsStringAsync());
        var identityId = body.RootElement.GetProperty("identityId").GetGuid();

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var realmId = await dbContext.Identities.AsNoTracking()
            .Where(identity => identity.Id == identityId)
            .Select(identity => identity.RealmId)
            .SingleAsync();
        dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
            Guid.CreateVersion7(),
            identityId,
            realmId,
            IdentifierScheme.Email,
            $"second-{Guid.NewGuid():N}@example.test",
            DateTimeOffset.UtcNow));

        await Assert.ThrowsAsync<DbUpdateException>(
            () => dbContext.SaveChangesAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("bgs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task DeleteAccount_MissingMalformedOrUnknownSessionCannotDeleteIdentity(
        string? sessionToken)
    {
        var email = $"delete-session-{Guid.NewGuid():N}@example.test";
        var (identityId, _, _) = await RegisterPasswordIdentityAsync(client, email);

        using var response = await DeleteAccountAsync(sessionToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        using var login = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        login.EnsureSuccessStatusCode();
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.Equal(identityId, loginBody.RootElement.GetProperty("identityId").GetGuid());
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("expired")]
    public async Task DeleteAccount_RevokedOrExpiredSessionCannotDeleteIdentity(
        string sessionState)
    {
        var email = $"delete-inactive-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, _) =
            await RegisterPasswordIdentityAsync(client, email);
        if (sessionState == "revoked")
        {
            using var revoke = await client.PostAsJsonAsync(
                "/v1/auth/session/revoke",
                new { sessionToken });
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        }
        else if (sessionState == "expired")
        {
            await using var expirationScope = api.Services.CreateAsyncScope();
            var dbContext = expirationScope.ServiceProvider
                .GetRequiredService<AccessDbContext>();
            var createdAt = await dbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .Select(session => session.CreatedAt)
                .SingleAsync();
            await dbContext.IdentitySessions
                .Where(session => session.IdentityId == identityId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    session => session.ExpiresAt,
                    createdAt.Add(TimeSpan.FromMilliseconds(1))));
        }
        else
        {
            throw new ArgumentOutOfRangeException(
                nameof(sessionState),
                sessionState,
                null);
        }

        using var response = await DeleteAccountAsync(sessionToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var login = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "password-123" });
        login.EnsureSuccessStatusCode();
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.Equal(identityId, loginBody.RootElement.GetProperty("identityId").GetGuid());
    }

    [Fact]
    public async Task DeleteAccount_RegistrationSessionCannotDeleteIdentity()
    {
        var bootstrap = await BootstrapAsync(
            Guid.NewGuid().ToString("N"),
            TestAccessPolicies.Create(phoneRequired: true));
        using var registrationClient = api.CreateClient();
        registrationClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(bootstrap.IssuedCredentials).Token);
        var email = $"delete-registration-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, sessionPurpose) =
            await RegisterPasswordIdentityAsync(registrationClient, email);
        Assert.Equal("registration", sessionPurpose);

        using var request = new HttpRequestMessage(HttpMethod.Delete, "/v1/account")
        {
            Content = JsonContent.Create(new { sessionToken }),
        };
        using var response = await registrationClient.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.True(await dbContext.Identities.AsNoTracking().AnyAsync(
            identity => identity.Id == identityId));
    }

    [Fact]
    public async Task DeleteAccount_SessionFromAnotherScopeCannotDeleteIdentity()
    {
        var email = $"delete-scope-{Guid.NewGuid():N}@example.test";
        var (identityId, sessionToken, _) =
            await RegisterPasswordIdentityAsync(client, email);
        var otherBootstrap = await BootstrapAsync(Guid.NewGuid().ToString("N"));
        using var otherClient = api.CreateClient();
        otherClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                Assert.Single(otherBootstrap.IssuedCredentials).Token);
        using var request = new HttpRequestMessage(HttpMethod.Delete, "/v1/account")
        {
            Content = JsonContent.Create(new { sessionToken }),
        };

        using var response = await otherClient.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal("session-inactive", body.RootElement.GetProperty("error").GetString());
        }
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.True(await dbContext.Identities.AsNoTracking().AnyAsync(
            identity => identity.Id == identityId));
    }

    [Fact]
    public async Task DeleteAccount_HardDeletesIdentityAndEveryDependentRecord()
    {
        var targetEmail = $"delete-target-{Guid.NewGuid():N}@example.test";
        var targetRegistration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = targetEmail, password = "password-123" });
        targetRegistration.EnsureSuccessStatusCode();
        using var targetBody = JsonDocument.Parse(
            await targetRegistration.Content.ReadAsStringAsync());
        var targetIdentityId = targetBody.RootElement.GetProperty("identityId").GetGuid();
        var targetToken = targetBody.RootElement.GetProperty("sessionToken").GetString();

        var secondLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = targetEmail, password = "password-123" });
        secondLogin.EnsureSuccessStatusCode();

        api.GoogleValidator.Assertion = new(
            $"delete-google-{Guid.NewGuid():N}@example.test",
            $"delete-google-subject-{Guid.NewGuid():N}",
            "Delete Target");
        var linked = await client.PostAsJsonAsync(
            "/v1/account/social/google/link",
            new { sessionToken = targetToken, idToken = "google-token" });
        linked.EnsureSuccessStatusCode();

        var claimantEmail = $"delete-claimant-{Guid.NewGuid():N}@example.test";
        var claimantRegistration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = claimantEmail, password = "password-123" });
        claimantRegistration.EnsureSuccessStatusCode();
        using var claimantBody = JsonDocument.Parse(
            await claimantRegistration.Content.ReadAsStringAsync());
        var claimantIdentityId = claimantBody.RootElement.GetProperty("identityId").GetGuid();

        Guid flowId;
        Guid challengeId;
        Guid phoneIdentifierId;
        Guid targetRegistrationContextId;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var now = DateTimeOffset.UtcNow;
            var targetIdentity = await dbContext.Identities.AsNoTracking().SingleAsync(
                identity => identity.Id == targetIdentityId);
            var targetSession = await dbContext.IdentitySessions.AsNoTracking().FirstAsync(
                session => session.IdentityId == targetIdentityId);
            var claimantSession = await dbContext.IdentitySessions.AsNoTracking().SingleAsync(
                session => session.IdentityId == claimantIdentityId);
            targetRegistrationContextId = await dbContext.RegistrationContexts.AsNoTracking()
                .Where(context => context.IdentityId == targetIdentityId)
                .Select(context => context.Id)
                .SingleAsync();
            var integrationClient = await dbContext.IntegrationClients.AsNoTracking()
                .SingleAsync(item => item.AppEnvironmentId == targetSession.AppEnvironmentId);
            var applicationClient = await dbContext.ApplicationClients.AsNoTracking()
                .SingleAsync(item => item.AppEnvironmentId == targetSession.AppEnvironmentId);

            phoneIdentifierId = Guid.CreateVersion7(now);
            var phone = new IdentityIdentifier(
                phoneIdentifierId,
                targetIdentityId,
                targetIdentity.RealmId,
                IdentifierScheme.Phone,
                "+5511999990001",
                now,
                now,
                "seed");
            dbContext.IdentityIdentifiers.Add(phone);
            dbContext.PasswordResetTokens.Add(new PasswordResetToken(
                Guid.CreateVersion7(now),
                targetIdentityId,
                targetSession.AppEnvironmentId,
                RandomNumberGenerator.GetBytes(
                    IdentityLimits.PasswordResetTokenHashLength),
                now,
                now.AddMinutes(30)));
            dbContext.PhonePasswordResetChallenges.Add(new PhonePasswordResetChallenge(
                Guid.CreateVersion7(now),
                targetIdentityId,
                targetSession.AppEnvironmentId,
                phone.NormalizedValue,
                RandomNumberGenerator.GetBytes(
                    IdentityLimits.PhonePasswordResetCodeHashLength),
                5,
                now,
                now.AddMinutes(10),
                now.AddMinutes(1)));

            flowId = Guid.CreateVersion7(now);
            var flow = new AccessFlow(
                flowId,
                targetIdentity.RealmId,
                targetSession.AppEnvironmentId,
                integrationClient.Id,
                applicationClient.Id,
                claimantIdentityId,
                null,
                claimantSession.Id,
                1,
                AccessFlowIntent.ManagePhone,
                now,
                now.AddMinutes(30));
            challengeId = Guid.CreateVersion7(now);
            dbContext.AccessFlows.Add(flow);
            dbContext.AccessFlowDataSubjects.AddRange(
                new AccessFlowDataSubject(
                    targetIdentity.RealmId,
                    flowId,
                    claimantIdentityId,
                    now),
                new AccessFlowDataSubject(
                    targetIdentity.RealmId,
                    flowId,
                    targetIdentityId,
                    now));
            dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
                flowId,
                1,
                "{}",
                now));
            dbContext.AccessFlowRequests.Add(new AccessFlowRequest(
                integrationClient.Id,
                Guid.NewGuid(),
                flowId,
                AccessFlowRequestKind.Start,
                RandomNumberGenerator.GetBytes(AccessFlowLimits.PayloadHashLength),
                1,
                now));
            var proofChallenge = new ProofChallenge(
                challengeId,
                flowId,
                claimantIdentityId,
                ProofChallengeType.PhonePossession,
                ProofChallengeChannel.Sms,
                IdentifierScheme.Phone,
                phone.NormalizedValue,
                RandomNumberGenerator.GetBytes(IdentityLimits.SessionTokenHashLength),
                "provider-reference",
                5,
                now,
                now.AddMinutes(10),
                now.AddMinutes(1));
            proofChallenge.Verify(now);
            dbContext.ProofChallenges.Add(proofChallenge);
            dbContext.ProofAttempts.Add(new ProofAttempt(
                Guid.CreateVersion7(now),
                challengeId,
                ProofAttemptOutcome.Succeeded,
                now));
            dbContext.IdentityProofs.Add(new IdentityProof(
                Guid.CreateVersion7(now),
                flowId,
                claimantIdentityId,
                challengeId,
                ProofChallengeType.PhonePossession,
                phoneIdentifierId,
                now));
            dbContext.PhoneRegistrationConflicts.Add(new PhoneRegistrationConflict(
                flowId,
                targetIdentityId,
                phoneIdentifierId,
                now,
                now.AddMinutes(20)));
            await dbContext.SaveChangesAsync();
        }

        using var deleted = await DeleteAccountAsync(targetToken);
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        using var retry = await DeleteAccountAsync(targetToken);
        Assert.Equal(HttpStatusCode.Unauthorized, retry.StatusCode);

        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        Assert.False(await verification.Identities.AsNoTracking().AnyAsync(
            identity => identity.Id == targetIdentityId));
        Assert.True(await verification.Identities.AsNoTracking().AnyAsync(
            identity => identity.Id == claimantIdentityId));
        Assert.False(await verification.IdentityIdentifiers.AsNoTracking().AnyAsync(
            identifier => identifier.IdentityId == targetIdentityId));
        Assert.False(await verification.PasswordCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == targetIdentityId));
        Assert.False(await verification.SocialCredentials.AsNoTracking().AnyAsync(
            credential => credential.IdentityId == targetIdentityId));
        Assert.False(await verification.IdentitySessions.AsNoTracking().AnyAsync(
            session => session.IdentityId == targetIdentityId));
        Assert.False(await verification.RegistrationContexts.AsNoTracking().AnyAsync(
            context => context.Id == targetRegistrationContextId));
        Assert.False(await verification.PasswordResetTokens.AsNoTracking().AnyAsync(
            token => token.IdentityId == targetIdentityId));
        Assert.False(await verification.PhonePasswordResetChallenges.AsNoTracking().AnyAsync(
            challenge => challenge.IdentityId == targetIdentityId));
        Assert.False(await verification.AccessFlows.AsNoTracking().AnyAsync(
            flow => flow.Id == flowId));
        Assert.False(await verification.AccessFlowDataSubjects.AsNoTracking().AnyAsync(
            subject => subject.FlowId == flowId));
        Assert.False(await verification.AccessFlowRevisions.AsNoTracking().AnyAsync(
            revision => revision.FlowId == flowId));
        Assert.False(await verification.AccessFlowRequests.AsNoTracking().AnyAsync(
            request => request.FlowId == flowId));
        Assert.False(await verification.ProofChallenges.AsNoTracking().AnyAsync(
            challenge => challenge.Id == challengeId));
        Assert.False(await verification.ProofAttempts.AsNoTracking().AnyAsync(
            attempt => attempt.ChallengeId == challengeId));
        Assert.False(await verification.IdentityProofs.AsNoTracking().AnyAsync(
            proof => proof.AccessFlowId == flowId
                || proof.SubjectIdentifierId == phoneIdentifierId));
        Assert.False(await verification.PhoneRegistrationConflicts.AsNoTracking().AnyAsync(
            conflict => conflict.AccessFlowId == flowId));
    }

    private async Task<bool> IsSessionActiveAsync(string? sessionToken)
    {
        var response = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken });
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("active").GetBoolean();
    }

    private async Task<HttpResponseMessage> DeleteAccountAsync(string? sessionToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, "/v1/account")
        {
            Content = JsonContent.Create(new { sessionToken }),
        };
        return await client.SendAsync(request);
    }

    private async Task<BootstrapTopologyResult> BootstrapAsync(
        string suffix,
        AppAccessPolicy? accessPolicy = null) =>
        await BootstrapAsync(CreateBootstrapCommand(suffix, accessPolicy));

    private async Task<BootstrapTopologyResult> BootstrapAsync(
        BootstrapTopologyCommand command)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
        return await handler.HandleAsync(command);
    }

    private static async Task<string?> ReadSessionTokenAsync(HttpResponseMessage response)
    {
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("sessionToken").GetString();
    }

    private static async Task<(Guid IdentityId, string SessionToken, string SessionPurpose)>
        RegisterPasswordIdentityAsync(HttpClient targetClient, string email)
    {
        using var response = await targetClient.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        return (
            root.GetProperty("identityId").GetGuid(),
            Assert.IsType<string>(root.GetProperty("sessionToken").GetString()),
            Assert.IsType<string>(root.GetProperty("sessionPurpose").GetString()));
    }

    private async Task WaitForBlockedSocialCredentialInsertsAsync(
        int expectedCount,
        CancellationToken cancellationToken)
    {
        await using var observer = new NpgsqlConnection(database.ConnectionString);
        await observer.OpenAsync(cancellationToken);

        while (true)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT count(*)
                FROM pg_stat_activity
                WHERE datname = current_database()
                  AND wait_event_type = 'Lock'
                  AND query ILIKE 'INSERT INTO social_credentials%';
                """;
            var blockedCount = Convert.ToInt32(
                await command.ExecuteScalarAsync(cancellationToken));
            if (blockedCount >= expectedCount)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken);
        }
    }

    private async Task<HttpResponseMessage[]> RacePasswordChangesAsync(
        (string? SessionToken, string? CurrentPassword, string NewPassword) first,
        (string? SessionToken, string? CurrentPassword, string NewPassword) second)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var lockConnection = new NpgsqlConnection(database.ConnectionString);
        await lockConnection.OpenAsync(timeout.Token);
        await using var lockTransaction = await lockConnection.BeginTransactionAsync(
            cancellationToken: timeout.Token);
        await using (var lockCommand = lockConnection.CreateCommand())
        {
            lockCommand.Transaction = lockTransaction;
            lockCommand.CommandText = "LOCK TABLE password_credentials IN SHARE MODE;";
            await lockCommand.ExecuteNonQueryAsync(timeout.Token);
        }

        var firstChange = client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken = first.SessionToken,
                currentPassword = first.CurrentPassword,
                newPassword = first.NewPassword,
            },
            timeout.Token);
        var secondChange = client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken = second.SessionToken,
                currentPassword = second.CurrentPassword,
                newPassword = second.NewPassword,
            },
            timeout.Token);
        await WaitForBlockedPasswordChangesAsync(
            expectedCount: 2,
            cancellationToken: timeout.Token);
        await lockTransaction.CommitAsync(timeout.Token);
        return await Task.WhenAll(firstChange, secondChange);
    }

    private async Task WaitForBlockedPasswordChangesAsync(
        int expectedCount,
        CancellationToken cancellationToken)
    {
        await using var observer = new NpgsqlConnection(database.ConnectionString);
        await observer.OpenAsync(cancellationToken);

        while (true)
        {
            await using var command = observer.CreateCommand();
            command.CommandText = """
                SELECT count(*)
                FROM pg_stat_activity
                WHERE datname = current_database()
                  AND wait_event_type = 'Lock'
                  AND (
                    query ILIKE 'UPDATE password_credentials%'
                    OR query ILIKE 'INSERT INTO password_credentials%'
                    OR query ILIKE '%FROM identities WHERE id =%FOR UPDATE%');
                """;
            var blockedCount = Convert.ToInt32(
                await command.ExecuteScalarAsync(cancellationToken));
            if (blockedCount >= expectedCount)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken);
        }
    }

    private static string FindCredential(
        BootstrapTopologyResult bootstrap,
        string path) =>
        bootstrap.IssuedCredentials.Single(
            credential => credential.IntegrationClientPath == path).Token;

    private static BootstrapTopologyCommand CreateRealmIsolationBootstrapCommand(
        string suffix)
    {
        var accessPolicy = TestAccessPolicies.Create(
            phoneEnabled: false,
            phoneVerificationEnabled: false,
            googleEnabled: true);
        return new BootstrapTopologyCommand(
            $"social-realm-isolation-{suffix}",
            "Social realm isolation tests",
            [
                new BootstrapAppDefinition(
                    $"baybo-{suffix}",
                    "BAYBO",
                    [
                        new BootstrapRealmDefinition(
                            $"first-realm-{suffix}",
                            "First realm"),
                        new BootstrapRealmDefinition(
                            $"second-realm-{suffix}",
                            "Second realm"),
                    ],
                    [
                        CreateEnvironmentDefinition(
                            "first",
                            "First",
                            $"first-realm-{suffix}",
                            accessPolicy),
                        CreateEnvironmentDefinition(
                            "second",
                            "Second",
                            $"second-realm-{suffix}",
                            accessPolicy),
                    ]),
            ]);
    }

    private static BootstrapEnvironmentDefinition CreateEnvironmentDefinition(
        string key,
        string name,
        string realmKey,
        AppAccessPolicy accessPolicy) =>
        new(
            key,
            name,
            realmKey,
            accessPolicy,
            TestEnvironmentConfigurations.VerificationPolicy,
            TestEnvironmentConfigurations.RecoveryPolicy(),
            TestEnvironmentConfigurations.Providers(accessPolicy),
            TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
            [
                new BootstrapIntegrationClientDefinition(
                    "api",
                    "API",
                    [AccessPermission.ExecuteFlows]),
            ],
            []);

    private static BootstrapTopologyCommand CreateBootstrapCommand(
        string suffix,
        AppAccessPolicy? accessPolicy = null) =>
        new(
            $"current-identity-{suffix}",
            "Current identity access tests",
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
                            accessPolicy ?? TestAccessPolicies.Create(
                                phoneEnabled: false,
                                phoneVerificationEnabled: false,
                                googleEnabled: true,
                                appleEnabled: true),
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(
                                accessPolicy ?? TestAccessPolicies.Create(
                                    phoneEnabled: false,
                                    phoneVerificationEnabled: false,
                                    googleEnabled: true,
                                    appleEnabled: true)),
                            TestEnvironmentConfigurations.DevelopmentBypass(
                                accessPolicy ?? TestAccessPolicies.Create(
                                    phoneEnabled: false,
                                    phoneVerificationEnabled: false,
                                    googleEnabled: true,
                                    appleEnabled: true)),
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
                            [
                                new BootstrapApplicationClientDefinition(
                                    "android-debug",
                                    "Android debug",
                                    ApplicationClientPlatform.Android,
                                    "app.baybo.currentidentity",
                                    "sha256:fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
                                    "92TvTC0UfaA",
                                    JsonSerializer.SerializeToElement(new { })),
                            ]),
                    ]),
            ]);
}
