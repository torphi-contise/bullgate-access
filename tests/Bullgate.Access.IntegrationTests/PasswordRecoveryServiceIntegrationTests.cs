using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Bullgate.Access.IntegrationTests;

public sealed class PasswordRecoveryServiceIntegrationTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private static readonly string[] ConcurrentPasswords =
        ["concurrent-password-one", "concurrent-password-two"];
    private const string RecoveryUrl = "https://baybo.app/reset-password";
    private readonly AdjustableTimeProvider clock = new(
        DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private Guid appEnvironmentId;
    private string topologySuffix = null!;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString, clock);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await dbContext.Database.EnsureCreatedAsync();
        }

        BootstrapTopologyResult bootstrap;
        topologySuffix = Guid.NewGuid().ToString("N");
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            bootstrap = await handler.HandleAsync(CreateBootstrapCommand(topologySuffix));
        }

        appEnvironmentId = bootstrap.Resources
            .Single(resource => resource.Type == "environment")
            .Id;
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
    public async Task Reset_WithAnyActiveToken_ReplacesPassword_ConsumesAllTokens_AndRevokesEverySession()
    {
        var email = $"recovery-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement
            .GetProperty("identityId")
            .GetGuid();
        var originalSessionToken = registrationBody.RootElement
            .GetProperty("sessionToken")
            .GetString();

        var secondLogin = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.OK, secondLogin.StatusCode);
        using var secondLoginBody = JsonDocument.Parse(
            await secondLogin.Content.ReadAsStringAsync());
        var secondSessionToken = secondLoginBody.RootElement
            .GetProperty("sessionToken")
            .GetString();

        PasswordResetIssueResult firstIssue;
        PasswordResetIssueResult secondIssue;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var passwordReset = scope.ServiceProvider
                .GetRequiredService<PasswordResetService>();
            firstIssue = await passwordReset.IssueAsync(
                identityId,
                appEnvironmentId);
            secondIssue = await passwordReset.IssueAsync(
                identityId,
                appEnvironmentId);
        }

        Assert.True(firstIssue.Succeeded);
        Assert.True(secondIssue.Succeeded);
        Assert.Equal(43, secondIssue.Token.Length);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var activeTokens = await dbContext.PasswordResetTokens
                .AsNoTracking()
                .Where(token => token.IdentityId == identityId && token.UsedAt == null)
                .ToArrayAsync();
            Assert.Equal(2, activeTokens.Length);
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var passwordReset = scope.ServiceProvider
                .GetRequiredService<PasswordResetService>();
            var reset = await passwordReset.ResetAsync(
                appEnvironmentId,
                firstIssue.Token,
                "replacement-password");
            Assert.True(reset.Succeeded);
            Assert.Equal(identityId, reset.IdentityId);
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var passwordHashes = scope.ServiceProvider
                .GetRequiredService<IPasswordHashService>();
            var credential = await dbContext.PasswordCredentials
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.True(passwordHashes.Verify(
                credential.PasswordHash,
                "replacement-password"));
            Assert.False(passwordHashes.Verify(
                credential.PasswordHash,
                "original-password"));

            var sessions = await dbContext.IdentitySessions
                .AsNoTracking()
                .Where(session => session.IdentityId == identityId)
                .ToArrayAsync();
            Assert.Equal(2, sessions.Length);
            Assert.All(sessions, session => Assert.NotNull(session.RevokedAt));

            var tokens = await dbContext.PasswordResetTokens
                .AsNoTracking()
                .Where(token => token.IdentityId == identityId)
                .OrderBy(token => token.CreatedAt)
                .ToArrayAsync();
            Assert.Equal(2, tokens.Length);
            Assert.NotNull(tokens[0].UsedAt);
            Assert.NotNull(tokens[1].UsedAt);
        }

        var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = originalSessionToken });
        Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
        using (var introspectionBody = JsonDocument.Parse(
            await introspection.Content.ReadAsStringAsync()))
        {
            Assert.False(introspectionBody.RootElement
                .GetProperty("active")
                .GetBoolean());
        }

        var secondIntrospection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken = secondSessionToken });
        Assert.Equal(HttpStatusCode.OK, secondIntrospection.StatusCode);
        using (var secondIntrospectionBody = JsonDocument.Parse(
            await secondIntrospection.Content.ReadAsStringAsync()))
        {
            Assert.False(secondIntrospectionBody.RootElement
                .GetProperty("active")
                .GetBoolean());
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var passwordReset = scope.ServiceProvider
                .GetRequiredService<PasswordResetService>();
            var reused = await passwordReset.ResetAsync(
                appEnvironmentId,
                secondIssue.Token,
                "another-password");
            Assert.Equal(PasswordResetError.InvalidToken, reused.Error);
        }

        var oldPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldPassword.StatusCode);

        var newPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "replacement-password" });
        Assert.Equal(HttpStatusCode.OK, newPassword.StatusCode);
    }

    [Fact]
    public async Task Reset_ConcurrentUseOfTheSameToken_HasExactlyOneWinner()
    {
        var email = $"concurrent-recovery-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement
            .GetProperty("identityId")
            .GetGuid();

        PasswordResetIssueResult issued;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var passwordReset = scope.ServiceProvider
                .GetRequiredService<PasswordResetService>();
            issued = await passwordReset.IssueAsync(identityId, appEnvironmentId);
        }
        Assert.True(issued.Succeeded);

        var attempts = ConcurrentPasswords.Select(async password =>
        {
            var response = await client.PostAsJsonAsync(
                "/v1/auth/password/recovery/reset",
                new { token = issued.Token, newPassword = password });
            return (Password: password, Response: response);
        });
        var results = await Task.WhenAll(attempts);

        Assert.Equal(
            1,
            results.Count(result =>
                result.Response.StatusCode == HttpStatusCode.NoContent));
        Assert.Equal(
            1,
            results.Count(result =>
                result.Response.StatusCode == HttpStatusCode.BadRequest));
        var winner = results.Single(result =>
            result.Response.StatusCode == HttpStatusCode.NoContent);
        var rejected = results.Single(result =>
            result.Response.StatusCode == HttpStatusCode.BadRequest);
        using (var rejectedBody = JsonDocument.Parse(
            await rejected.Response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "invalid-token",
                rejectedBody.RootElement.GetProperty("error").GetString());
        }

        var winningPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = winner.Password });
        Assert.Equal(HttpStatusCode.OK, winningPassword.StatusCode);
        var rejectedPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = rejected.Password });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedPassword.StatusCode);
    }

    [Fact]
    public async Task Reset_TokenIsScopedToTheIssuingAppEnvironment()
    {
        var email = $"environment-recovery-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement
            .GetProperty("identityId")
            .GetGuid();

        PasswordResetIssueResult issued;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var passwordReset = scope.ServiceProvider
                .GetRequiredService<PasswordResetService>();
            issued = await passwordReset.IssueAsync(identityId, appEnvironmentId);
        }
        Assert.True(issued.Succeeded);

        BootstrapTopologyResult bootstrap;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            bootstrap = await handler.HandleAsync(CreateBootstrapCommand(
                topologySuffix,
                includeSecondaryEnvironment: true));
        }
        var secondaryEnvironmentId = bootstrap.Resources
            .Single(resource =>
                resource.Type == "environment"
                && resource.Path.EndsWith("/secondary", StringComparison.Ordinal))
            .Id;

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var passwordReset = scope.ServiceProvider
                .GetRequiredService<PasswordResetService>();
            var wrongEnvironment = await passwordReset.ResetAsync(
                secondaryEnvironmentId,
                issued.Token,
                "wrong-environment-password");
            Assert.Equal(PasswordResetError.InvalidToken, wrongEnvironment.Error);

            var issuingEnvironment = await passwordReset.ResetAsync(
                appEnvironmentId,
                issued.Token,
                "replacement-password");
            Assert.True(issuingEnvironment.Succeeded);
        }
    }

    [Fact]
    public async Task EmailEndpoint_UsesUniformAcceptedStatus_AndDeliveredTokenResetsPassword()
    {
        var email = $"email-recovery-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);

        var unknown = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/email",
            new { email = $"unknown-{Guid.NewGuid():N}@example.com" });
        var invalid = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/email",
            new { email = "not-an-email" });
        Assert.Equal(HttpStatusCode.Accepted, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, invalid.StatusCode);
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);

        var known = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/email",
            new { email = email.ToUpperInvariant() });
        Assert.Equal(HttpStatusCode.Accepted, known.StatusCode);

        var delivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        Assert.Equal(email, delivery.Email);
        Assert.Equal("BAYBO", delivery.AppName);
        Assert.Equal(60, delivery.TokenLifetimeMinutes);
        var resetUrl = new Uri(delivery.ResetUrl);
        Assert.Equal("https://baybo.app/reset-password", resetUrl.GetLeftPart(UriPartial.Path));
        var token = Uri.UnescapeDataString(resetUrl.Query["?token=".Length..]);
        Assert.Equal(43, token.Length);

        var reset = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token, newPassword = "replacement-password" });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);

        var oldPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, oldPassword.StatusCode);
        var newPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "replacement-password" });
        Assert.Equal(HttpStatusCode.OK, newPassword.StatusCode);
    }

    [Fact]
    public async Task EmailIssue_RejectsAnAddressThatChangedBeforeTheIdentityLock()
    {
        var originalEmail = $"stale-email-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = originalEmail, password = "original-password" });
        registration.EnsureSuccessStatusCode();
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement.GetProperty("identityId").GetGuid();
        var sessionToken = registrationBody.RootElement.GetProperty("sessionToken").GetString();
        var currentEmail = $"current-email-{Guid.NewGuid():N}@example.invalid";

        var changed = await client.PutAsJsonAsync(
            "/v1/account/email",
            new { sessionToken, email = currentEmail });
        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);

        await using var scope = api.Services.CreateAsyncScope();
        var passwordReset = scope.ServiceProvider
            .GetRequiredService<PasswordResetService>();
        var stale = await passwordReset.IssueForEmailAsync(
            identityId,
            appEnvironmentId,
            originalEmail);
        Assert.Equal(PasswordResetIssueError.IdentityIneligible, stale.Error);

        var current = await passwordReset.IssueForEmailAsync(
            identityId,
            appEnvironmentId,
            currentEmail);
        Assert.True(current.Succeeded);

        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Single(await dbContext.PasswordResetTokens.AsNoTracking()
            .Where(token => token.IdentityId == identityId)
            .ToArrayAsync());
    }

    [Fact]
    public async Task FailedEmailDelivery_PreservesThePreviouslyDeliveredResetLink()
    {
        var email = $"email-failure-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement
            .GetProperty("identityId")
            .GetGuid();

        var delivered = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/email",
            new { email });
        Assert.Equal(HttpStatusCode.Accepted, delivered.StatusCode);
        var firstDelivery = Assert.Single(
            api.PasswordRecoveryEmailSender.DeliveryAttempts);
        var firstToken = ReadResetToken(firstDelivery);

        api.PasswordRecoveryEmailSender.DeliverySucceeds = false;
        var failed = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/email",
            new { email });
        Assert.Equal(HttpStatusCode.Accepted, failed.StatusCode);
        Assert.Equal(2, api.PasswordRecoveryEmailSender.DeliveryAttempts.Count);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var tokens = await dbContext.PasswordResetTokens
                .AsNoTracking()
                .Where(token => token.IdentityId == identityId)
                .ToArrayAsync();
            Assert.Equal(2, tokens.Length);
            Assert.All(tokens, token => Assert.True(token.IsActive(DateTimeOffset.UtcNow)));
        }

        var reset = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token = firstToken, newPassword = "replacement-password" });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var tokens = await dbContext.PasswordResetTokens
                .AsNoTracking()
                .Where(token => token.IdentityId == identityId)
                .ToArrayAsync();
            Assert.Equal(2, tokens.Length);
            Assert.All(tokens, token => Assert.NotNull(token.UsedAt));
        }
    }

    [Fact]
    public async Task EmailEndpoint_DoesNotIssueWhenSenderOrRecoveryUrlIsUnavailable()
    {
        var email = $"email-unavailable-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement
            .GetProperty("identityId")
            .GetGuid();

        api.PasswordRecoveryEmailSender.IsAvailable = false;
        var unavailableSender = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/email",
            new { email });
        Assert.Equal(HttpStatusCode.Accepted, unavailableSender.StatusCode);
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);

        api.PasswordRecoveryEmailSender.IsAvailable = true;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            var result = await handler.HandleAsync(CreateBootstrapCommand(
                topologySuffix,
                emailRecoveryEnabled: false));
            Assert.Empty(result.IssuedCredentials);
        }

        var unavailableUrl = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/email",
            new { email });
        Assert.Equal(HttpStatusCode.Accepted, unavailableUrl.StatusCode);
        Assert.Empty(api.PasswordRecoveryEmailSender.DeliveryAttempts);

        await using var verificationScope = api.Services.CreateAsyncScope();
        var verificationDb = verificationScope.ServiceProvider
            .GetRequiredService<AccessDbContext>();
        Assert.False(await verificationDb.PasswordResetTokens
            .AnyAsync(token => token.IdentityId == identityId));
    }

    [Fact]
    public async Task EmailEndpoint_AllowsFiveActiveTokens_AndSixthRequestCreatesNothing()
    {
        var email = $"email-rate-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement
            .GetProperty("identityId")
            .GetGuid();

        var requests = Enumerable.Range(0, 6)
            .Select(_ => client.PostAsJsonAsync(
                "/v1/auth/password/recovery/email",
                new { email }))
            .ToArray();
        var responses = await Task.WhenAll(requests);
        foreach (var response in responses)
        {
            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        }

        Assert.Equal(5, api.PasswordRecoveryEmailSender.DeliveryAttempts.Count);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tokens = await dbContext.PasswordResetTokens
            .AsNoTracking()
            .Where(token => token.IdentityId == identityId)
            .ToArrayAsync();
        Assert.Equal(5, tokens.Length);
        Assert.All(tokens, token => Assert.True(token.IsActive(DateTimeOffset.UtcNow)));
    }

    [Fact]
    public async Task AuthenticatedPasswordChange_InvalidatesPasswordResetTokens()
    {
        var email = $"change-password-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement
            .GetProperty("identityId")
            .GetGuid();
        var sessionToken = registrationBody.RootElement
            .GetProperty("sessionToken")
            .GetString();

        PasswordResetIssueResult issued;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var passwordReset = scope.ServiceProvider
                .GetRequiredService<PasswordResetService>();
            issued = await passwordReset.IssueAsync(identityId, appEnvironmentId);
        }
        Assert.True(issued.Succeeded);

        var change = await client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                currentPassword = "original-password",
                newPassword = "changed-password",
            });
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var stored = await dbContext.PasswordResetTokens
                .AsNoTracking()
                .SingleAsync(token => token.IdentityId == identityId);
            Assert.NotNull(stored.UsedAt);
        }

        var rejectedReset = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token = issued.Token, newPassword = "replacement-password" });
        Assert.Equal(HttpStatusCode.BadRequest, rejectedReset.StatusCode);

        var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken });
        Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
        using var introspectionBody = JsonDocument.Parse(
            await introspection.Content.ReadAsStringAsync());
        Assert.True(introspectionBody.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task AuthenticatedPasswordChange_AndResetHaveExactlyOneWinner()
    {
        var email = $"change-reset-race-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var identityId = registrationBody.RootElement.GetProperty("identityId").GetGuid();
        var sessionToken = registrationBody.RootElement.GetProperty("sessionToken").GetString();

        PasswordResetIssueResult issued;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var passwordReset = scope.ServiceProvider
                .GetRequiredService<PasswordResetService>();
            issued = await passwordReset.IssueAsync(identityId, appEnvironmentId);
        }
        Assert.True(issued.Succeeded);

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

        var change = client.PostAsJsonAsync(
            "/v1/account/password",
            new
            {
                sessionToken,
                currentPassword = "original-password",
                newPassword = "authenticated-password",
            },
            timeout.Token);
        var reset = client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token = issued.Token, newPassword = "recovered-password" },
            timeout.Token);
        await WaitForBlockedPasswordMutationsAsync(
            expectedCount: 2,
            cancellationToken: timeout.Token);
        await lockTransaction.CommitAsync(timeout.Token);
        var changeResponse = await change;
        var resetResponse = await reset;

        var changeWon = changeResponse.StatusCode == HttpStatusCode.OK;
        if (changeWon)
        {
            Assert.Equal(HttpStatusCode.BadRequest, resetResponse.StatusCode);
            using var body = JsonDocument.Parse(
                await resetResponse.Content.ReadAsStringAsync());
            Assert.Equal("invalid-token", body.RootElement.GetProperty("error").GetString());
        }
        else
        {
            Assert.Equal(HttpStatusCode.Conflict, changeResponse.StatusCode);
            using var body = JsonDocument.Parse(
                await changeResponse.Content.ReadAsStringAsync());
            Assert.Equal(
                "password-change-conflict",
                body.RootElement.GetProperty("error").GetString());
            Assert.Equal(HttpStatusCode.NoContent, resetResponse.StatusCode);
        }

        var originalPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, originalPassword.StatusCode);
        var authenticatedPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "authenticated-password" });
        Assert.Equal(
            changeWon ? HttpStatusCode.OK : HttpStatusCode.Unauthorized,
            authenticatedPassword.StatusCode);
        var recoveredPassword = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email, password = "recovered-password" });
        Assert.Equal(
            changeWon ? HttpStatusCode.Unauthorized : HttpStatusCode.OK,
            recoveredPassword.StatusCode);

        var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken });
        introspection.EnsureSuccessStatusCode();
        using var introspectionBody = JsonDocument.Parse(
            await introspection.Content.ReadAsStringAsync());
        Assert.Equal(
            changeWon,
            introspectionBody.RootElement.GetProperty("active").GetBoolean());
    }

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(1, false)]
    public async Task Reset_ExpiresAtTheExactDeadline(
        int secondsFromExpiration,
        bool succeeds)
    {
        var account = await RegisterRecoveryAccountAsync();
        var issued = await IssueResetAsync(account.IdentityId);
        clock.Advance(issued.ExpiresAt.AddSeconds(secondsFromExpiration) - clock.GetUtcNow());

        using var response = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token = issued.Token, newPassword = "recovered-password" });

        Assert.Equal(succeeds ? HttpStatusCode.NoContent : HttpStatusCode.BadRequest, response.StatusCode);
        if (!succeeds)
        {
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("invalid-token", body.RootElement.GetProperty("error").GetString());
            Assert.Equal("token", body.RootElement.GetProperty("field").GetString());
        }

        await AssertPasswordAsync(account.Email, "original-password", !succeeds, account.IdentityId);
        await AssertPasswordAsync(account.Email, "recovered-password", succeeds, account.IdentityId);
        using var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect", new { sessionToken = account.SessionToken });
        Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
        using var state = JsonDocument.Parse(await introspection.Content.ReadAsStringAsync());
        Assert.Equal(!succeeds, state.RootElement.GetProperty("active").GetBoolean());
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var token = await dbContext.PasswordResetTokens.AsNoTracking()
            .SingleAsync(item => item.Id == issued.TokenId);
        Assert.Equal(succeeds, token.UsedAt.HasValue);
        Assert.Equal(issued.ExpiresAt, token.ExpiresAt);
    }

    [Theory]
    [InlineData(null, "missing-fields")]
    [InlineData("", "missing-fields")]
    [InlineData("        ", "missing-fields")]
    [InlineData("short", "password-too-short")]
    public async Task Reset_InvalidPasswordPreservesTheLinkForACorrectedRetry(
        string? newPassword,
        string expectedError)
    {
        var account = await RegisterRecoveryAccountAsync();
        var issued = await IssueResetAsync(account.IdentityId);

        using var rejected = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset", new { token = issued.Token, newPassword });

        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        using var error = JsonDocument.Parse(await rejected.Content.ReadAsStringAsync());
        Assert.Equal(expectedError, error.RootElement.GetProperty("error").GetString());
        Assert.Equal("newPassword", error.RootElement.GetProperty("field").GetString());
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var token = await dbContext.PasswordResetTokens.AsNoTracking()
                .SingleAsync(item => item.Id == issued.TokenId);
            Assert.Null(token.UsedAt);
            Assert.Equal(issued.ExpiresAt, token.ExpiresAt);
        }
        await AssertPasswordAsync(account.Email, "original-password", true, account.IdentityId);
        using var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect", new { sessionToken = account.SessionToken });
        Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
        using var state = JsonDocument.Parse(await introspection.Content.ReadAsStringAsync());
        Assert.True(state.RootElement.GetProperty("active").GetBoolean());

        using var retry = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token = issued.Token, newPassword = "recovered-password" });
        Assert.Equal(HttpStatusCode.NoContent, retry.StatusCode);
        await AssertPasswordAsync(account.Email, "original-password", false, account.IdentityId);
        await AssertPasswordAsync(account.Email, "recovered-password", true, account.IdentityId);
    }

    [Theory]
    [InlineData("google")]
    [InlineData("apple")]
    public async Task EmailRecovery_AddsFirstPasswordWithoutLosingSocialIdentity(string provider)
    {
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var bootstrap = await scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>()
                .HandleAsync(CreateBootstrapCommand(topologySuffix, socialEnabled: true));
            Assert.Empty(bootstrap.IssuedCredentials);
        }
        var email = $"social-recovery-{Guid.NewGuid():N}@example.test";
        var subject = Guid.NewGuid().ToString("N");
        api.GoogleValidator.Assertion = new(email, subject, "Recovery User");
        api.AppleValidator.Assertion = new(email, subject, "Recovery User");
        object assertion = provider == "google"
            ? new { idToken = "google-token" }
            : new { identityToken = "apple-token" };
        using var social = await client.PostAsJsonAsync($"/v1/auth/{provider}", assertion);
        Assert.Equal(HttpStatusCode.OK, social.StatusCode);
        using var account = JsonDocument.Parse(await social.Content.ReadAsStringAsync());
        var identityId = account.RootElement.GetProperty("identityId").GetGuid();
        var sessionToken = account.RootElement.GetProperty("sessionToken").GetString();
        Assert.False(account.RootElement.GetProperty("hasPassword").GetBoolean());

        using var recovery = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/email", new { email });
        Assert.Equal(HttpStatusCode.Accepted, recovery.StatusCode);
        var delivery = Assert.Single(api.PasswordRecoveryEmailSender.DeliveryAttempts);
        using var reset = await client.PostAsJsonAsync(
            "/v1/auth/password/recovery/reset",
            new { token = ReadResetToken(delivery), newPassword = "first-password" });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);

        await AssertPasswordAsync(email, "first-password", true, identityId);
        using var providerLogin = await client.PostAsJsonAsync($"/v1/auth/{provider}", assertion);
        Assert.Equal(HttpStatusCode.OK, providerLogin.StatusCode);
        using var providerBody = JsonDocument.Parse(await providerLogin.Content.ReadAsStringAsync());
        Assert.Equal(identityId, providerBody.RootElement.GetProperty("identityId").GetGuid());
        Assert.True(providerBody.RootElement.GetProperty("hasPassword").GetBoolean());
        using var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect", new { sessionToken });
        Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
        using var state = JsonDocument.Parse(await introspection.Content.ReadAsStringAsync());
        Assert.False(state.RootElement.GetProperty("active").GetBoolean());
        await using var verificationScope = api.Services.CreateAsyncScope();
        var db = verificationScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Single(await db.PasswordCredentials.AsNoTracking()
            .Where(credential => credential.IdentityId == identityId).ToArrayAsync());
    }

    private async Task<(Guid IdentityId, string Email, string SessionToken)> RegisterRecoveryAccountAsync()
    {
        var email = $"recovery-boundary-{Guid.NewGuid():N}@example.test";
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/register", new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (body.RootElement.GetProperty("identityId").GetGuid(), email,
            Assert.IsType<string>(body.RootElement.GetProperty("sessionToken").GetString()));
    }

    private async Task<PasswordResetIssueResult> IssueResetAsync(Guid identityId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var issued = await scope.ServiceProvider.GetRequiredService<PasswordResetService>()
            .IssueAsync(identityId, appEnvironmentId);
        Assert.True(issued.Succeeded);
        return issued;
    }

    private async Task AssertPasswordAsync(string email, string password, bool works, Guid identityId)
    {
        using var response = await client.PostAsJsonAsync("/v1/auth/login", new { email, password });
        Assert.Equal(works ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, response.StatusCode);
        if (works)
        {
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(identityId, body.RootElement.GetProperty("identityId").GetGuid());
        }
    }

    private async Task WaitForBlockedPasswordMutationsAsync(
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

    private static string ReadResetToken(PasswordRecoveryEmailDelivery delivery)
    {
        var resetUrl = new Uri(delivery.ResetUrl);
        return Uri.UnescapeDataString(resetUrl.Query["?token=".Length..]);
    }

    private static BootstrapTopologyCommand CreateBootstrapCommand(
        string suffix,
        bool includeSecondaryEnvironment = false,
        bool emailRecoveryEnabled = true,
        bool socialEnabled = false)
    {
        var accessPolicy = TestAccessPolicies.Create(
            phoneEnabled: false,
            phoneVerificationEnabled: false,
            googleEnabled: socialEnabled,
            appleEnabled: socialEnabled);
        var recoveryUrl = emailRecoveryEnabled ? RecoveryUrl : null;
        var environments = new List<BootstrapEnvironmentDefinition>
        {
            new(
                "tests",
                "Tests",
                $"realm-{suffix}",
                accessPolicy,
                TestEnvironmentConfigurations.VerificationPolicy,
                TestEnvironmentConfigurations.RecoveryPolicy(recoveryUrl),
                TestEnvironmentConfigurations.Providers(accessPolicy, recoveryUrl),
                TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
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
                []),
        };
        if (includeSecondaryEnvironment)
        {
            environments.Add(new BootstrapEnvironmentDefinition(
                "secondary",
                "Secondary",
                $"realm-{suffix}",
                accessPolicy,
                TestEnvironmentConfigurations.VerificationPolicy,
                TestEnvironmentConfigurations.RecoveryPolicy(recoveryUrl),
                TestEnvironmentConfigurations.Providers(accessPolicy, recoveryUrl),
                TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
                [],
                []));
        }

        return new BootstrapTopologyCommand(
            $"password-recovery-{suffix}",
            "Password recovery tests",
            [
                new BootstrapAppDefinition(
                    $"baybo-{suffix}",
                    "BAYBO",
                    [new BootstrapRealmDefinition($"realm-{suffix}", "BAYBO tests")],
                    environments),
            ]);
    }
}
