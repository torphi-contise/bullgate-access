using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Mail;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Bullgate.Access.IntegrationTests;

public sealed class EmailPasswordRegistrationBoundaryTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private HttpClient secondaryClient = null!;
    private HttpClient isolatedClient = null!;
    private string topologySuffix = null!;
    private Guid realmId;
    private Guid isolatedRealmId;
    private Guid environmentId;
    private Guid secondaryEnvironmentId;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await db.Database.EnsureCreatedAsync();
        topologySuffix = Guid.NewGuid().ToString("N");
        var bootstrap = await scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>()
            .HandleAsync(CreateBootstrapCommand(topologySuffix));
        realmId = FindResource(bootstrap, "realm", "/realms/shared");
        isolatedRealmId = FindResource(bootstrap, "realm", "/realms/isolated");
        environmentId = FindResource(bootstrap, "environment", "/primary");
        secondaryEnvironmentId = FindResource(bootstrap, "environment", "/secondary");
        client = CreateClient(bootstrap, "primary");
        secondaryClient = CreateClient(bootstrap, "secondary");
        isolatedClient = CreateClient(bootstrap, "isolated");
    }

    public async Task DisposeAsync()
    {
        isolatedClient.Dispose();
        secondaryClient.Dispose();
        client.Dispose();
        await api.DisposeAsync();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-email")]
    public async Task Register_InvalidEmailLeavesNoPartialAccount(string? email)
    {
        using var rejected = await client.PostAsJsonAsync(
            "/v1/auth/register", new { email, password = "password-123" });

        await AssertErrorAsync(rejected, HttpStatusCode.BadRequest, "invalid-email", "email");
        await AssertEmptyRegistrationAsync();
        var corrected = await RegisterAsync(client, NewEmail(), "password-123");
        await AssertOnlyRegisteredAccountAsync(corrected.IdentityId);
    }

    [Fact]
    public async Task Register_OversizedEmailReturnsAValidationErrorWithoutPartialAccount()
    {
        var email = OversizedEmail();
        // Isolate Access's size limit from the framework's address-syntax checks.
        Assert.True(MailAddress.TryCreate(email, out _));
        using var rejected = await client.PostAsJsonAsync(
            "/v1/auth/register", new { email, password = "password-123" });

        await AssertErrorAsync(rejected, HttpStatusCode.BadRequest, "invalid-email", "email");
        await AssertEmptyRegistrationAsync();
        var corrected = await RegisterAsync(client, NewEmail(), "password-123");
        await AssertOnlyRegisteredAccountAsync(corrected.IdentityId);
        Assert.Equal(corrected.IdentityId,
            (await LoginAsync(client, corrected.Email, "password-123")).IdentityId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Seven77")]
    public async Task Register_ShortPasswordDoesNotReserveTheEmail(string? password)
    {
        var email = NewEmail();
        using var rejected = await client.PostAsJsonAsync(
            "/v1/auth/register", new { email, password });

        await AssertErrorAsync(rejected, HttpStatusCode.BadRequest, "password-too-short", "password");
        await AssertEmptyRegistrationAsync();
        var corrected = await RegisterAsync(client, email, "Eight888");
        await AssertOnlyRegisteredAccountAsync(corrected.IdentityId);
        var login = await LoginAsync(client, email, "Eight888");
        Assert.Equal(corrected.IdentityId, login.IdentityId);
    }

    [Fact]
    public async Task Register_MinimumLengthPasswordRemainsCaseSensitiveAtLogin()
    {
        var email = NewEmail();
        var account = await RegisterAsync(client, email, "Eight888");

        using var changedCase = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email, password = "eight888" });

        await AssertErrorAsync(changedCase, HttpStatusCode.Unauthorized, "invalid-credentials");
        await AssertOnlyRegisteredAccountAsync(account.IdentityId);
        Assert.Equal(account.IdentityId, (await LoginAsync(client, email, "Eight888")).IdentityId);
    }

    [Fact]
    public async Task Register_ConcurrentNormalizedEmailsPersistOnlyTheWinningAccountAndPassword()
    {
        var email = NewEmail();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var blocker = new NpgsqlConnection(database.ConnectionString);
        await blocker.OpenAsync(timeout.Token);
        await using var transaction = await blocker.BeginTransactionAsync(timeout.Token);
        await using (var command = blocker.CreateCommand())
        {
            command.Transaction = transaction;
            // Let both existence checks finish before either registration can persist.
            command.CommandText = "LOCK TABLE identities IN SHARE MODE";
            await command.ExecuteNonQueryAsync(timeout.Token);
        }
        var first = client.PostAsJsonAsync(
            "/v1/auth/register", new { email, password = "first-password" }, timeout.Token);
        var second = client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = $"  {email.ToUpperInvariant()}  ", password = "second-password" }, timeout.Token);
        await WaitForBlockedRegistrationsAsync(timeout.Token);
        await transaction.CommitAsync(timeout.Token);
        using var firstResponse = await first;
        using var secondResponse = await second;
        var firstWon = firstResponse.StatusCode == HttpStatusCode.Created;
        var winner = firstWon ? firstResponse : secondResponse;
        var loser = firstWon ? secondResponse : firstResponse;
        Assert.Equal(HttpStatusCode.Created, winner.StatusCode);
        await AssertErrorAsync(loser, HttpStatusCode.Conflict, "email-taken", "email");
        var account = await ReadAccountAsync(winner);
        Assert.Equal(email, account.Email);
        Assert.True(account.IsNew);
        await AssertOnlyRegisteredAccountAsync(account.IdentityId);

        var winningPassword = firstWon ? "first-password" : "second-password";
        var losingPassword = firstWon ? "second-password" : "first-password";
        using var rejectedLogin = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email, password = losingPassword });
        await AssertErrorAsync(rejectedLogin, HttpStatusCode.Unauthorized, "invalid-credentials");
        Assert.Equal(account.IdentityId, (await LoginAsync(client, email, winningPassword)).IdentityId);
        await AssertSessionActiveAsync(client, account.Token);
    }

    [Theory]
    [InlineData(PostgresErrorCodes.CheckViolation)]
    [InlineData(PostgresErrorCodes.UniqueViolation)]
    public async Task Register_UnexpectedDatabaseFailureRollsBackTheAccountAndAllowsRetry(string sqlState)
    {
        var email = NewEmail();
        await using (var fault = await PostgreSqlInsertFault.CreateAsync(
            database.ConnectionString, "registration_contexts", environmentId, sqlState))
        {
            Assert.False(await fault.WasTriggeredAsync());

            using var rejected = await client.PostAsJsonAsync(
                "/v1/auth/register", new { email, password = "password-123" });

            Assert.True(await fault.WasTriggeredAsync());
            Assert.Equal(HttpStatusCode.InternalServerError, rejected.StatusCode);
            await AssertEmptyRegistrationAsync();
        }

        var retried = await RegisterAsync(client, email, "password-123");
        await AssertOnlyRegisteredAccountAsync(retried.IdentityId);
        var login = await LoginAsync(client, email, "password-123");
        Assert.Equal(retried.IdentityId, login.IdentityId);
        await AssertSessionActiveAsync(client, retried.Token);
    }

    [Fact]
    public async Task Login_SessionInsertFailurePreservesTheAccountAndAllowsRetry()
    {
        var account = await RegisterAsync(client, NewEmail(), "password-123");
        var credentialBefore = await ReadPasswordCredentialAsync(account.IdentityId);
        await using (var fault = await PostgreSqlInsertFault.CreateAsync(
            database.ConnectionString, "identity_sessions", environmentId))
        {
            Assert.False(await fault.WasTriggeredAsync());

            using var rejected = await client.PostAsJsonAsync(
                "/v1/auth/login", new { email = account.Email, password = "password-123" });

            Assert.True(await fault.WasTriggeredAsync());
            Assert.Equal(HttpStatusCode.InternalServerError, rejected.StatusCode);
            await AssertOnlyRegisteredAccountAsync(account.IdentityId);
            var credentialAfter = await ReadPasswordCredentialAsync(account.IdentityId);
            Assert.Equal(credentialBefore.PasswordHash, credentialAfter.PasswordHash);
            Assert.Equal(credentialBefore.UpdatedAt, credentialAfter.UpdatedAt);
            await AssertSessionActiveAsync(client, account.Token);
        }

        var retried = await LoginAsync(client, account.Email, "password-123");
        Assert.Equal(account.IdentityId, retried.IdentityId);
        Assert.NotEqual(account.Token, retried.Token);
        await AssertSessionActiveAsync(client, retried.Token);
        await AssertSessionActiveAsync(client, account.Token);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var sessions = await db.IdentitySessions.AsNoTracking()
            .Where(item => item.IdentityId == account.IdentityId).ToArrayAsync();
        Assert.Equal(2, sessions.Length);
        Assert.All(sessions, session => Assert.Null(session.RevokedAt));
    }

    [Fact]
    public async Task Login_AbandonedIdentityCannotIssueASessionWithItsStillValidPassword()
    {
        await ConfigurePrimaryPolicyAsync(TestAccessPolicies.Create());
        var account = await RegisterAsync(client, NewEmail(), "password-123");
        var before = await LoginAsync(client, account.Email, "password-123");
        Assert.Equal(account.IdentityId, before.IdentityId);
        Assert.Equal("registration", before.Purpose);
        var credentialBefore = await ReadPasswordCredentialAsync(account.IdentityId);
        await using (var setupScope = api.Services.CreateAsyncScope())
        {
            var db = setupScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identity = await db.Identities.SingleAsync(item => item.Id == account.IdentityId);
            // Preserve identifiers and credentials so lifecycle state is the only reason for rejection.
            identity.Abandon();
            await db.SaveChangesAsync();
        }

        using var rejected = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = account.Email, password = "password-123" });

        await AssertInvalidCredentialsAsync(rejected);
        var credentialAfter = await ReadPasswordCredentialAsync(account.IdentityId);
        Assert.Equal(credentialBefore.PasswordHash, credentialAfter.PasswordHash);
        Assert.Equal(credentialBefore.UpdatedAt, credentialAfter.UpdatedAt);
        await using var verificationScope = api.Services.CreateAsyncScope();
        var verification = verificationScope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var storedIdentity = await verification.Identities.AsNoTracking()
            .SingleAsync(item => item.Id == account.IdentityId);
        Assert.Equal(IdentityLifecycleState.Abandoned, storedIdentity.LifecycleState);
        var identifier = await verification.IdentityIdentifiers.AsNoTracking()
            .SingleAsync(item => item.IdentityId == account.IdentityId && item.Scheme == IdentifierScheme.Email);
        Assert.Equal(account.Email, identifier.NormalizedValue);
        var sessions = await verification.IdentitySessions.AsNoTracking()
            .Where(item => item.IdentityId == account.IdentityId).ToArrayAsync();
        Assert.Equal(2, sessions.Length);
        Assert.All(sessions, session => Assert.Null(session.RevokedAt));
    }

    [Fact]
    public async Task Register_AnotherEnvironmentInTheSameRealmCannotReplaceExistingCredentials()
    {
        var email = NewEmail();
        var account = await RegisterAsync(client, email, "original-password");

        using var duplicate = await secondaryClient.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = $"  {email.ToUpperInvariant()}  ", password = "replacement-password" });

        await AssertErrorAsync(duplicate, HttpStatusCode.Conflict, "email-taken", "email");
        await AssertOnlyRegisteredAccountAsync(account.IdentityId);
        using var replacementLogin = await secondaryClient.PostAsJsonAsync(
            "/v1/auth/login", new { email, password = "replacement-password" });
        await AssertErrorAsync(replacementLogin, HttpStatusCode.Unauthorized, "invalid-credentials");
        var secondary = await LoginAsync(secondaryClient, email, "original-password");
        Assert.Equal(account.IdentityId, secondary.IdentityId);
        Assert.NotEqual(account.Token, secondary.Token);
        await AssertSessionActiveAsync(client, account.Token);
        await AssertSessionActiveAsync(secondaryClient, secondary.Token);
    }

    [Fact]
    public async Task Register_IndependentRealmsCanUseTheSameEmailWithoutSharingPasswords()
    {
        var email = NewEmail();
        var first = await RegisterAsync(client, email, "first-realm-password");
        using var beforeRegistration = await isolatedClient.PostAsJsonAsync(
            "/v1/auth/login", new { email, password = "first-realm-password" });
        await AssertErrorAsync(beforeRegistration, HttpStatusCode.Unauthorized, "invalid-credentials");

        var second = await RegisterAsync(isolatedClient, email, "second-realm-password");

        Assert.NotEqual(first.IdentityId, second.IdentityId);
        using var wrongFirst = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email, password = "second-realm-password" });
        using var wrongSecond = await isolatedClient.PostAsJsonAsync(
            "/v1/auth/login", new { email, password = "first-realm-password" });
        await AssertErrorAsync(wrongFirst, HttpStatusCode.Unauthorized, "invalid-credentials");
        await AssertErrorAsync(wrongSecond, HttpStatusCode.Unauthorized, "invalid-credentials");
        Assert.Equal(first.IdentityId, (await LoginAsync(client, email, "first-realm-password")).IdentityId);
        Assert.Equal(second.IdentityId, (await LoginAsync(isolatedClient, email, "second-realm-password")).IdentityId);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var identifiers = await db.IdentityIdentifiers.AsNoTracking()
            .Where(item => item.Scheme == IdentifierScheme.Email && item.NormalizedValue == email)
            .ToArrayAsync();
        Assert.Equal(2, identifiers.Length);
        Assert.Contains(identifiers, item => item.RealmId == realmId && item.IdentityId == first.IdentityId);
        Assert.Contains(identifiers, item => item.RealmId == isolatedRealmId && item.IdentityId == second.IdentityId);
    }

    [Theory]
    [InlineData("google")]
    [InlineData("apple")]
    public async Task Register_EmailOwnedBySocialIdentityCannotBeClaimedWithANewPassword(string provider)
    {
        var email = NewEmail();
        var subject = Guid.NewGuid().ToString("N");
        api.GoogleValidator.Assertion = new(email, subject, "Existing social owner");
        api.AppleValidator.Assertion = new(email, subject, "Existing social owner");
        object assertion = provider == "google"
            ? new { idToken = "google-token" }
            : new { identityToken = "apple-token" };
        using var socialResponse = await client.PostAsJsonAsync($"/v1/auth/{provider}", assertion);
        Assert.Equal(HttpStatusCode.OK, socialResponse.StatusCode);
        var social = await ReadAccountAsync(socialResponse);

        using var registration = await client.PostAsJsonAsync(
            "/v1/auth/register", new { email, password = "claimant-password" });

        await AssertErrorAsync(registration, HttpStatusCode.Conflict, "email-taken", "email");
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identity = await db.Identities.AsNoTracking().SingleAsync(item => item.RealmId == realmId);
            Assert.Equal(social.IdentityId, identity.Id);
            Assert.False(await db.PasswordCredentials.AnyAsync(item => item.IdentityId == social.IdentityId));
            var credential = await db.SocialCredentials.AsNoTracking().SingleAsync(item => item.RealmId == realmId);
            Assert.Equal(social.IdentityId, credential.IdentityId);
            Assert.Equal(provider, credential.Provider);
            Assert.Single(await db.RegistrationContexts.AsNoTracking()
                .Where(item => item.RealmId == realmId).ToArrayAsync());
            Assert.Single(await db.IdentitySessions.AsNoTracking()
                .Where(item => item.AppEnvironmentId == environmentId).ToArrayAsync());
        }
        using var passwordLogin = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email, password = "claimant-password" });
        await AssertErrorAsync(passwordLogin, HttpStatusCode.Unauthorized, "invalid-credentials");
        using var providerLogin = await client.PostAsJsonAsync($"/v1/auth/{provider}", assertion);
        Assert.Equal(HttpStatusCode.OK, providerLogin.StatusCode);
        var returning = await ReadAccountAsync(providerLogin);
        Assert.Equal(social.IdentityId, returning.IdentityId);
        Assert.False(returning.IsNew);
        using var providerBody = JsonDocument.Parse(await providerLogin.Content.ReadAsStringAsync());
        Assert.False(providerBody.RootElement.GetProperty("hasPassword").GetBoolean());
        await AssertSessionActiveAsync(client, social.Token);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task Login_DisablingAccessOnlyBlocksTheConfiguredEnvironment(
        bool emailEnabled,
        bool passwordEnabled)
    {
        var account = await RegisterAsync(client, NewEmail(), "original-password");
        await ConfigurePrimaryPolicyAsync(TestAccessPolicies.Create(
            emailEnabled: emailEnabled,
            emailRequired: emailEnabled,
            passwordEnabled: passwordEnabled,
            phoneEnabled: false,
            phoneVerificationEnabled: false,
            googleEnabled: true,
            appleEnabled: true));

        using var rejected = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = account.Email, password = "original-password" });

        await AssertErrorAsync(rejected, HttpStatusCode.Conflict, "authenticator-disabled");
        await AssertOnlyRegisteredAccountAsync(account.IdentityId);

        var secondary = await LoginAsync(secondaryClient, account.Email, "original-password");
        Assert.Equal(account.IdentityId, secondary.IdentityId);
        await AssertSessionActiveAsync(secondaryClient, secondary.Token);
        using var stillDisabled = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = account.Email, password = "original-password" });
        await AssertErrorAsync(stillDisabled, HttpStatusCode.Conflict, "authenticator-disabled");
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var sessions = await db.IdentitySessions.AsNoTracking()
                .Where(item => item.IdentityId == account.IdentityId).ToArrayAsync();
            Assert.Equal(2, sessions.Length);
            Assert.Single(sessions, item => item.AppEnvironmentId == environmentId);
            Assert.Single(sessions, item => item.AppEnvironmentId == secondaryEnvironmentId);
        }

        await ConfigurePrimaryPolicyAsync(DefaultPolicy());
        var restored = await LoginAsync(client, account.Email, "original-password");
        Assert.Equal(account.IdentityId, restored.IdentityId);
        Assert.False(restored.IsNew);
        await AssertSessionActiveAsync(client, restored.Token);
    }

    [Theory]
    [InlineData(null, "original-password")]
    [InlineData("", "original-password")]
    [InlineData("   ", "original-password")]
    [InlineData("not-an-email", "original-password")]
    [InlineData("oversized", "original-password")]
    [InlineData("unknown@example.test", "original-password")]
    [InlineData("existing", null)]
    [InlineData("existing", "")]
    [InlineData("existing", "        ")]
    [InlineData("existing", "wrong-password")]
    public async Task Login_InvalidCredentialsReturnTheSameResponseWithoutChangingTheAccount(
        string? emailInput,
        string? password)
    {
        var account = await RegisterAsync(client, NewEmail(), "original-password");
        var credentialBefore = await ReadPasswordCredentialAsync(account.IdentityId);
        using var wrongPassword = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = account.Email, password = "wrong-password" });
        var expectedResponse = await AssertInvalidCredentialsAsync(wrongPassword);
        var email = emailInput switch
        {
            "existing" => account.Email,
            "oversized" => OversizedEmail(),
            _ => emailInput,
        };

        using var rejected = await client.PostAsJsonAsync("/v1/auth/login", new { email, password });

        var actualResponse = await AssertInvalidCredentialsAsync(rejected);
        Assert.Equal(expectedResponse, actualResponse);
        await AssertOnlyRegisteredAccountAsync(account.IdentityId);
        var credentialAfter = await ReadPasswordCredentialAsync(account.IdentityId);
        Assert.Equal(credentialBefore.PasswordHash, credentialAfter.PasswordHash);
        Assert.Equal(credentialBefore.UpdatedAt, credentialAfter.UpdatedAt);
        await AssertSessionActiveAsync(client, account.Token);
        var corrected = await LoginAsync(client, account.Email, "original-password");
        Assert.Equal(account.IdentityId, corrected.IdentityId);
    }

    [Theory]
    [InlineData(PasswordHasherCompatibilityMode.IdentityV2, true)]
    [InlineData(PasswordHasherCompatibilityMode.IdentityV2, false)]
    [InlineData(PasswordHasherCompatibilityMode.IdentityV3, true)]
    [InlineData(PasswordHasherCompatibilityMode.IdentityV3, false)]
    public async Task Login_OnlyAcceptsTheCorrectPasswordForAnOlderHash(
        PasswordHasherCompatibilityMode compatibilityMode,
        bool correctPassword)
    {
        var account = await RegisterAsync(client, NewEmail(), "original-password");
        var oldHasher = new PasswordHasher<object>(Options.Create(new PasswordHasherOptions
        {
            CompatibilityMode = compatibilityMode,
            IterationCount = 10_000,
        }));
        var marker = new object();
        var oldHash = oldHasher.HashPassword(marker, "original-password");
        // Prove this fixture reaches the compatibility result rather than ordinary success.
        var currentHasher = new PasswordHasher<object>();
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded,
            currentHasher.VerifyHashedPassword(marker, oldHash, "original-password"));
        Assert.Equal(PasswordVerificationResult.Failed,
            currentHasher.VerifyHashedPassword(marker, oldHash, "wrong-password"));
        await using (var seedScope = api.Services.CreateAsyncScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var credential = await db.PasswordCredentials.SingleAsync(item => item.IdentityId == account.IdentityId);
            credential.Replace(oldHash, DateTimeOffset.UtcNow);
            await db.SaveChangesAsync();
        }
        var credentialBefore = await ReadPasswordCredentialAsync(account.IdentityId);

        using var response = await client.PostAsJsonAsync("/v1/auth/login", new
        {
            email = account.Email,
            password = correctPassword ? "original-password" : "wrong-password",
        });

        if (correctPassword)
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var login = await ReadAccountAsync(response);
            Assert.Equal(account.IdentityId, login.IdentityId);
            Assert.Equal("product", login.Purpose);
            Assert.False(login.IsNew);
            Assert.NotEqual(account.Token, login.Token);
            await AssertSessionActiveAsync(client, login.Token);
        }
        else
        {
            await AssertInvalidCredentialsAsync(response);
            await AssertOnlyRegisteredAccountAsync(account.IdentityId);
        }
        var credentialAfter = await ReadPasswordCredentialAsync(account.IdentityId);
        Assert.Equal(oldHash, credentialAfter.PasswordHash);
        Assert.Equal(credentialBefore.UpdatedAt, credentialAfter.UpdatedAt);
        await AssertSessionActiveAsync(client, account.Token);
    }

    [Fact]
    public async Task Login_ResumesRegistrationUntilTheFlowCompletes()
    {
        await ConfigurePrimaryPolicyAsync(TestAccessPolicies.Create());
        var account = await RegisterAsync(client, NewEmail(), "password-123");
        Assert.Equal("registration", account.Purpose);
        var resumed = await LoginAsync(client, account.Email, "password-123");
        Assert.Equal(account.IdentityId, resumed.IdentityId);
        Assert.Equal("registration", resumed.Purpose);
        Assert.False(resumed.IsNew);
        using var started = await client.PostAsJsonAsync("/v1/access/flows", new
        {
            requestId = Guid.NewGuid(),
            protocolVersions = new[] { 1 },
            intent = "continueRegistration",
            applicationClientKey = "android-debug",
            sessionToken = resumed.Token,
        });
        Assert.Equal(HttpStatusCode.Created, started.StatusCode);
        using var startBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        var snapshot = startBody.RootElement.GetProperty("snapshot");
        var flowId = snapshot.GetProperty("flowId").GetGuid();
        var skip = Assert.Single(snapshot.GetProperty("actions").EnumerateArray(),
            item => item.GetProperty("type").GetString() == "skipRegistration");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/v1/access/flows/{flowId:D}/actions")
        {
            Content = JsonContent.Create(new
            {
                requestId = Guid.NewGuid(),
                expectedRevision = snapshot.GetProperty("revision").GetInt32(),
                action = new { id = skip.GetProperty("id").GetGuid(), type = "skipRegistration" },
            }),
        };
        request.Headers.Add("Bullgate-Flow-Capability", startBody.RootElement.GetProperty("flowCapability").GetString());

        using var completed = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);
        var returning = await LoginAsync(client, account.Email, "password-123");
        Assert.Equal(account.IdentityId, returning.IdentityId);
        Assert.Equal("product", returning.Purpose);
        Assert.False(returning.IsNew);
        await AssertSessionActiveAsync(client, account.Token, false);
        await AssertSessionActiveAsync(client, resumed.Token, false);
        await AssertSessionActiveAsync(client, returning.Token);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var context = await db.RegistrationContexts.AsNoTracking()
            .SingleAsync(item => item.IdentityId == account.IdentityId);
        Assert.Equal(RegistrationContextStatus.Completed, context.Status);
        Assert.NotNull(context.ClosedAt);
    }

    [Fact]
    public async Task Login_OpenRegistrationInAnotherEnvironmentDoesNotChangeItsSessionPurpose()
    {
        await ConfigurePrimaryPolicyAsync(TestAccessPolicies.Create());
        var account = await RegisterAsync(client, NewEmail(), "password-123");
        Assert.Equal("registration", account.Purpose);

        var secondary = await LoginAsync(secondaryClient, account.Email, "password-123");

        Assert.Equal(account.IdentityId, secondary.IdentityId);
        Assert.Equal("product", secondary.Purpose);
        Assert.False(secondary.IsNew);
        var primary = await LoginAsync(client, account.Email, "password-123");
        Assert.Equal("registration", primary.Purpose);
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var context = await db.RegistrationContexts.AsNoTracking()
            .SingleAsync(item => item.IdentityId == account.IdentityId);
        Assert.Equal(environmentId, context.AppEnvironmentId);
        Assert.Equal(RegistrationContextStatus.Open, context.Status);
        Assert.Null(context.ClosedAt);
        var secondarySession = await db.IdentitySessions.AsNoTracking().SingleAsync(item =>
            item.IdentityId == account.IdentityId && item.AppEnvironmentId == secondaryEnvironmentId);
        Assert.Equal(IdentitySessionPurpose.Product, secondarySession.Purpose);
    }

    [Fact]
    public async Task Login_ReturnsProviderContactsFromTheCurrentIdentityOnly()
    {
        var other = await RegisterAsync(client, NewEmail(), "password-123");
        var otherProviders = await LinkProvidersAsync(other);
        var account = await RegisterAsync(client, NewEmail(), "password-123");
        var providers = await LinkProvidersAsync(account);

        var snapshot = await ReadLoginSnapshotAsync(account);

        AssertLoginProviders(snapshot, account, providers.GoogleEmail, providers.AppleEmail);
        var otherSnapshot = await ReadLoginSnapshotAsync(other);
        AssertLoginProviders(otherSnapshot, other, otherProviders.GoogleEmail, otherProviders.AppleEmail);
    }

    [Theory]
    [InlineData("google")]
    [InlineData("apple")]
    public async Task Login_UnlinkedProviderDisappearsEvenWhenAnotherIdentityStillHasIt(string provider)
    {
        var other = await RegisterAsync(client, NewEmail(), "password-123");
        var otherProviders = await LinkProvidersAsync(other);
        var account = await RegisterAsync(client, NewEmail(), "password-123");
        var providers = await LinkProvidersAsync(account);
        var before = await ReadLoginSnapshotAsync(account);
        AssertLoginProviders(before, account, providers.GoogleEmail, providers.AppleEmail);

        using var unlinked = await client.PostAsJsonAsync(
            $"/v1/account/social/{provider}/unlink", new { sessionToken = account.Token });

        Assert.Equal(HttpStatusCode.OK, unlinked.StatusCode);
        var after = await ReadLoginSnapshotAsync(account);
        AssertLoginProviders(after, account,
            provider == "google" ? null : providers.GoogleEmail,
            provider == "apple" ? null : providers.AppleEmail);
        var otherSnapshot = await ReadLoginSnapshotAsync(other);
        AssertLoginProviders(otherSnapshot, other, otherProviders.GoogleEmail, otherProviders.AppleEmail);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Login_PhoneAndVerificationBelongOnlyToTheCurrentIdentity(
        bool hasPhone,
        bool verified)
    {
        const string otherPhone = "+5511987650001";
        const string accountPhone = "+5511987650002";
        var other = await RegisterAsync(client, NewEmail(), "password-123");
        var account = await RegisterAsync(client, NewEmail(), "password-123");
        var verifiedAt = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        await using (var seedScope = api.Services.CreateAsyncScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            db.IdentityIdentifiers.Add(new IdentityIdentifier(
                Guid.CreateVersion7(), other.IdentityId, realmId, IdentifierScheme.Phone,
                otherPhone, verifiedAt, verifiedAt, "sms"));
            if (hasPhone)
            {
                db.IdentityIdentifiers.Add(new IdentityIdentifier(
                    Guid.CreateVersion7(), account.IdentityId, realmId, IdentifierScheme.Phone,
                    accountPhone, verifiedAt, verified ? verifiedAt : null, verified ? "sms" : null));
            }
            await db.SaveChangesAsync();
        }

        var snapshot = await ReadLoginSnapshotAsync(account);

        Assert.Equal(account.IdentityId, snapshot.GetProperty("identityId").GetGuid());
        Assert.Equal(account.Email, snapshot.GetProperty("email").GetString());
        Assert.Equal(hasPhone ? accountPhone : null, snapshot.GetProperty("phone").GetString());
        if (verified)
        {
            Assert.Equal(verifiedAt, snapshot.GetProperty("phoneVerifiedAt").GetDateTimeOffset());
        }
        else
        {
            Assert.Equal(JsonValueKind.Null, snapshot.GetProperty("phoneVerifiedAt").ValueKind);
        }
        var otherSnapshot = await ReadLoginSnapshotAsync(other);
        Assert.Equal(otherPhone, otherSnapshot.GetProperty("phone").GetString());
        Assert.Equal(verifiedAt, otherSnapshot.GetProperty("phoneVerifiedAt").GetDateTimeOffset());
    }

    private async Task<(string GoogleEmail, string AppleEmail)> LinkProvidersAsync(AccountSession account)
    {
        var googleEmail = $"google-{Guid.NewGuid():N}@example.test";
        var appleEmail = $"apple-{Guid.NewGuid():N}@example.test";
        api.GoogleValidator.Assertion = new(googleEmail, Guid.NewGuid().ToString("N"), "Google contact");
        api.AppleValidator.Assertion = new(appleEmail, Guid.NewGuid().ToString("N"), null);
        using var google = await client.PostAsJsonAsync(
            "/v1/account/social/google/link", new { sessionToken = account.Token, idToken = "google-token" });
        Assert.Equal(HttpStatusCode.OK, google.StatusCode);
        using var apple = await client.PostAsJsonAsync(
            "/v1/account/social/apple/link", new { sessionToken = account.Token, identityToken = "apple-token" });
        Assert.Equal(HttpStatusCode.OK, apple.StatusCode);
        return (googleEmail, appleEmail);
    }

    private async Task<JsonElement> ReadLoginSnapshotAsync(AccountSession account)
    {
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email = account.Email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.Clone();
    }

    private static void AssertLoginProviders(
        JsonElement snapshot, AccountSession account, string? googleEmail, string? appleEmail)
    {
        Assert.Equal(account.IdentityId, snapshot.GetProperty("identityId").GetGuid());
        Assert.Equal(account.Email, snapshot.GetProperty("email").GetString());
        Assert.True(snapshot.GetProperty("hasPassword").GetBoolean());
        Assert.Equal(googleEmail is not null, snapshot.GetProperty("hasGoogle").GetBoolean());
        Assert.Equal(googleEmail, snapshot.GetProperty("googleEmail").GetString());
        Assert.Equal(appleEmail is not null, snapshot.GetProperty("hasApple").GetBoolean());
        Assert.Equal(appleEmail, snapshot.GetProperty("appleEmail").GetString());
    }

    private static string OversizedEmail()
    {
        const string suffix = "@example.test";
        return new string('a', IdentityLimits.IdentifierValueMaxLength + 1 - suffix.Length) + suffix;
    }

    private async Task WaitForBlockedRegistrationsAsync(CancellationToken cancellationToken)
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
                  AND query ILIKE '%INSERT INTO identities%';
                """;
            if (Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken)) >= 2)
            {
                return;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken);
        }
    }

    private async Task<PasswordCredential> ReadPasswordCredentialAsync(Guid identityId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        return await db.PasswordCredentials.AsNoTracking().SingleAsync(item => item.IdentityId == identityId);
    }

    private static async Task<string> AssertInvalidCredentialsAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        using var body = JsonDocument.Parse(json);
        Assert.Equal(new[] { "error", "field" },
            body.RootElement.EnumerateObject().Select(item => item.Name).OrderBy(name => name).ToArray());
        Assert.Equal("invalid-credentials", body.RootElement.GetProperty("error").GetString());
        Assert.Equal(JsonValueKind.Null, body.RootElement.GetProperty("field").ValueKind);
        return json;
    }

    private async Task AssertEmptyRegistrationAsync()
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await db.Identities.AnyAsync(item => item.RealmId == realmId));
        Assert.False(await db.IdentityIdentifiers.AnyAsync(item => item.RealmId == realmId));
        Assert.False(await db.RegistrationContexts.AnyAsync(item => item.AppEnvironmentId == environmentId));
        Assert.False(await db.IdentitySessions.AnyAsync(item => item.AppEnvironmentId == environmentId));
    }

    private async Task AssertOnlyRegisteredAccountAsync(Guid identityId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var identity = await db.Identities.AsNoTracking().SingleAsync(item => item.RealmId == realmId);
        Assert.Equal(identityId, identity.Id);
        var identifier = await db.IdentityIdentifiers.AsNoTracking()
            .SingleAsync(item => item.RealmId == realmId);
        Assert.Equal(identityId, identifier.IdentityId);
        Assert.Equal(IdentifierScheme.Email, identifier.Scheme);
        Assert.True(await db.PasswordCredentials.AnyAsync(item => item.IdentityId == identityId));
        var context = await db.RegistrationContexts.AsNoTracking()
            .SingleAsync(item => item.RealmId == realmId);
        Assert.Equal(identityId, context.IdentityId);
        Assert.Equal(environmentId, context.AppEnvironmentId);
        Assert.Equal(RegistrationContextStatus.Completed, context.Status);
        var session = await db.IdentitySessions.AsNoTracking().SingleAsync(item =>
            item.AppEnvironmentId == environmentId || item.AppEnvironmentId == secondaryEnvironmentId);
        Assert.Equal(identityId, session.IdentityId);
        Assert.Equal(environmentId, session.AppEnvironmentId);
        Assert.Equal(IdentitySessionPurpose.Product, session.Purpose);
        Assert.Null(session.RevokedAt);
    }

    private async Task AssertSessionActiveAsync(HttpClient caller, string token, bool expectedActive = true)
    {
        using var response = await caller.PostAsJsonAsync(
            "/v1/auth/session/introspect", new { sessionToken = token });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(expectedActive, body.RootElement.GetProperty("active").GetBoolean());
    }

    private static async Task AssertErrorAsync(
        HttpResponseMessage response, HttpStatusCode status, string error, string? field = null)
    {
        Assert.Equal(status, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(error, body.RootElement.GetProperty("error").GetString());
        if (field is not null)
        {
            Assert.Equal(field, body.RootElement.GetProperty("field").GetString());
        }
        Assert.False(body.RootElement.TryGetProperty("identityId", out _));
        Assert.False(body.RootElement.TryGetProperty("sessionToken", out _));
    }

    private static async Task<AccountSession> RegisterAsync(HttpClient caller, string email, string password)
    {
        using var response = await caller.PostAsJsonAsync("/v1/auth/register", new { email, password });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var account = await ReadAccountAsync(response);
        Assert.True(account.IsNew);
        return account;
    }

    private static async Task<AccountSession> LoginAsync(HttpClient caller, string email, string password)
    {
        using var response = await caller.PostAsJsonAsync("/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var account = await ReadAccountAsync(response);
        Assert.False(account.IsNew);
        return account;
    }

    private static async Task<AccountSession> ReadAccountAsync(HttpResponseMessage response)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        return new AccountSession(
            root.GetProperty("identityId").GetGuid(),
            Assert.IsType<string>(root.GetProperty("email").GetString()),
            Assert.IsType<string>(root.GetProperty("sessionToken").GetString()),
            Assert.IsType<string>(root.GetProperty("sessionPurpose").GetString()),
            root.GetProperty("isNew").GetBoolean());
    }

    private async Task ConfigurePrimaryPolicyAsync(AppAccessPolicy policy)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var bootstrap = await scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>()
            .HandleAsync(CreateBootstrapCommand(topologySuffix, policy));
        Assert.Empty(bootstrap.IssuedCredentials);
    }

    private HttpClient CreateClient(BootstrapTopologyResult bootstrap, string environment)
    {
        var credential = bootstrap.IssuedCredentials.Single(item =>
            item.IntegrationClientPath.EndsWith($"/{environment}/integration-clients/api", StringComparison.Ordinal));
        var result = api.CreateClient();
        result.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential.Token);
        return result;
    }

    private static Guid FindResource(BootstrapTopologyResult bootstrap, string type, string pathSuffix) =>
        bootstrap.Resources.Single(item => item.Type == type
            && item.Path.EndsWith(pathSuffix, StringComparison.Ordinal)).Id;

    private static string NewEmail() => $"registration-boundary-{Guid.NewGuid():N}@example.test";

    private static AppAccessPolicy DefaultPolicy() => TestAccessPolicies.Create(
        phoneEnabled: false, phoneVerificationEnabled: false, googleEnabled: true, appleEnabled: true);

    private static BootstrapTopologyCommand CreateBootstrapCommand(string suffix, AppAccessPolicy? primaryPolicy = null)
    {
        BootstrapEnvironmentDefinition Environment(string key, string realm, AppAccessPolicy policy) => new(
            key, key, realm, policy,
            TestEnvironmentConfigurations.VerificationPolicy,
            TestEnvironmentConfigurations.RecoveryPolicy(),
            TestEnvironmentConfigurations.Providers(policy),
            TestEnvironmentConfigurations.DevelopmentBypass(policy),
            [new("api", "API",
                [AccessPermission.ExecuteFlows, AccessPermission.IntrospectSessions, AccessPermission.ManageCurrentIdentity])],
            [
                new BootstrapApplicationClientDefinition("android-debug", "Android debug",
                    ApplicationClientPlatform.Android, "app.baybo",
                    "sha256:fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
                    "92TvTC0UfaA", JsonSerializer.SerializeToElement(new { })),
            ]);

        return new BootstrapTopologyCommand($"registration-boundaries-{suffix}", "Registration boundary tests",
            [
                new BootstrapAppDefinition("app", "App",
                    [new("shared", "Shared identities"), new("isolated", "Isolated identities")],
                    [
                        Environment("primary", "shared", primaryPolicy ?? DefaultPolicy()),
                        Environment("secondary", "shared", DefaultPolicy()),
                        Environment("isolated", "isolated", DefaultPolicy()),
                    ]),
            ]);
    }

    private sealed record AccountSession(Guid IdentityId, string Email, string Token, string Purpose, bool IsNew);
}
