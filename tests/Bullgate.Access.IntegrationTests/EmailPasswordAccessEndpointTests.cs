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

public sealed class EmailPasswordAccessEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private string topologySuffix = null!;
    private Guid realmId;
    private Guid appEnvironmentId;

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
            topologySuffix = Guid.NewGuid().ToString("N");
            bootstrap = await handler.HandleAsync(CreateBootstrapCommand(topologySuffix));
        }

        var credential = Assert.Single(bootstrap.IssuedCredentials);
        realmId = bootstrap.Resources.Single(resource => resource.Type == "realm").Id;
        appEnvironmentId = bootstrap.Resources.Single(resource => resource.Type == "environment").Id;
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
    public async Task Register_PersistsQueryableEmail_AndIssuesIntrospectableSession()
    {
        var response = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = "  Person@Example.COM  ", password = "password-123" });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        var identityId = root.GetProperty("identityId").GetGuid();
        var sessionToken = root.GetProperty("sessionToken").GetString();
        Assert.Equal("person@example.com", root.GetProperty("email").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("phone").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("phoneVerifiedAt").ValueKind);
        Assert.Equal(
            "registration",
            root.GetProperty("sessionPurpose").GetString());
        Assert.True(root.GetProperty("isNew").GetBoolean());
        Assert.StartsWith("bgs_", sessionToken, StringComparison.Ordinal);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identifier = await dbContext.IdentityIdentifiers
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);

            Assert.Equal(IdentifierScheme.Email, identifier.Scheme);
            Assert.Equal("person@example.com", identifier.NormalizedValue);

            var registrationContext = await dbContext.RegistrationContexts
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.Equal(RegistrationContextStatus.Open, registrationContext.Status);

            var phoneVerifiedAt = new DateTimeOffset(
                2026,
                9,
                2,
                20,
                0,
                0,
                TimeSpan.Zero);
            dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
                Guid.CreateVersion7(),
                identityId,
                identifier.RealmId,
                IdentifierScheme.Phone,
                "+5511987654321",
                phoneVerifiedAt,
                phoneVerifiedAt,
                "sms"));
            await dbContext.SaveChangesAsync();
        }

        var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken });

        Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);
        using var introspectionBody = JsonDocument.Parse(
            await introspection.Content.ReadAsStringAsync());
        var introspectionRoot = introspectionBody.RootElement;
        Assert.True(introspectionRoot.GetProperty("active").GetBoolean());
        Assert.Equal(identityId, introspectionRoot.GetProperty("identityId").GetGuid());
        Assert.Equal(
            "person@example.com",
            introspectionRoot.GetProperty("email").GetString());
        Assert.Equal(
            "+5511987654321",
            introspectionRoot.GetProperty("phone").GetString());
        Assert.Equal(
            new DateTimeOffset(2026, 9, 2, 20, 0, 0, TimeSpan.Zero),
            introspectionRoot.GetProperty("phoneVerifiedAt").GetDateTimeOffset());
        Assert.Equal(
            "registration",
            introspectionRoot.GetProperty("sessionPurpose").GetString());
    }

    [Fact]
    public async Task Login_UsesNormalizedEmail_AndReturnsOnlyGenericCredentialFailure()
    {
        var email = $"login-{Guid.NewGuid():N}@example.com";
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using (var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync()))
        {
            var identityId = registrationBody.RootElement
                .GetProperty("identityId")
                .GetGuid();
            await using var scope = api.Services.CreateAsyncScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var realmId = await dbContext.Identities
                .Where(identity => identity.Id == identityId)
                .Select(identity => identity.RealmId)
                .SingleAsync();
            dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
                Guid.CreateVersion7(),
                identityId,
                realmId,
                IdentifierScheme.Phone,
                "+5511976543210",
                DateTimeOffset.UtcNow));
            await dbContext.SaveChangesAsync();
        }

        var rejected = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = email.ToUpperInvariant(), password = "wrong-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        using (var rejectedBody = JsonDocument.Parse(
            await rejected.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "invalid-credentials",
                rejectedBody.RootElement.GetProperty("error").GetString());
        }

        var accepted = await client.PostAsJsonAsync(
            "/v1/auth/login",
            new { email = $" {email.ToUpperInvariant()} ", password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        using var acceptedBody = JsonDocument.Parse(await accepted.Content.ReadAsStringAsync());
        Assert.Equal(email, acceptedBody.RootElement.GetProperty("email").GetString());
        Assert.Equal(
            "+5511976543210",
            acceptedBody.RootElement.GetProperty("phone").GetString());
        Assert.Equal(
            JsonValueKind.Null,
            acceptedBody.RootElement.GetProperty("phoneVerifiedAt").ValueKind);
        Assert.Equal(
            "registration",
            acceptedBody.RootElement.GetProperty("sessionPurpose").GetString());
        Assert.False(acceptedBody.RootElement.GetProperty("isNew").GetBoolean());
    }

    [Fact]
    public async Task RevokeCurrentSession_MakesThePresentedSessionInactive()
    {
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"logout-{Guid.NewGuid():N}@example.com",
                password = "password-123",
            });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);

        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());
        var sessionToken = registrationBody.RootElement
            .GetProperty("sessionToken")
            .GetString();

        var revoke = await client.PostAsJsonAsync(
            "/v1/auth/session/revoke",
            new { sessionToken });
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        var introspection = await client.PostAsJsonAsync(
            "/v1/auth/session/introspect",
            new { sessionToken });
        Assert.Equal(HttpStatusCode.OK, introspection.StatusCode);

        using var introspectionBody = JsonDocument.Parse(
            await introspection.Content.ReadAsStringAsync());
        Assert.False(introspectionBody.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Register_RejectsDuplicateEmail_AndShortPasswordWithStableErrors()
    {
        var email = $"duplicate-{Guid.NewGuid():N}@example.com";
        var first = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var duplicate = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = email.ToUpperInvariant(), password = "password-123" });
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
        using (var duplicateBody = JsonDocument.Parse(
            await duplicate.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                "email-taken",
                duplicateBody.RootElement.GetProperty("error").GetString());
        }

        var tooShort = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email = $"short-{Guid.NewGuid():N}@example.com", password = "1234567" });
        Assert.Equal(HttpStatusCode.BadRequest, tooShort.StatusCode);
        using var shortBody = JsonDocument.Parse(await tooShort.Content.ReadAsStringAsync());
        Assert.Equal(
            "password-too-short",
            shortBody.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Register_WithoutAnEnabledPhoneStep_IssuesAProductSessionImmediately()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false,
            phoneVerificationEnabled: false));

        var response = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"direct-{Guid.NewGuid():N}@example.com",
                password = "password-123",
            });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;
        var identityId = root.GetProperty("identityId").GetGuid();
        Assert.Equal("product", root.GetProperty("sessionPurpose").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var registrationContext = await dbContext.RegistrationContexts
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(RegistrationContextStatus.Completed, registrationContext.Status);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task Register_DisabledAccessLeavesNoAccountAndAllowsTheSameEmailAfterReactivation(
        bool emailEnabled,
        bool passwordEnabled)
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            emailEnabled: emailEnabled,
            emailRequired: emailEnabled,
            phoneEnabled: false,
            phoneVerificationEnabled: false,
            passwordEnabled: passwordEnabled));

        var email = $"disabled-{Guid.NewGuid():N}@example.com";
        using var response = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email,
                password = "password-123",
            });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "authenticator-disabled",
            body.RootElement.GetProperty("error").GetString());
        await using (var rejectedScope = api.Services.CreateAsyncScope())
        {
            var db = rejectedScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.Identities.AnyAsync(item => item.RealmId == realmId));
            Assert.False(await db.IdentityIdentifiers.AnyAsync(item => item.RealmId == realmId));
            Assert.False(await db.RegistrationContexts.AnyAsync(item => item.AppEnvironmentId == appEnvironmentId));
            Assert.False(await db.IdentitySessions.AnyAsync(item => item.AppEnvironmentId == appEnvironmentId));
        }

        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            phoneEnabled: false, phoneVerificationEnabled: false));
        using var retried = await client.PostAsJsonAsync(
            "/v1/auth/register", new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, retried.StatusCode);
        using var retryBody = JsonDocument.Parse(await retried.Content.ReadAsStringAsync());
        var identityId = retryBody.RootElement.GetProperty("identityId").GetGuid();
        Assert.Equal(email, retryBody.RootElement.GetProperty("email").GetString());
        Assert.True(retryBody.RootElement.GetProperty("isNew").GetBoolean());
        await using (var verificationScope = api.Services.CreateAsyncScope())
        {
            var db = verificationScope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identity = await db.Identities.AsNoTracking().SingleAsync(item => item.RealmId == realmId);
            Assert.Equal(identityId, identity.Id);
            var context = await db.RegistrationContexts.AsNoTracking()
                .SingleAsync(item => item.AppEnvironmentId == appEnvironmentId);
            Assert.Equal(identityId, context.IdentityId);
            Assert.Equal(RegistrationContextStatus.Completed, context.Status);
            var session = await db.IdentitySessions.AsNoTracking()
                .SingleAsync(item => item.AppEnvironmentId == appEnvironmentId);
            Assert.Equal(identityId, session.IdentityId);
        }
        using var login = await client.PostAsJsonAsync(
            "/v1/auth/login", new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var loginBody = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        Assert.Equal(identityId, loginBody.RootElement.GetProperty("identityId").GetGuid());
    }

    private async Task ConfigurePolicyAsync(AppAccessPolicy policy)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
        var result = await handler.HandleAsync(CreateBootstrapCommand(topologySuffix, policy));
        Assert.Empty(result.IssuedCredentials);
    }

    private static BootstrapTopologyCommand CreateBootstrapCommand(
        string suffix,
        AppAccessPolicy? accessPolicy = null) =>
        new(
            $"email-access-{suffix}",
            "Email access tests",
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
                            accessPolicy ?? TestAccessPolicies.Create(),
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(
                                accessPolicy ?? TestAccessPolicies.Create()),
                            TestEnvironmentConfigurations.DevelopmentBypass(
                                accessPolicy ?? TestAccessPolicies.Create()),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "api",
                                    "API",
                                    [
                                        AccessPermission.ExecuteFlows,
                                        AccessPermission.IntrospectSessions,
                                        AccessPermission.RevokeCurrentSession,
                                    ]),
                            ],
                            []),
                    ]),
            ]);
}
