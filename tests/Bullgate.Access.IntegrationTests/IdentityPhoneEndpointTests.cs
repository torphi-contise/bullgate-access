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

public sealed class IdentityPhoneEndpointTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private AccessApiFactory api = null!;
    private HttpClient primaryClient = null!;
    private HttpClient sameRealmClient = null!;
    private HttpClient otherRealmClient = null!;
    private HttpClient clientWithoutReadPermission = null!;
    private Guid primaryRealmId;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await dbContext.Database.EnsureCreatedAsync();
        }

        var suffix = Guid.NewGuid().ToString("N");
        BootstrapTopologyResult bootstrap;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            bootstrap = await handler.HandleAsync(CreateBootstrapCommand(suffix));
        }

        var appPath = $"identity-phone-{suffix}/consumer-{suffix}";
        primaryRealmId = FindResource(
            bootstrap,
            "realm",
            $"{appPath}/realms/primary-{suffix}");
        primaryClient = CreateClient(FindCredential(
            bootstrap,
            $"{appPath}/primary/integration-clients/api"));
        clientWithoutReadPermission = CreateClient(FindCredential(
            bootstrap,
            $"{appPath}/primary/integration-clients/no-read"));
        sameRealmClient = CreateClient(FindCredential(
            bootstrap,
            $"{appPath}/same-realm/integration-clients/reader"));
        otherRealmClient = CreateClient(FindCredential(
            bootstrap,
            $"{appPath}/other-realm/integration-clients/reader"));
    }

    public async Task DisposeAsync()
    {
        clientWithoutReadPermission.Dispose();
        otherRealmClient.Dispose();
        sameRealmClient.Dispose();
        primaryClient.Dispose();
        await api.DisposeAsync();
    }

    [Fact]
    public async Task GetPhone_RequiresReadPermission_AndReturnsPhoneWithVerification()
    {
        var identityId = await RegisterAsync();
        var verifiedAt = new DateTimeOffset(
            2026,
            9,
            2,
            20,
            0,
            0,
            TimeSpan.Zero);
        await AddPhoneAsync(identityId, "+5511987654321", verifiedAt);

        using var response = await primaryClient.GetAsync(
            $"/v1/identities/{identityId:D}/phone");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(2, body.RootElement.EnumerateObject().Count());
            Assert.Equal(
                "+5511987654321",
                body.RootElement.GetProperty("phone").GetString());
            Assert.Equal(
                verifiedAt,
                body.RootElement.GetProperty("verifiedAt").GetDateTimeOffset());
        }

        using var sameRealmResponse = await sameRealmClient.GetAsync(
            $"/v1/identities/{identityId:D}/phone");
        Assert.Equal(HttpStatusCode.OK, sameRealmResponse.StatusCode);

        using var forbidden = await clientWithoutReadPermission.GetAsync(
            $"/v1/identities/{identityId:D}/phone");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        using var anonymousClient = api.CreateClient();
        using var unauthorized = await anonymousClient.GetAsync(
            $"/v1/identities/{identityId:D}/phone");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
    }

    [Fact]
    public async Task GetPhone_ReturnsAnUnverifiedPhoneWithNullVerifiedAt()
    {
        var identityId = await RegisterAsync();
        await AddPhoneAsync(identityId, "+5511976543210", null);

        using var response = await primaryClient.GetAsync(
            $"/v1/identities/{identityId:D}/phone");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "+5511976543210",
            body.RootElement.GetProperty("phone").GetString());
        Assert.Equal(
            JsonValueKind.Null,
            body.RootElement.GetProperty("verifiedAt").ValueKind);
    }

    [Fact]
    public async Task GetPhone_HidesMissingOutOfRealmInactiveAndPhonelessIdentities()
    {
        var identityId = await RegisterAsync();
        await AddPhoneAsync(identityId, "+5511965432109", DateTimeOffset.UtcNow);

        await AssertNotFoundAsync(otherRealmClient, identityId);
        await AssertNotFoundAsync(primaryClient, Guid.CreateVersion7());
        await AssertNotFoundAsync(primaryClient, Guid.Empty);

        var identityWithoutPhone = await RegisterAsync();
        await AssertNotFoundAsync(primaryClient, identityWithoutPhone);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identity = await dbContext.Identities.SingleAsync(
                item => item.Id == identityId);
            identity.Abandon();
            await dbContext.SaveChangesAsync();
        }
        await AssertNotFoundAsync(primaryClient, identityId);
    }

    // A second phone identifier for the same identity is rejected by
    // ux_identity_identifiers_realm_identity_scheme; the ambiguity scenario is
    // covered by CurrentIdentityAccessEndpointTests
    // .IdentityIdentifier_RejectsASecondIdentifierOfTheSameScheme.

    private async Task<Guid> RegisterAsync()
    {
        using var response = await primaryClient.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"phone-{Guid.NewGuid():N}@example.com",
                password = "password-123",
            });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("identityId").GetGuid();
    }

    private async Task AddPhoneAsync(
        Guid identityId,
        string phone,
        DateTimeOffset? verifiedAt)
    {
        var createdAt = verifiedAt ?? DateTimeOffset.UtcNow;
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
            Guid.CreateVersion7(),
            identityId,
            primaryRealmId,
            IdentifierScheme.Phone,
            phone,
            createdAt,
            verifiedAt,
            verifiedAt is null ? null : "sms"));
        await dbContext.SaveChangesAsync();
    }

    private static async Task AssertNotFoundAsync(HttpClient client, Guid identityId)
    {
        using var response = await client.GetAsync(
            $"/v1/identities/{identityId:D}/phone");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            "identity-not-found",
            body.RootElement.GetProperty("error").GetString());
    }

    private HttpClient CreateClient(string credential)
    {
        var client = api.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", credential);
        return client;
    }

    private static Guid FindResource(
        BootstrapTopologyResult bootstrap,
        string type,
        string path) =>
        bootstrap.Resources.Single(resource => resource.Type == type && resource.Path == path).Id;

    private static string FindCredential(
        BootstrapTopologyResult bootstrap,
        string path) =>
        bootstrap.IssuedCredentials.Single(
            credential => credential.IntegrationClientPath == path).Token;

    private static BootstrapTopologyCommand CreateBootstrapCommand(string suffix)
    {
        var accessPolicy = TestAccessPolicies.Create(
            phoneEnabled: false,
            phoneVerificationEnabled: false);
        return new BootstrapTopologyCommand(
            $"identity-phone-{suffix}",
            "Identity phone tests",
            [
                new BootstrapAppDefinition(
                    $"consumer-{suffix}",
                    "Consumer",
                    [
                        new BootstrapRealmDefinition(
                            $"primary-{suffix}",
                            "Primary realm"),
                        new BootstrapRealmDefinition(
                            $"other-{suffix}",
                            "Other realm"),
                    ],
                    [
                        new BootstrapEnvironmentDefinition(
                            "primary",
                            "Primary",
                            $"primary-{suffix}",
                            accessPolicy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(accessPolicy),
                            TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "api",
                                    "API",
                                    [
                                        AccessPermission.ExecuteFlows,
                                        AccessPermission.ReadIdentities,
                                    ]),
                                new BootstrapIntegrationClientDefinition(
                                    "no-read",
                                    "No read",
                                    [AccessPermission.ExecuteFlows]),
                            ],
                            []),
                        new BootstrapEnvironmentDefinition(
                            "same-realm",
                            "Same realm",
                            $"primary-{suffix}",
                            accessPolicy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(accessPolicy),
                            TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "reader",
                                    "Reader",
                                    [AccessPermission.ReadIdentities]),
                            ],
                            []),
                        new BootstrapEnvironmentDefinition(
                            "other-realm",
                            "Other realm",
                            $"other-{suffix}",
                            accessPolicy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(accessPolicy),
                            TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "reader",
                                    "Reader",
                                    [AccessPermission.ReadIdentities]),
                            ],
                            []),
                    ]),
            ]);
    }
}
