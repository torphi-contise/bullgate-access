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

public sealed class IdentityEmailEndpointTests(PostgreSqlFixture database)
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

        var appPath = $"identity-email-{suffix}/baybo-{suffix}";
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
    public async Task GetEmail_RequiresReadPermission_AndReturnsOnlyTheNormalizedEmail()
    {
        var identityId = await RegisterAsync("  Person@Example.COM  ");

        using var response = await primaryClient.GetAsync(
            $"/v1/identities/{identityId:D}/email");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            var property = Assert.Single(body.RootElement.EnumerateObject());
            Assert.Equal("email", property.Name);
            Assert.Equal("person@example.com", property.Value.GetString());
        }

        using var sameRealmResponse = await sameRealmClient.GetAsync(
            $"/v1/identities/{identityId:D}/email");
        Assert.Equal(HttpStatusCode.OK, sameRealmResponse.StatusCode);

        using var forbidden = await clientWithoutReadPermission.GetAsync(
            $"/v1/identities/{identityId:D}/email");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        using var anonymousClient = api.CreateClient();
        using var unauthorized = await anonymousClient.GetAsync(
            $"/v1/identities/{identityId:D}/email");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
    }

    [Fact]
    public async Task GetEmail_HidesMissingOutOfRealmInactiveAndEmaillessIdentities()
    {
        var identityId = await RegisterAsync($"identity-{Guid.NewGuid():N}@example.com");

        await AssertNotFoundAsync(
            otherRealmClient,
            identityId);
        await AssertNotFoundAsync(
            primaryClient,
            Guid.CreateVersion7());
        await AssertNotFoundAsync(
            primaryClient,
            Guid.Empty);

        var emaillessIdentityId = Guid.CreateVersion7();
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            dbContext.Identities.Add(new Identity(
                emaillessIdentityId,
                primaryRealmId,
                DateTimeOffset.UtcNow));
            await dbContext.SaveChangesAsync();
        }
        await AssertNotFoundAsync(primaryClient, emaillessIdentityId);

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

    // A second e-mail identifier for the same identity is rejected by
    // ux_identity_identifiers_realm_identity_scheme; the ambiguity scenario is
    // covered by CurrentIdentityAccessEndpointTests
    // .IdentityIdentifier_RejectsASecondIdentifierOfTheSameScheme.

    private async Task<Guid> RegisterAsync(string email)
    {
        using var response = await primaryClient.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "password-123" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("identityId").GetGuid();
    }

    private static async Task AssertNotFoundAsync(HttpClient client, Guid identityId)
    {
        using var response = await client.GetAsync(
            $"/v1/identities/{identityId:D}/email");
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
            $"identity-email-{suffix}",
            "Identity email tests",
            [
                new BootstrapAppDefinition(
                    $"baybo-{suffix}",
                    "BAYBO",
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
