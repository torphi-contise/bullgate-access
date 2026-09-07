using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class ApplicationClientConfigurationEndpointTests(
    PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private const string ApplicationClientKey = "android-development";
    private AccessApiFactory api = null!;
    private HttpClient firstClient = null!;
    private HttpClient secondClient = null!;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await dbContext.Database.EnsureDeletedAsync();
            await dbContext.Database.EnsureCreatedAsync();
        }

        BootstrapTopologyResult bootstrap;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            bootstrap = await handler.HandleAsync(CreateBootstrapCommand());
        }

        var firstCredential = Assert.Single(
            bootstrap.IssuedCredentials,
            item => item.IntegrationClientPath.EndsWith(
                "/first/integration-clients/api",
                StringComparison.Ordinal));
        var secondCredential = Assert.Single(
            bootstrap.IssuedCredentials,
            item => item.IntegrationClientPath.EndsWith(
                "/second/integration-clients/api",
                StringComparison.Ordinal));
        firstClient = CreateClient(firstCredential.Token);
        secondClient = CreateClient(secondCredential.Token);
    }

    public async Task DisposeAsync()
    {
        firstClient.Dispose();
        secondClient.Dispose();
        await api.DisposeAsync();
    }

    [Fact]
    public async Task Get_ReturnsOnlyTypedAndDeclaredPublicConfigurationWithinCredentialEnvironment()
    {
        using var firstResponse = await firstClient.GetAsync(
            $"/v1/config/application-clients/{ApplicationClientKey}");
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        var firstJson = await firstResponse.Content.ReadAsStringAsync();
        Assert.DoesNotContain("providers", firstJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("keySecret", firstJson, StringComparison.OrdinalIgnoreCase);
        using (var firstBody = JsonDocument.Parse(firstJson))
        {
            var root = firstBody.RootElement;
            Assert.Equal(7, root.GetProperty("configurationVersion").GetInt32());
            Assert.Equal("first", root.GetProperty("common").GetProperty("environment").GetString());
            var client = root.GetProperty("client");
            Assert.Equal(ApplicationClientKey, client.GetProperty("key").GetString());
            Assert.Equal("android", client.GetProperty("platform").GetString());
            Assert.Equal("app.baybo.dev", client.GetProperty("applicationId").GetString());
            Assert.Equal("92TvTC0UfaA", client.GetProperty("smsRetrieverAppHash").GetString());
            Assert.Equal(
                "first",
                client.GetProperty("configuration").GetProperty("channel").GetString());
        }

        using var secondResponse = await secondClient.GetAsync(
            $"/v1/config/application-clients/{ApplicationClientKey}");
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        using var secondBody = JsonDocument.Parse(
            await secondResponse.Content.ReadAsStringAsync());
        Assert.Equal(
            "second",
            secondBody.RootElement.GetProperty("common").GetProperty("environment").GetString());
        Assert.Equal(
            "92TvTC0UfaB",
            secondBody.RootElement.GetProperty("client")
                .GetProperty("smsRetrieverAppHash")
                .GetString());
    }

    [Fact]
    public async Task Get_UnknownOrMalformedKey_ReturnsStableApplicationClientError()
    {
        foreach (var key in new[] { "unknown", "INVALID" })
        {
            using var response = await firstClient.GetAsync(
                $"/v1/config/application-clients/{key}");
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(
                "application-client-invalid",
                body.RootElement.GetProperty("error").GetString());
            Assert.Equal(
                "applicationClientKey",
                body.RootElement.GetProperty("field").GetString());
        }
    }

    [Fact]
    public async Task Get_WithoutIntegrationCredential_ReturnsUnauthorized()
    {
        using var anonymous = api.CreateClient();
        using var response = await anonymous.GetAsync(
            $"/v1/config/application-clients/{ApplicationClientKey}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private HttpClient CreateClient(string token)
    {
        var client = api.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static BootstrapTopologyCommand CreateBootstrapCommand()
    {
        var policy = TestAccessPolicies.Create();
        return new BootstrapTopologyCommand(
            $"configuration-{Guid.NewGuid():N}",
            "Configuration tests",
            [
                new BootstrapAppDefinition(
                    $"baybo-{Guid.NewGuid():N}",
                    "BAYBO",
                    [new BootstrapRealmDefinition("shared-realm", "Shared realm")],
                    [
                        Environment("first", policy, 7, "92TvTC0UfaA"),
                        Environment("second", policy, 8, "92TvTC0UfaB"),
                    ]),
            ]);
    }

    private static BootstrapEnvironmentDefinition Environment(
        string key,
        AppAccessPolicy policy,
        int configurationVersion,
        string appHash) =>
        new(
            key,
            key,
            "shared-realm",
            policy,
            TestEnvironmentConfigurations.VerificationPolicy,
            TestEnvironmentConfigurations.RecoveryPolicy(),
            TestEnvironmentConfigurations.Providers(policy),
            TestEnvironmentConfigurations.DevelopmentBypass(policy),
            new AppEnvironmentPublicConfiguration(
                configurationVersion,
                JsonSerializer.SerializeToElement(new { environment = key })),
            [
                new BootstrapIntegrationClientDefinition(
                    "api",
                    "API",
                    [AccessPermission.ExecuteFlows]),
            ],
            [
                new BootstrapApplicationClientDefinition(
                    ApplicationClientKey,
                    "BAYBO Android development",
                    ApplicationClientPlatform.Android,
                    "app.baybo.dev",
                    $"sha256:{key}",
                    appHash,
                    JsonSerializer.SerializeToElement(new { channel = key })),
            ]);
}
