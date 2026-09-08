using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bullgate.Access.Application.Administration;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

/// <summary>Only disposable PostgreSQL and fake providers; never installation credentials.</summary>
internal sealed class AccessAdministrationTestHost(string connectionString) : IAsyncDisposable
{
    private readonly AccessApiFactory root = new(connectionString);
    internal readonly string Secret = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    internal WebApplicationFactory<Program> Api { get; private set; } = null!;
    internal HttpClient Admin { get; private set; } = null!;
    internal HttpClient Consumer { get; private set; } = null!;
    internal HttpClient SecondaryConsumer { get; private set; } = null!;
    internal Guid RealmId { get; private set; }
    internal Guid EnvironmentId { get; private set; }
    internal Guid SecondaryEnvironmentId { get; private set; }
    internal BootstrapTopologyCommand Command { get; private set; } = null!;
    internal AppEnvironmentConfiguration Configuration => Command.Apps[0].Environments[0].Configuration;
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };
    internal static AdminCallContext Context(string permission) => new("operator-1", "session-1", "scope-1", permission);

    internal async Task InitializeAsync(bool migrate = false)
    {
        if (migrate)
        {
            await using var migration = MigrationContext();
            await migration.Database.MigrateAsync();
            Assert.False(migration.Database.HasPendingModelChanges());
        }
        Api = root.WithWebHostBuilder(builder => builder.UseSetting("Bullgate:Admin:CredentialSha256",
            Convert.ToHexString(SHA256.HashData(WebEncoders.Base64UrlDecode(Secret)))));
        await using var scope = Api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await db.Database.EnsureCreatedAsync();
        Command = CreateCommand();
        var result = await scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>().HandleAsync(Command);
        RealmId = Assert.Single(result.Resources, item => item.Type == "realm").Id;
        EnvironmentId = Assert.Single(result.Resources, item => item.Type == "environment" && item.Path.EndsWith("/primary", StringComparison.Ordinal)).Id;
        SecondaryEnvironmentId = Assert.Single(result.Resources, item => item.Type == "environment" && item.Path.EndsWith("/secondary", StringComparison.Ordinal)).Id;
        Admin = Api.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        Admin.DefaultRequestHeaders.Authorization = new("BullgateAdmin", Secret);
        Consumer = ConsumerClient("primary");
        SecondaryConsumer = ConsumerClient("secondary");
        HttpClient ConsumerClient(string key)
        {
            var client = Api.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
                Assert.Single(result.IssuedCredentials, item => item.IntegrationClientPath.Contains($"/{key}/", StringComparison.Ordinal)).Token);
            return client;
        }
    }

    internal AccessDbContext MigrationContext()
    {
        var rootPath = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(rootPath.FullName, "Bullgate.Access.slnx")))
            rootPath = rootPath.Parent ?? throw new InvalidOperationException("Access solution root not found.");
        // Reuse the already-built migrations project without adding a project/package dependency.
        var buildConfiguration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        var assemblyPath = Path.Combine(rootPath.FullName, "src", "Bullgate.Access.Migrations", "bin", buildConfiguration,
            "net10.0", "Bullgate.Access.Migrations.dll");
        var assembly = Assembly.LoadFrom(assemblyPath);
        return new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>()
            .UseNpgsql(connectionString, options => options.MigrationsAssembly(assembly.FullName)).Options);
    }

    internal Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string permission,
        Guid? operationId = null, object? body = null, string? revision = null, AdminCallContext? context = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-Bullgate-Admin-Context", WebEncoders.Base64UrlEncode(
            JsonSerializer.SerializeToUtf8Bytes(context ?? Context(permission), Json)));
        if (operationId is not null) request.Headers.Add("X-Bullgate-Operation-Id", operationId.Value.ToString("D"));
        if (revision is not null) request.Headers.TryAddWithoutValidation("If-Match", revision);
        if (body is not null) request.Content = JsonContent.Create(body, options: Json);
        return SendAndDisposeAsync(request);
    }
    private async Task<HttpResponseMessage> SendAndDisposeAsync(HttpRequestMessage request)
    { using (request) return await Admin.SendAsync(request); }

    internal async Task<(Guid Id, string Email, string Token)> RegisterAsync()
    {
        var email = $"admin-{Guid.NewGuid():N}@example.test";
        using var result = await Consumer.PostAsJsonAsync("/v1/auth/register", new { email, password = "password-123" });
        result.EnsureSuccessStatusCode();
        var json = await result.Content.ReadFromJsonAsync<JsonElement>();
        return (json.GetProperty("identityId").GetGuid(), email, json.GetProperty("sessionToken").GetString()!);
    }
    internal async Task<string> RevisionAsync()
    {
        await using var scope = Api.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<AccessAdministrationService>();
        string? cursor = null;
        do
        {
            var page = await service.ListEnvironmentsAsync(Context(AccessPermission.ManageConfiguration), 50, cursor);
            if (page.Items.SingleOrDefault(item => item.Id == EnvironmentId) is { } target) return target.Revision;
            cursor = page.NextCursor;
        } while (cursor is not null);
        throw new InvalidOperationException("Test environment missing.");
    }
    internal string IdentityPath(Guid id) => $"/admin/v1/realms/{RealmId}/identities/{id}";
    internal string ConfigurationPath => $"/admin/v1/environments/{EnvironmentId}/configuration";

    public async ValueTask DisposeAsync()
    {
        Admin?.Dispose(); Consumer?.Dispose(); SecondaryConsumer?.Dispose();
        if (Api is not null) await Api.DisposeAsync();
        await root.DisposeAsync();
    }

    private static BootstrapTopologyCommand CreateCommand()
    {
        var policy = TestAccessPolicies.Create(phoneEnabled: false, phoneVerificationEnabled: false);
        return new($"admin-{Guid.NewGuid():N}", "Admin tests", [new("app", "App",
            [new("realm", "Realm")], new[] { "primary", "secondary" }.Select(key => new BootstrapEnvironmentDefinition(
                key, key, "realm", policy, TestEnvironmentConfigurations.VerificationPolicy,
                TestEnvironmentConfigurations.RecoveryPolicy(), new(null, null, null, null), new(false, null, null),
                [new("api", "API", AccessPermission.All)],
                [new("web", "Web", ApplicationClientPlatform.Web, null, null, null, JsonSerializer.SerializeToElement(new { }))]))
            .ToArray())]);
    }
}
