using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class AppEnvironmentConfigurationReaderIntegrationTests(
    PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>
{
    [Fact]
    public async Task FindAsync_SeparatesProviderConfigurationByEnvironment()
    {
        await using var api = new AccessApiFactory(database.ConnectionString);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await dbContext.Database.EnsureDeletedAsync();
        await dbContext.Database.EnsureCreatedAsync();

        var suffix = Guid.NewGuid().ToString("N");
        var firstPolicy = TestAccessPolicies.Create(googleEnabled: true);
        var secondPolicy = TestAccessPolicies.Create(appleEnabled: true);
        var result = await scope.ServiceProvider
            .GetRequiredService<BootstrapTopologyHandler>()
            .HandleAsync(new BootstrapTopologyCommand(
                $"configuration-reader-{suffix}",
                "Configuration reader tests",
                [
                    new BootstrapAppDefinition(
                        $"app-{suffix}",
                        "Test app",
                        [new BootstrapRealmDefinition($"realm-{suffix}", "Test realm")],
                        [
                            Environment(
                                "first",
                                $"realm-{suffix}",
                                firstPolicy,
                                "https://first.example.test/reset-password",
                                "smtp.first.example.test",
                                "first-smtp-password",
                                "first-twilio-secret",
                                googleClientId: "first-google-client"),
                            Environment(
                                "second",
                                $"realm-{suffix}",
                                secondPolicy,
                                "https://second.example.test/reset-password",
                                "smtp.second.example.test",
                                "second-smtp-password",
                                "second-twilio-secret",
                                appleClientId: "second-apple-client"),
                        ]),
                ]));

        var firstId = result.Resources.Single(resource =>
            resource.Type == "environment" && resource.Path.EndsWith("/first")).Id;
        var secondId = result.Resources.Single(resource =>
            resource.Type == "environment" && resource.Path.EndsWith("/second")).Id;
        var reader = scope.ServiceProvider
            .GetRequiredService<IAppEnvironmentConfigurationReader>();

        var first = Assert.IsType<AppEnvironmentConfiguration>(
            await reader.FindAsync(firstId, CancellationToken.None));
        var second = Assert.IsType<AppEnvironmentConfiguration>(
            await reader.FindAsync(secondId, CancellationToken.None));

        Assert.Equal("smtp.first.example.test", first.Providers.Smtp?.Host);
        Assert.Equal("first-smtp-password", first.Providers.Smtp?.Password);
        Assert.Equal("first-twilio-secret", first.Providers.TwilioVerify?.KeySecret);
        Assert.Equal("first-google-client", first.Providers.Google?.ClientId);
        Assert.Null(first.Providers.Apple);

        Assert.Equal("smtp.second.example.test", second.Providers.Smtp?.Host);
        Assert.Equal("second-smtp-password", second.Providers.Smtp?.Password);
        Assert.Equal("second-twilio-secret", second.Providers.TwilioVerify?.KeySecret);
        Assert.Equal("second-apple-client", second.Providers.Apple?.ClientId);
        Assert.Null(second.Providers.Google);
    }

    private static BootstrapEnvironmentDefinition Environment(
        string key,
        string realmKey,
        AppAccessPolicy accessPolicy,
        string recoveryUrl,
        string smtpHost,
        string smtpPassword,
        string twilioSecret,
        string? googleClientId = null,
        string? appleClientId = null) =>
        new(
            key,
            key,
            realmKey,
            accessPolicy,
            TestEnvironmentConfigurations.VerificationPolicy,
            TestEnvironmentConfigurations.RecoveryPolicy(recoveryUrl),
            new AppEnvironmentProviders(
                new SmtpProviderConfiguration(
                    smtpHost,
                    587,
                    "test-user",
                    smtpPassword,
                    $"{key}@example.test",
                    key,
                    true,
                    false),
                new TwilioVerifyProviderConfiguration(
                    $"SK-{key}",
                    twilioSecret,
                    $"VA-{key}",
                    "sms",
                    "en-US",
                    null),
                googleClientId is null
                    ? null
                    : new GoogleProviderConfiguration(googleClientId),
                appleClientId is null
                    ? null
                    : new AppleProviderConfiguration(appleClientId)),
            TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
            [],
            []);
}
