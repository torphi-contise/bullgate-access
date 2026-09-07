using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class RegistrationLifecyclePersistenceTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private AccessApiFactory api = null!;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await dbContext.Database.EnsureCreatedAsync();
    }

    public Task DisposeAsync() => api.DisposeAsync().AsTask();

    [Fact]
    public async Task RegistrationLifecycle_RoundTripsThroughPostgreSql()
    {
        var suffix = Guid.NewGuid().ToString("N");
        BootstrapTopologyResult topology;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
            topology = await handler.HandleAsync(CreateBootstrapCommand(suffix));
        }

        var realmId = Assert.Single(
            topology.Resources,
            resource => resource.Type == "realm").Id;
        var appEnvironmentId = Assert.Single(
            topology.Resources,
            resource => resource.Type == "environment").Id;
        var now = new DateTimeOffset(2026, 9, 1, 18, 0, 0, TimeSpan.Zero);
        var provisionalIdentity = new Identity(Guid.CreateVersion7(), realmId, now);
        var context = new RegistrationContext(
            Guid.CreateVersion7(),
            realmId,
            appEnvironmentId,
            provisionalIdentity.Id,
            now);
        var session = new IdentitySession(
            Guid.CreateVersion7(),
            provisionalIdentity.Id,
            appEnvironmentId,
            IdentitySessionPurpose.Registration,
            new byte[IdentityLimits.SessionTokenHashLength],
            now,
            now.AddMinutes(30));

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            dbContext.Identities.Add(provisionalIdentity);
            dbContext.RegistrationContexts.Add(context);
            dbContext.IdentitySessions.Add(session);
            await dbContext.SaveChangesAsync();
        }

        provisionalIdentity.Abandon();
        context.Abandon(now.AddMinutes(5));

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            dbContext.Identities.Update(provisionalIdentity);
            dbContext.RegistrationContexts.Update(context);
            await dbContext.SaveChangesAsync();
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var storedIdentity = await dbContext.Identities
                .AsNoTracking()
                .SingleAsync(identity => identity.Id == provisionalIdentity.Id);
            var storedContext = await dbContext.RegistrationContexts
                .AsNoTracking()
                .SingleAsync(item => item.Id == context.Id);
            var storedSession = await dbContext.IdentitySessions
                .AsNoTracking()
                .SingleAsync(item => item.Id == session.Id);

            Assert.Equal(
                IdentityLifecycleState.Abandoned,
                storedIdentity.LifecycleState);
            Assert.Equal(RegistrationContextStatus.Abandoned, storedContext.Status);
            Assert.Equal(now.AddMinutes(5), storedContext.ClosedAt);
            Assert.Equal(IdentitySessionPurpose.Registration, storedSession.Purpose);
        }
    }

    private static BootstrapTopologyCommand CreateBootstrapCommand(string suffix) =>
        new(
            $"registration-lifecycle-{suffix}",
            "Registration lifecycle tests",
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
                            TestAccessPolicies.Create(),
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(
                                TestAccessPolicies.Create()),
                            TestEnvironmentConfigurations.DevelopmentBypass(
                                TestAccessPolicies.Create()),
                            [],
                            []),
                    ]),
            ]);
}
