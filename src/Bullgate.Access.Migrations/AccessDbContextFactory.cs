using Bullgate.Access.Infrastructure;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Bullgate.Access.Migrations;

/// <summary>
/// Creates the design-time context for EF migrations, using the configured Access
/// database or an explicitly local development fallback.
/// </summary>
public sealed class AccessDbContextFactory : IDesignTimeDbContextFactory<AccessDbContext>
{
    private const string LocalConnectionString =
        "Host=localhost;Port=5432;Database=bullgate_access;Username=bullgate_access;Password=bullgate_access_dev";

    /// <summary>
    /// Creates the EF design-time context from the environment connection string, using
    /// the explicitly local development fallback only when that value is absent.
    /// </summary>
    /// <remarks>This factory is tooling support and does not apply migrations.</remarks>
    public AccessDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable(
            $"ConnectionStrings__{DependencyInjection.ConnectionStringName}");

        var options = new DbContextOptionsBuilder<AccessDbContext>()
            .UseNpgsql(
                connectionString ?? LocalConnectionString,
                postgres => postgres.MigrationsAssembly(typeof(AccessDbContextFactory).Assembly.FullName))
            .Options;

        return new AccessDbContext(options);
    }
}
