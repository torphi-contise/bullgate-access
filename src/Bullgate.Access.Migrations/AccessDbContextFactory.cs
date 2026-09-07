using Bullgate.Access.Infrastructure;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Bullgate.Access.Migrations;

/// <summary>
/// Creates the design-time context for EF migrations from the configured Access
/// database connection string.
/// </summary>
public sealed class AccessDbContextFactory : IDesignTimeDbContextFactory<AccessDbContext>
{
    /// <summary>
    /// Creates the EF design-time context from the environment connection string.
    /// </summary>
    /// <remarks>
    /// This factory is tooling support and does not apply migrations. It carries no
    /// built-in connection string: a compiled-in default would place a credential in
    /// source and would let a design-time command reach an unintended database when the
    /// environment variable is missing. The operator supplies the target explicitly.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The connection-string environment variable is absent or blank.
    /// </exception>
    public AccessDbContext CreateDbContext(string[] args)
    {
        var variable = $"ConnectionStrings__{DependencyInjection.ConnectionStringName}";
        var connectionString = Environment.GetEnvironmentVariable(variable);

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                $"Set the {variable} environment variable before running Entity Framework " +
                "design-time commands. This factory has no built-in connection string.");
        }

        var options = new DbContextOptionsBuilder<AccessDbContext>()
            .UseNpgsql(
                connectionString,
                postgres => postgres.MigrationsAssembly(typeof(AccessDbContextFactory).Assembly.FullName))
            .Options;

        return new AccessDbContext(options);
    }
}
