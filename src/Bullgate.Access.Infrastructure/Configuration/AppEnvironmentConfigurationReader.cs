using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Configuration;

/// <summary>
/// Loads and decrypts the configuration of an active app environment without tracking
/// the persistence entity or exposing its encryption envelope to application code.
/// </summary>
internal sealed class AppEnvironmentConfigurationReader(
    AccessDbContext dbContext,
    IAppEnvironmentConfigurationProtector protector)
    : IAppEnvironmentConfigurationReader
{
    public async Task<AppEnvironmentConfiguration?> FindAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(appEnvironmentId, Guid.Empty);

        var stored = await dbContext.AppEnvironments
            .AsNoTracking()
            // An inactive environment is unavailable even if its ciphertext remains
            // valid. Activation is part of authorization, not only presentation state.
            .Where(environment =>
                environment.Id == appEnvironmentId && environment.IsActive)
            .Select(environment => new
            {
                environment.ConfigurationFormatVersion,
                environment.ConfigurationNonce,
                environment.ConfigurationCiphertext,
                environment.ConfigurationTag,
            })
            .SingleOrDefaultAsync(cancellationToken);

        // Only genuine absence or inactivity maps to null. Authentication or schema
        // errors from Unprotect must surface because fallback would cross a trust boundary.
        return stored is null
            ? null
            : protector.Unprotect(
                appEnvironmentId,
                new ProtectedAppEnvironmentConfiguration(
                    stored.ConfigurationFormatVersion,
                    stored.ConfigurationNonce,
                    stored.ConfigurationCiphertext,
                    stored.ConfigurationTag));
    }
}
