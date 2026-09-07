using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Configuration;

/// <summary>
/// Decrypts and returns the protected configuration owned by an app environment.
/// </summary>
public interface IAppEnvironmentConfigurationReader
{
    /// <summary>
    /// Returns the authenticated configuration of an active environment, or
    /// <see langword="null"/> when that environment is absent or inactive.
    /// </summary>
    /// <remarks>
    /// Authentication, key, format, and JSON failures are not converted to absence.
    /// Callers must treat those exceptions as configuration failures rather than silently
    /// falling back to global or request-supplied values.
    /// </remarks>
    Task<AppEnvironmentConfiguration?> FindAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken);
}
