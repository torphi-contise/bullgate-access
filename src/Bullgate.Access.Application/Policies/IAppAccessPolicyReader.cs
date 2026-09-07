using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Policies;

/// <summary>Reads the effective access policy owned by one app environment.</summary>
public interface IAppAccessPolicyReader
{
    Task<AppAccessPolicy?> FindAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken);
}
