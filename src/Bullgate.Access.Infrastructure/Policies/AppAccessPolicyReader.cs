using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Policies;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Infrastructure.Policies;

/// <summary>
/// Projects the effective access policy from the protected configuration of one active
/// app environment.
/// </summary>
internal sealed class AppAccessPolicyReader(
    IAppEnvironmentConfigurationReader configurations)
    : IAppAccessPolicyReader
{
    public async Task<AppAccessPolicy?> FindAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        (await configurations.FindAsync(appEnvironmentId, cancellationToken))?
        .AccessPolicy;
}
