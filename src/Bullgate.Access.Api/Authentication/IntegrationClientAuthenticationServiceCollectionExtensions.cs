using Bullgate.Access.Domain.Topology;
using Microsoft.AspNetCore.Authentication;

namespace Bullgate.Access.Api.Authentication;

/// <summary>
/// Registers integration-client authentication and one exact-claim authorization
/// policy for every permission defined by the Access domain.
/// </summary>
internal static class IntegrationClientAuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Adds the private bearer scheme and generates one exact-claim authorization policy
    /// for every permission in the closed domain vocabulary.
    /// </summary>
    public static IServiceCollection AddIntegrationClientAuthentication(
        this IServiceCollection services)
    {
        services
            .AddAuthentication(IntegrationClientAuthenticationDefaults.Scheme)
            .AddScheme<AuthenticationSchemeOptions, IntegrationClientAuthenticationHandler>(
                IntegrationClientAuthenticationDefaults.Scheme,
                _ => { });

        services.AddAuthorization(options =>
        {
            // Generate policies from the closed permission vocabulary so endpoint
            // declarations and credential validation share the same canonical names.
            foreach (var permission in AccessPermission.All)
            {
                options.AddPolicy(
                    permission,
                    policy => policy
                        .AddAuthenticationSchemes(IntegrationClientAuthenticationDefaults.Scheme)
                        .RequireAuthenticatedUser()
                        .RequireClaim(
                            IntegrationClientAuthenticationDefaults.PermissionClaim,
                            permission));
            }
        });

        return services;
    }
}
