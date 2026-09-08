using Bullgate.Access.Domain.Topology;
using Microsoft.AspNetCore.Authentication;

namespace Bullgate.Access.Api.Authentication;

/// <summary>Separate caller policies, including when an Access function key is shared.</summary>
internal static class AdminServiceAuthenticationExtensions
{
    internal const string Scheme = "BullgateAdmin";
    internal const string ContextHeader = "X-Bullgate-Admin-Context";
    internal const string PermissionClaim = "bullgate-admin-permission";
    internal const string ContextItem = "bullgate-admin-context";
    internal const string CredentialHashSetting = "Bullgate:Admin:CredentialSha256";
    internal static string Policy(string permission) => $"BullgateAdmin:{permission}";

    public static IServiceCollection AddAdminServiceAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, AdminServiceAuthenticationHandler>(Scheme, _ => { });
        services.AddAuthorization(options =>
        {
            options.AddPolicy(Scheme, policy => policy.AddAuthenticationSchemes(Scheme).RequireAuthenticatedUser());
            foreach (var permission in AccessPermission.Administrative)
                options.AddPolicy(Policy(permission), policy => policy.AddAuthenticationSchemes(Scheme)
                    .RequireAuthenticatedUser().RequireClaim(PermissionClaim, permission));
        });
        return services;
    }
}

/// <summary>Identifies routes requiring human attribution, distinct from service metadata.</summary>
internal sealed record AdminFunction(string Permission);
