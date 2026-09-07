using System.Security.Claims;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.Identities;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>
/// Maps permission-scoped e-mail reads for identities in the authenticated realm.
/// </summary>
internal static class IdentityEmailEndpoints
{
    public static IEndpointRouteBuilder MapIdentityEmailEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/v1/identities/{identityId:guid}/email", GetEmailAsync)
            .RequireAuthorization(AccessPermission.ReadIdentities)
            .WithTags("Access");

        return endpoints;
    }

    private static async Task<IResult> GetEmailAsync(
        Guid identityId,
        ClaimsPrincipal principal,
        IdentityEmailReader reader,
        CancellationToken cancellationToken)
    {
        if (identityId == Guid.Empty)
        {
            return IdentityNotFound();
        }

        var realm = principal.FindFirstValue(
            IntegrationClientAuthenticationDefaults.RealmIdClaim);
        if (!Guid.TryParseExact(realm, "D", out var realmId))
        {
            throw new InvalidOperationException(
                "Authenticated integration client scope is incomplete.");
        }

        var email = await reader.GetAsync(realmId, identityId, cancellationToken);
        // Absence, inactivity, missing contact data, and cross-realm selection share one
        // 404 shape so the route cannot disclose identity existence outside caller scope.
        return email is null
            ? IdentityNotFound()
            : Results.Ok(new IdentityEmailResponse(email));
    }

    private static IResult IdentityNotFound() =>
        Results.NotFound(new IdentityEmailErrorResponse("identity-not-found"));
}

/// <summary>Normalized e-mail of an active identity in the authenticated realm.</summary>
/// <param name="Email">Canonical stored e-mail.</param>
internal sealed record IdentityEmailResponse(string Email);

/// <summary>Stable absence response that does not disclose another realm.</summary>
/// <param name="Error">Machine-readable collapsed absence code.</param>
internal sealed record IdentityEmailErrorResponse(string Error);
