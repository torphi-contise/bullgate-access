using System.Security.Claims;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.Identities;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>
/// Maps permission-scoped phone reads for identities in the authenticated realm.
/// </summary>
internal static class IdentityPhoneEndpoints
{
    public static IEndpointRouteBuilder MapIdentityPhoneEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/v1/identities/{identityId:guid}/phone", GetPhoneAsync)
            .RequireAuthorization(AccessPermission.ReadIdentities)
            .WithTags("Access");

        return endpoints;
    }

    private static async Task<IResult> GetPhoneAsync(
        Guid identityId,
        ClaimsPrincipal principal,
        IdentityPhoneReader reader,
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

        var phone = await reader.GetAsync(realmId, identityId, cancellationToken);
        // Absence, inactivity, missing contact data, and cross-realm selection share one
        // 404 shape so the route cannot disclose identity existence outside caller scope.
        return phone is null
            ? IdentityNotFound()
            : Results.Ok(new IdentityPhoneResponse(phone.Phone, phone.VerifiedAt));
    }

    private static IResult IdentityNotFound() =>
        Results.NotFound(new IdentityPhoneErrorResponse("identity-not-found"));
}

/// <summary>
/// Normalized phone and optional time at which possession was verified for an active
/// identity in the authenticated realm.
/// </summary>
/// <param name="Phone">Canonical stored phone.</param>
/// <param name="VerifiedAt">UTC proof time, or <see langword="null"/> when unverified.</param>
internal sealed record IdentityPhoneResponse(
    string Phone,
    DateTimeOffset? VerifiedAt);

/// <summary>Stable absence response that does not disclose another realm.</summary>
/// <param name="Error">Machine-readable collapsed absence code.</param>
internal sealed record IdentityPhoneErrorResponse(string Error);
