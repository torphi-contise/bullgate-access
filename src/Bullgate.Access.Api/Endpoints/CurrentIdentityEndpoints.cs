using System.Security.Claims;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.AspNetCore.Mvc;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>
/// Maps current-identity e-mail replacement and hard-deletion operations authorized
/// by a product session inside the authenticated integration scope.
/// </summary>
internal static class CurrentIdentityEndpoints
{
    /// <summary>Adds current-identity routes and their integration permission gates.</summary>
    /// <param name="endpoints">Route builder receiving the account operations.</param>
    /// <returns>The same route builder for composition.</returns>
    public static IEndpointRouteBuilder MapCurrentIdentityEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPut("/v1/account/email", ChangeEmailAsync)
            .RequireAuthorization(AccessPermission.ManageCurrentIdentity)
            .WithTags("Access");
        endpoints.MapDelete("/v1/account", DeleteAsync)
            .RequireAuthorization(AccessPermission.ManageCurrentIdentity)
            .WithTags("Access");

        return endpoints;
    }

    private static async Task<IResult> ChangeEmailAsync(
        ChangeCurrentEmailRequest request,
        ClaimsPrincipal principal,
        CurrentIdentityService identities,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await identities.ChangeEmailAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.SessionToken,
            request.Email,
            cancellationToken);
        return result.Succeeded
            ? Results.Ok(ToResponse(result))
            : ToError(result.Error!.Value);
    }

    /// <summary>
    /// Deletes the Access identity selected by an active product-session bearer inside
    /// the integration credential's fixed realm and environment.
    /// </summary>
    /// <remarks>
    /// HTTP 204 confirms only that the local Access transaction committed. The endpoint
    /// accepts no identity UUID and does not coordinate deletion in a consumer database.
    /// A retry with the same bearer after success returns <c>session-inactive</c> because
    /// the authorizing session was part of the deleted graph.
    /// </remarks>
    private static async Task<IResult> DeleteAsync(
        [FromBody] DeleteCurrentIdentityRequest request,
        ClaimsPrincipal principal,
        CurrentIdentityService identities,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var error = await identities.DeleteAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.SessionToken,
            cancellationToken);
        // NoContent confirms only the local Access erasure transaction. The consumer BFF
        // owns ordering and recovery for deletion of its separate profile database.
        return error is null ? Results.NoContent() : ToError(error.Value);
    }

    private static CurrentIdentityResponse ToResponse(CurrentIdentityResult result) =>
        new(
            result.IdentityId,
            result.SessionId,
            result.Email,
            result.Phone,
            result.PhoneVerifiedAt,
            result.ExpiresAt,
            result.Purpose.ToString().ToLowerInvariant(),
            result.Authenticators.HasPassword,
            result.Authenticators.HasGoogle,
            result.Authenticators.GoogleEmail,
            result.Authenticators.HasApple,
            result.Authenticators.AppleEmail);

    private static IResult ToError(CurrentIdentityError error) => error switch
    {
        CurrentIdentityError.SessionInactive => Results.Json(
            new AccessErrorResponse("session-inactive"),
            statusCode: StatusCodes.Status401Unauthorized),
        CurrentIdentityError.SessionPurposeInvalid => Results.Conflict(
            new AccessErrorResponse("session-purpose-invalid")),
        CurrentIdentityError.InvalidEmail => Results.BadRequest(
            new AccessErrorResponse("invalid-email", "email")),
        CurrentIdentityError.EmailTaken => Results.Conflict(
            new AccessErrorResponse("email-taken", "email")),
        _ => throw new ArgumentOutOfRangeException(nameof(error), error, null),
    };

    private static IntegrationScope ReadScope(ClaimsPrincipal principal)
    {
        var environment = principal.FindFirstValue(
            IntegrationClientAuthenticationDefaults.AppEnvironmentIdClaim);
        var realm = principal.FindFirstValue(
            IntegrationClientAuthenticationDefaults.RealmIdClaim);
        if (!Guid.TryParseExact(environment, "D", out var appEnvironmentId)
            || !Guid.TryParseExact(realm, "D", out var realmId))
        {
            throw new InvalidOperationException(
                "Authenticated integration client scope is incomplete.");
        }
        return new IntegrationScope(appEnvironmentId, realmId);
    }

    private sealed record IntegrationScope(Guid AppEnvironmentId, Guid RealmId);
}

/// <summary>Product session and replacement e-mail for the current identity.</summary>
/// <param name="SessionToken">Untrusted clear product-session bearer.</param>
/// <param name="Email">Candidate primary e-mail; normalization occurs server-side.</param>
internal sealed record ChangeCurrentEmailRequest(string? SessionToken, string? Email);

/// <summary>Product session authorizing hard deletion of the current identity.</summary>
/// <param name="SessionToken">
/// Untrusted clear product-session bearer; its hash selects the identity to erase only
/// inside the realm and environment fixed by the authenticated integration credential.
/// </param>
internal sealed record DeleteCurrentIdentityRequest(string? SessionToken);
