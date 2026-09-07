using System.Security.Claims;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>
/// Maps the two-step phone password-recovery protocol while preserving its
/// anti-enumeration and rate-limit error contract.
/// </summary>
internal static class PhonePasswordRecoveryEndpoints
{
    public static IEndpointRouteBuilder MapPhonePasswordRecoveryEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(
                "/v1/auth/password/recovery/phone",
                RequestAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access");
        endpoints.MapPost(
                "/v1/auth/password/recovery/phone/confirm",
                ConfirmAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access");

        return endpoints;
    }

    private static async Task<IResult> RequestAsync(
        PhonePasswordRecoveryRequest request,
        ClaimsPrincipal principal,
        PhonePasswordRecoveryService recovery,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await recovery.RequestAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.Phone,
            request.ApplicationClientKey,
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(new PhonePasswordRecoveryRequestResponse(
                result.ExpiresAt!.Value,
                result.ResendAvailableAt!.Value))
            : ToError(result.Error!.Value);
    }

    private static async Task<IResult> ConfirmAsync(
        PhonePasswordRecoveryConfirmRequest request,
        ClaimsPrincipal principal,
        PhonePasswordRecoveryService recovery,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await recovery.ConfirmAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.Phone,
            request.Code,
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(new PhonePasswordRecoveryConfirmResponse(
                result.Token!,
                result.ExpiresAt!.Value))
            : ToError(result.Error!.Value);
    }

    private static IResult ToError(PhonePasswordRecoveryError error) =>
        error switch
        {
            PhonePasswordRecoveryError.RecoveryDisabled => Results.Conflict(
                new AccessErrorResponse("authenticator-disabled")),
            PhonePasswordRecoveryError.MissingPhone => Results.BadRequest(
                new AccessErrorResponse("missing-fields", "phone")),
            PhonePasswordRecoveryError.InvalidPhone => Results.BadRequest(
                new AccessErrorResponse("invalid-phone", "phone")),
            PhonePasswordRecoveryError.ApplicationClientInvalid => Results.BadRequest(
                new AccessErrorResponse(
                    "application-client-invalid",
                    "applicationClientKey")),
            PhonePasswordRecoveryError.MissingCode => Results.BadRequest(
                new AccessErrorResponse("missing-fields", "code")),
            PhonePasswordRecoveryError.InvalidCode => Results.BadRequest(
                new AccessErrorResponse("invalid-code", "code")),
            PhonePasswordRecoveryError.DeliveryUnavailable => Results.Json(
                new AccessErrorResponse("verification-delivery-unavailable"),
                statusCode: StatusCodes.Status503ServiceUnavailable),
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

/// <summary>
/// Phone-recovery initiation input. Application-client key selects delivery metadata
/// inside the authenticated environment and grants no authority.
/// </summary>
internal sealed record PhonePasswordRecoveryRequest(
    string? Phone,
    string? ApplicationClientKey);

/// <summary>
/// Public timing envelope returned without confirming whether the phone has an owner.
/// </summary>
internal sealed record PhonePasswordRecoveryRequestResponse(
    DateTimeOffset ExpiresAt,
    DateTimeOffset ResendAvailableAt);

/// <summary>Normalized-phone candidate and one-time confirmation code.</summary>
internal sealed record PhonePasswordRecoveryConfirmRequest(
    string? Phone,
    string? Code);

/// <summary>
/// Short-lived single-use password-reset authority issued after successful phone
/// confirmation.
/// </summary>
/// <remarks>The token belongs only in the intended recovery path and must not be logged.</remarks>
internal sealed record PhonePasswordRecoveryConfirmResponse(
    string Token,
    DateTimeOffset ExpiresAt);
