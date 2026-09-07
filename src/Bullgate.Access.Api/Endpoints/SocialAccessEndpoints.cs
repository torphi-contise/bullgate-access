using System.Security.Claims;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.Social;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>
/// Maps Google and Apple authentication plus explicit link and unlink operations
/// without exposing provider credentials beyond the server-side integration boundary.
/// </summary>
internal static class SocialAccessEndpoints
{
    public static IEndpointRouteBuilder MapSocialAccessEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/v1/auth/google", GoogleAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access");
        endpoints.MapPost("/v1/auth/apple", AppleAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access");
        endpoints.MapPost("/v1/account/social/google/link", LinkGoogleAsync)
            .RequireAuthorization(AccessPermission.ManageCurrentIdentity)
            .WithTags("Access");
        endpoints.MapPost("/v1/account/social/google/unlink", UnlinkGoogleAsync)
            .RequireAuthorization(AccessPermission.ManageCurrentIdentity)
            .WithTags("Access");
        endpoints.MapPost("/v1/account/social/apple/link", LinkAppleAsync)
            .RequireAuthorization(AccessPermission.ManageCurrentIdentity)
            .WithTags("Access");
        endpoints.MapPost("/v1/account/social/apple/unlink", UnlinkAppleAsync)
            .RequireAuthorization(AccessPermission.ManageCurrentIdentity)
            .WithTags("Access");

        return endpoints;
    }

    private static async Task<IResult> GoogleAsync(
        GoogleAuthRequest request,
        ClaimsPrincipal principal,
        SocialAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await access.GoogleAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.IdToken,
            request.AccessToken,
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(ToResponse(result))
            : ToError(result.Error!.Value);
    }

    private static async Task<IResult> AppleAsync(
        AppleAuthRequest request,
        ClaimsPrincipal principal,
        SocialAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await access.AppleAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.IdentityToken,
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(ToResponse(result))
            : ToError(result.Error!.Value);
    }

    private static async Task<IResult> LinkGoogleAsync(
        GoogleManagementRequest request,
        ClaimsPrincipal principal,
        SocialAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await access.LinkGoogleAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.SessionToken,
            request.IdToken,
            request.AccessToken,
            cancellationToken);
        return ToManagementResult(result);
    }

    private static async Task<IResult> UnlinkGoogleAsync(
        SessionManagementRequest request,
        ClaimsPrincipal principal,
        SocialAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        return ToManagementResult(await access.UnlinkGoogleAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.SessionToken,
            cancellationToken));
    }

    private static async Task<IResult> LinkAppleAsync(
        AppleManagementRequest request,
        ClaimsPrincipal principal,
        SocialAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await access.LinkAppleAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.SessionToken,
            request.IdentityToken,
            cancellationToken);
        return ToManagementResult(result);
    }

    private static async Task<IResult> UnlinkAppleAsync(
        SessionManagementRequest request,
        ClaimsPrincipal principal,
        SocialAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        return ToManagementResult(await access.UnlinkAppleAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.SessionToken,
            cancellationToken));
    }

    private static SocialAuthResponse ToResponse(SocialAccessResult result) =>
        new(
            result.IdentityId,
            result.Email,
            result.Phone,
            result.PhoneVerifiedAt,
            result.SessionToken,
            result.SessionExpiresAt,
            result.SessionPurpose.ToString().ToLowerInvariant(),
            result.IsNew,
            result.Authenticators.HasPassword,
            result.Authenticators.HasGoogle,
            result.Authenticators.GoogleEmail,
            result.Authenticators.HasApple,
            result.Authenticators.AppleEmail);

    private static IResult ToManagementResult(SocialManagementResult result)
    {
        if (result.Succeeded)
        {
            return Results.Ok(new CurrentIdentityResponse(
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
                result.Authenticators.AppleEmail));
        }

        return result.Error!.Value switch
        {
            SocialManagementError.SessionInactive => Results.Json(
                new AccessErrorResponse("session-inactive"),
                statusCode: StatusCodes.Status401Unauthorized),
            SocialManagementError.SessionPurposeInvalid => Results.Conflict(
                new AccessErrorResponse("session-purpose-invalid")),
            SocialManagementError.AuthenticatorDisabled => Results.Conflict(
                new AccessErrorResponse("authenticator-disabled")),
            SocialManagementError.MissingToken => Results.BadRequest(
                new AccessErrorResponse("missing-token")),
            SocialManagementError.InvalidToken => Results.Json(
                new AccessErrorResponse("invalid-token"),
                statusCode: StatusCodes.Status401Unauthorized),
            SocialManagementError.ProviderAlreadyLinked => Results.Conflict(
                new AccessErrorResponse("provider-already-linked")),
            SocialManagementError.CredentialAlreadyInUse => Results.Conflict(
                new AccessErrorResponse("email-taken", "email")),
            SocialManagementError.ProviderNotLinked => Results.Conflict(
                new AccessErrorResponse("provider-not-linked")),
            SocialManagementError.LastAuthenticator => Results.Conflict(
                new AccessErrorResponse("last-authenticator")),
            _ => throw new ArgumentOutOfRangeException(),
        };
    }

    private static IResult ToError(SocialAccessError error) => error switch
    {
        SocialAccessError.MissingToken => Results.BadRequest(
            new AccessErrorResponse("missing-token")),
        SocialAccessError.InvalidToken => Results.Json(
            new AccessErrorResponse("invalid-token"),
            statusCode: StatusCodes.Status401Unauthorized),
        SocialAccessError.EmailTaken => Results.Conflict(
            new AccessErrorResponse("email-taken", "email")),
        SocialAccessError.AuthenticatorDisabled => Results.Conflict(
            new AccessErrorResponse("authenticator-disabled")),
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
/// Google assertion input. When both values are present, the ID token takes precedence.
/// </summary>
internal sealed record GoogleAuthRequest(string? IdToken, string? AccessToken);

/// <summary>Apple identity token submitted for server-side validation.</summary>
internal sealed record AppleAuthRequest(string? IdentityToken);

/// <summary>Product session and Google assertion used to link an authenticator.</summary>
internal sealed record GoogleManagementRequest(
    string? SessionToken,
    string? IdToken,
    string? AccessToken);

/// <summary>Product session and Apple identity token used to link an authenticator.</summary>
internal sealed record AppleManagementRequest(
    string? SessionToken,
    string? IdentityToken);

/// <summary>Product session used to authorize social-authenticator removal.</summary>
internal sealed record SessionManagementRequest(string? SessionToken);

/// <summary>
/// Social registration or login result containing identity state and newly issued
/// session bearer material for BFF handling.
/// </summary>
/// <remarks>`SessionToken` must not be exposed to application JavaScript.</remarks>
internal sealed record SocialAuthResponse(
    Guid IdentityId,
    string Email,
    string? Phone,
    DateTimeOffset? PhoneVerifiedAt,
    string SessionToken,
    DateTimeOffset SessionExpiresAt,
    string SessionPurpose,
    bool IsNew,
    bool HasPassword,
    bool HasGoogle,
    string? GoogleEmail,
    bool HasApple,
    string? AppleEmail);
