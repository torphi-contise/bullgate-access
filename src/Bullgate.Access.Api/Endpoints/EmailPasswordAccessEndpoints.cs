using System.Security.Claims;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>
/// Maps e-mail/password registration, authentication, session, password-change, and
/// e-mail-recovery operations to the application service contract.
/// </summary>
internal static class EmailPasswordAccessEndpoints
{
    public static IEndpointRouteBuilder MapEmailPasswordAccessEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/v1/auth/register", RegisterAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access");
        endpoints.MapPost("/v1/auth/login", LoginAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access");
        endpoints.MapPost("/v1/auth/session/introspect", IntrospectAsync)
            .RequireAuthorization(AccessPermission.IntrospectSessions)
            .WithTags("Access");
        endpoints.MapPost("/v1/auth/session/revoke", RevokeCurrentSessionAsync)
            .RequireAuthorization(AccessPermission.RevokeCurrentSession)
            .WithTags("Access");
        endpoints.MapPost("/v1/account/password", ChangePasswordAsync)
            .RequireAuthorization(AccessPermission.ManageCurrentIdentity)
            .WithTags("Access");
        endpoints.MapPost(
                "/v1/auth/password/recovery/email",
                RequestPasswordRecoveryByEmailAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access");
        endpoints.MapPost(
                "/v1/auth/password/recovery/reset",
                ResetPasswordAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access");

        return endpoints;
    }

    private static async Task<IResult> RegisterAsync(
        EmailPasswordRequest request,
        ClaimsPrincipal principal,
        EmailPasswordAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await access.RegisterAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.Email,
            request.Password,
            cancellationToken);

        return result.Succeeded
            ? Results.Json(ToResponse(result), statusCode: StatusCodes.Status201Created)
            : ToError(result.Error!.Value);
    }

    private static async Task<IResult> LoginAsync(
        EmailPasswordRequest request,
        ClaimsPrincipal principal,
        EmailPasswordAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await access.LoginAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.Email,
            request.Password,
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(ToResponse(result))
            : ToError(result.Error!.Value);
    }

    private static async Task<IResult> IntrospectAsync(
        SessionIntrospectionRequest request,
        ClaimsPrincipal principal,
        EmailPasswordAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await access.IntrospectAsync(
            scope.AppEnvironmentId,
            request.SessionToken,
            cancellationToken);

        // Introspection is a query, not authentication of the HTTP caller. Return 200
        // with Active=false for an unknown or inactive session so token existence is
        // represented only by the response contract.
        return Results.Ok(new SessionIntrospectionResponse(
            result.Active,
            result.IdentityId,
            result.SessionId,
            result.Email,
            result.Phone,
            result.PhoneVerifiedAt,
            result.ExpiresAt,
            result.Purpose?.ToString().ToLowerInvariant(),
            result.Authenticators?.HasPassword ?? false,
            result.Authenticators?.HasGoogle ?? false,
            result.Authenticators?.GoogleEmail,
            result.Authenticators?.HasApple ?? false,
            result.Authenticators?.AppleEmail));
    }

    private static async Task<IResult> RevokeCurrentSessionAsync(
        SessionIntrospectionRequest request,
        ClaimsPrincipal principal,
        EmailPasswordAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        await access.RevokeCurrentSessionAsync(
            scope.AppEnvironmentId,
            request.SessionToken,
            cancellationToken);

        // Revocation is idempotent at the transport boundary. Do not disclose whether
        // the presented session hash matched an active row.
        return Results.NoContent();
    }

    private static async Task<IResult> ChangePasswordAsync(
        ChangePasswordRequest request,
        ClaimsPrincipal principal,
        EmailPasswordAccessService access,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await access.ChangePasswordAsync(
            scope.AppEnvironmentId,
            request.SessionToken,
            request.CurrentPassword,
            request.NewPassword,
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(ToCurrentIdentityResponse(result))
            : ToChangePasswordError(result.Error!.Value);
    }

    private static async Task<IResult> RequestPasswordRecoveryByEmailAsync(
        PasswordRecoveryEmailRequest request,
        ClaimsPrincipal principal,
        EmailPasswordRecoveryService recovery,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        _ = await recovery.RequestAsync(
            scope.RealmId,
            scope.AppEnvironmentId,
            request.Email,
            cancellationToken);

        // Deliberately discard the internal outcome. Public recovery initiation must
        // not reveal whether the normalized e-mail belongs to an identity.
        return Results.Accepted();
    }

    private static async Task<IResult> ResetPasswordAsync(
        PasswordRecoveryResetRequest request,
        ClaimsPrincipal principal,
        PasswordResetService passwordReset,
        CancellationToken cancellationToken)
    {
        var scope = ReadScope(principal);
        var result = await passwordReset.ResetAsync(
            scope.AppEnvironmentId,
            request.Token,
            request.NewPassword,
            cancellationToken);

        return result.Succeeded
            ? Results.NoContent()
            : ToPasswordRecoveryResetError(result.Error!.Value);
    }

    private static EmailPasswordResponse ToResponse(EmailPasswordAccessResult result) =>
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

    private static CurrentIdentityResponse ToCurrentIdentityResponse(
        CurrentIdentitySessionResult result) =>
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

    private static IResult ToChangePasswordError(ChangePasswordAccessError error) =>
        error switch
        {
            ChangePasswordAccessError.SessionInactive => Results.Json(
                new AccessErrorResponse("session-inactive"),
                statusCode: StatusCodes.Status401Unauthorized),
            ChangePasswordAccessError.SessionPurposeInvalid => Results.Conflict(
                new AccessErrorResponse("session-purpose-invalid")),
            ChangePasswordAccessError.AuthenticatorDisabled => Results.Conflict(
                new AccessErrorResponse("authenticator-disabled")),
            ChangePasswordAccessError.MissingNewPassword => Results.BadRequest(
                new AccessErrorResponse("missing-fields", "newPassword")),
            ChangePasswordAccessError.PasswordTooShort => Results.BadRequest(
                new AccessErrorResponse("password-too-short", "newPassword")),
            ChangePasswordAccessError.CurrentPasswordRequired => Results.BadRequest(
                new AccessErrorResponse("current-password-required", "currentPassword")),
            ChangePasswordAccessError.CurrentPasswordWrong => Results.BadRequest(
                new AccessErrorResponse("current-password-wrong", "currentPassword")),
            ChangePasswordAccessError.PasswordChangeConflict => Results.Conflict(
                new AccessErrorResponse("password-change-conflict")),
            _ => throw new ArgumentOutOfRangeException(nameof(error), error, null),
        };

    private static IResult ToError(EmailPasswordAccessError error) => error switch
    {
        EmailPasswordAccessError.InvalidEmail => Results.BadRequest(
            new AccessErrorResponse("invalid-email", "email")),
        EmailPasswordAccessError.PasswordTooShort => Results.BadRequest(
            new AccessErrorResponse("password-too-short", "password")),
        EmailPasswordAccessError.EmailTaken => Results.Conflict(
            new AccessErrorResponse("email-taken", "email")),
        EmailPasswordAccessError.InvalidCredentials => Results.Json(
            new AccessErrorResponse("invalid-credentials"),
            statusCode: StatusCodes.Status401Unauthorized),
        EmailPasswordAccessError.AuthenticatorDisabled => Results.Conflict(
            new AccessErrorResponse("authenticator-disabled")),
        _ => throw new ArgumentOutOfRangeException(nameof(error), error, null),
    };

    private static IResult ToPasswordRecoveryResetError(
        PasswordResetError error) => error switch
        {
            PasswordResetError.AuthenticatorDisabled => Results.Conflict(
                new AccessErrorResponse("authenticator-disabled")),
            PasswordResetError.InvalidToken => Results.BadRequest(
                new AccessErrorResponse("invalid-token", "token")),
            PasswordResetError.MissingNewPassword => Results.BadRequest(
                new AccessErrorResponse("missing-fields", "newPassword")),
            PasswordResetError.PasswordTooShort => Results.BadRequest(
                new AccessErrorResponse("password-too-short", "newPassword")),
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

/// <summary>Registration or login input containing an e-mail and clear password.</summary>
internal sealed record EmailPasswordRequest(string? Email, string? Password);

/// <summary>Server-side session token submitted for introspection or revocation.</summary>
/// <param name="SessionToken">Untrusted clear bearer retained by the consumer BFF.</param>
internal sealed record SessionIntrospectionRequest(string? SessionToken);

/// <summary>
/// Product-session-authorized password replacement input. Current password may be
/// omitted only when the identity does not yet have a password authenticator.
/// </summary>
internal sealed record ChangePasswordRequest(
    string? SessionToken,
    string? CurrentPassword,
    string? NewPassword);

/// <summary>E-mail selector for an anti-enumerable recovery request.</summary>
internal sealed record PasswordRecoveryEmailRequest(string? Email);

/// <summary>Single-use recovery token and replacement password.</summary>
internal sealed record PasswordRecoveryResetRequest(
    string? Token,
    string? NewPassword);

/// <summary>
/// Registration or login result containing identity state and newly issued session
/// bearer material for BFF handling.
/// </summary>
/// <remarks>
/// `SessionToken` must not be forwarded to application JavaScript. The BFF should store
/// it in protected server-side session state or an appropriate HttpOnly cookie.
/// </remarks>
internal sealed record EmailPasswordResponse(
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

/// <summary>
/// Session state returned with HTTP 200; identity fields are absent when `Active` is
/// false.
/// </summary>
/// <remarks>
/// <c>Active</c> describes session validity, not product authorization. A true result
/// may still carry registration purpose and must not be resolved as a product principal.
/// </remarks>
/// <param name="Active">Whether the scoped bearer is currently valid.</param>
/// <param name="IdentityId">Access identity id, present only when active.</param>
/// <param name="SessionId">Durable session selector, present only when active.</param>
/// <param name="Email">Current canonical e-mail, present only when active.</param>
/// <param name="Phone">Optional current canonical phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone-possession proof time.</param>
/// <param name="ExpiresAt">Exclusive UTC expiry, present only when active.</param>
/// <param name="SessionPurpose">Registration or product authority class when active.</param>
/// <param name="HasPassword">Whether the active identity has a password authenticator.</param>
/// <param name="HasGoogle">Whether the active identity has a Google authenticator.</param>
/// <param name="GoogleEmail">Current Google e-mail metadata when linked.</param>
/// <param name="HasApple">Whether the active identity has an Apple authenticator.</param>
/// <param name="AppleEmail">Current Apple e-mail metadata when linked.</param>
internal sealed record SessionIntrospectionResponse(
    bool Active,
    Guid? IdentityId,
    Guid? SessionId,
    string? Email,
    string? Phone,
    DateTimeOffset? PhoneVerifiedAt,
    DateTimeOffset? ExpiresAt,
    string? SessionPurpose,
    bool HasPassword,
    bool HasGoogle,
    string? GoogleEmail,
    bool HasApple,
    string? AppleEmail);

/// <summary>
/// Current active identity, session, contacts, purpose, and authenticator snapshot
/// returned after an authenticated account mutation.
/// </summary>
internal sealed record CurrentIdentityResponse(
    Guid IdentityId,
    Guid SessionId,
    string Email,
    string? Phone,
    DateTimeOffset? PhoneVerifiedAt,
    DateTimeOffset ExpiresAt,
    string SessionPurpose,
    bool HasPassword,
    bool HasGoogle,
    string? GoogleEmail,
    bool HasApple,
    string? AppleEmail);

/// <summary>Stable machine-readable Access error code and optional input-field hint.</summary>
internal sealed record AccessErrorResponse(string Error, string? Field = null);
