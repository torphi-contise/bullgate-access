using System.Security.Claims;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>
/// Maps the versioned AccessFlow transport contract and translates protocol outcomes
/// to stable HTTP status and error codes.
/// </summary>
internal static class AccessFlowEndpoints
{
    private const string CapabilityHeader = "Bullgate-Flow-Capability";

    /// <summary>
    /// Maps start, action, and read routes under integration-client authentication and
    /// the least privilege required to execute AccessFlow journeys.
    /// </summary>
    public static IEndpointRouteBuilder MapAccessFlowEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/v1/access/flows", StartAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access Flows");
        endpoints.MapPost("/v1/access/flows/{flowId:guid}/actions", ActAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access Flows");
        endpoints.MapGet("/v1/access/flows/{flowId:guid}", GetAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Access Flows");

        return endpoints;
    }

    private static async Task<IResult> StartAsync(
        StartAccessFlowRequest request,
        ClaimsPrincipal principal,
        AccessFlowService flows,
        CancellationToken cancellationToken)
    {
        var result = await flows.StartAsync(
            ReadScope(principal),
            new AccessFlowStartCommand(
                request.RequestId,
                request.ProtocolVersions,
                request.Intent,
                request.ApplicationClientKey,
                request.SessionToken),
            cancellationToken);

        return result.Succeeded
            ? Results.Json(ToResponse(result), statusCode: StatusCodes.Status201Created)
            : ToError(result.Error!.Value);
    }

    private static async Task<IResult> ActAsync(
        Guid flowId,
        AccessFlowActionRequest request,
        ClaimsPrincipal principal,
        HttpContext httpContext,
        AccessFlowService flows,
        CancellationToken cancellationToken)
    {
        var action = request.Action;
        var result = await flows.ActAsync(
            ReadScope(principal),
            flowId,
            ReadCapability(httpContext),
            new AccessFlowActionCommand(
                request.RequestId,
                request.ExpectedRevision,
                action?.Id ?? Guid.Empty,
                action?.Type,
                action?.Input),
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(ToResponse(result))
            : ToError(result.Error!.Value);
    }

    private static async Task<IResult> GetAsync(
        Guid flowId,
        ClaimsPrincipal principal,
        HttpContext httpContext,
        AccessFlowService flows,
        CancellationToken cancellationToken)
    {
        var result = await flows.GetAsync(
            ReadScope(principal),
            flowId,
            ReadCapability(httpContext),
            cancellationToken);

        return result.Succeeded
            ? Results.Ok(ToResponse(result))
            : ToError(result.Error!.Value);
    }

    private static AccessFlowServerResponse ToResponse(AccessFlowResult result) =>
        // Capability and optional issued session are server bearer material. The BFF
        // must retain them while exposing only the semantic snapshot to its application.
        new(
            result.FlowCapability!,
            result.Snapshot!,
            result.IssuedSession);

    private static IResult ToError(AccessFlowError error) => error switch
    {
        AccessFlowError.InvalidRequest => Results.BadRequest(
            new AccessFlowErrorResponse("invalid-request")),
        AccessFlowError.ProtocolVersionUnsupported => Results.Conflict(
            new AccessFlowErrorResponse("protocol-version-unsupported")),
        AccessFlowError.IntentUnsupported => Results.BadRequest(
            new AccessFlowErrorResponse("intent-unsupported", "intent")),
        AccessFlowError.SessionInactive => Results.Json(
            new AccessFlowErrorResponse("session-inactive"),
            statusCode: StatusCodes.Status401Unauthorized),
        AccessFlowError.RegistrationNotPending => Results.Conflict(
            new AccessFlowErrorResponse("registration-not-pending")),
        AccessFlowError.ApplicationClientInvalid => Results.BadRequest(
            new AccessFlowErrorResponse(
                "application-client-invalid",
                "applicationClientKey")),
        AccessFlowError.IntegrationClientConflict => Results.Conflict(
            new AccessFlowErrorResponse("integration-client-conflict")),
        AccessFlowError.RequestIdConflict => Results.Conflict(
            new AccessFlowErrorResponse("request-id-conflict", "requestId")),
        // Missing, malformed, incorrectly scoped, and non-matching capabilities collapse
        // to the same absence response so a flow UUID is never an enumeration oracle.
        AccessFlowError.FlowNotFound => Results.NotFound(
            new AccessFlowErrorResponse("flow-not-found")),
        AccessFlowError.RevisionConflict => Results.Conflict(
            new AccessFlowErrorResponse("revision-conflict", "expectedRevision")),
        AccessFlowError.ActionNotAvailable => Results.Conflict(
            new AccessFlowErrorResponse("action-not-available", "action")),
        AccessFlowError.DeliveryUnavailable => Results.Json(
            new AccessFlowErrorResponse("verification-delivery-unavailable"),
            statusCode: StatusCodes.Status503ServiceUnavailable),
        AccessFlowError.PasswordRecoveryRateLimited => Results.Json(
            new AccessFlowErrorResponse("password-recovery-rate-limited"),
            statusCode: StatusCodes.Status429TooManyRequests),
        AccessFlowError.PasswordRecoveryUnavailable => Results.Json(
            new AccessFlowErrorResponse("password-recovery-unavailable"),
            statusCode: StatusCodes.Status503ServiceUnavailable),
        AccessFlowError.FlowCreationUnavailable => Results.Json(
            new AccessFlowErrorResponse("flow-creation-unavailable"),
            statusCode: StatusCodes.Status503ServiceUnavailable),
        _ => throw new ArgumentOutOfRangeException(nameof(error), error, null),
    };

    private static string? ReadCapability(HttpContext httpContext) =>
        // Exactly one header value is required. Combining repeated bearer capabilities
        // would create an ambiguous authority string.
        httpContext.Request.Headers.TryGetValue(CapabilityHeader, out var values)
        && values.Count == 1
            ? values.ToString()
            : null;

    private static AccessFlowScope ReadScope(ClaimsPrincipal principal)
    {
        var integrationClient = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var environment = principal.FindFirstValue(
            IntegrationClientAuthenticationDefaults.AppEnvironmentIdClaim);
        var realm = principal.FindFirstValue(
            IntegrationClientAuthenticationDefaults.RealmIdClaim);

        if (!Guid.TryParseExact(integrationClient, "D", out var integrationClientId)
            || !Guid.TryParseExact(environment, "D", out var appEnvironmentId)
            || !Guid.TryParseExact(realm, "D", out var realmId))
        {
            throw new InvalidOperationException(
                "Authenticated integration client scope is incomplete.");
        }

        return new AccessFlowScope(integrationClientId, appEnvironmentId, realmId);
    }
}

/// <summary>
/// Starts or exactly replays a version-negotiated flow from a server-held source
/// session and public application-client selector.
/// </summary>
internal sealed record StartAccessFlowRequest(
    Guid RequestId,
    IReadOnlyList<int>? ProtocolVersions,
    string? Intent,
    string? ApplicationClientKey,
    string? SessionToken);

/// <summary>
/// Executes one action advertised by the expected flow revision under a caller-created
/// idempotency request id.
/// </summary>
internal sealed record AccessFlowActionRequest(
    Guid RequestId,
    int ExpectedRevision,
    AccessFlowActionSubmission? Action);

/// <summary>
/// Action id, semantic type, and optional type-specific JSON input copied from the
/// current server-advertised action contract.
/// </summary>
internal sealed record AccessFlowActionSubmission(
    Guid Id,
    string? Type,
    System.Text.Json.JsonElement? Input);

/// <summary>
/// Authorized flow snapshot plus server bearer capability and optional terminal
/// product session.
/// </summary>
/// <remarks>
/// A consumer BFF must retain `FlowCapability` and any issued session token; application
/// code should receive the semantic snapshot and product-specific result only.
/// </remarks>
internal sealed record AccessFlowServerResponse(
    string FlowCapability,
    AccessFlowSnapshot Snapshot,
    AccessFlowIssuedSession? IssuedSession);

/// <summary>Stable flow error code and optional invalid or conflicting field hint.</summary>
internal sealed record AccessFlowErrorResponse(string Error, string? Field = null);
