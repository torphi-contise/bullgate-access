using System.Text.Json;
using System.Text.Json.Serialization;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.Administration;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>Access-owned administrative operations; no consumer bearer authorizes these routes.</summary>
internal static class AccessAdministrationEndpoints
{
    private static readonly JsonSerializerOptions ConfigurationJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        AllowDuplicateProperties = false,
        Converters = { new JsonStringEnumConverter() },
    };

    public static IEndpointRouteBuilder MapAccessAdministrationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/admin/v1").WithTags("Access administration")
            .RequireAuthorization(AdminServiceAuthenticationExtensions.Scheme);
        group.MapGet("/capabilities", () => Results.Ok(new { contractVersion = 1, permissions = AccessPermission.Administrative }));

        Protect(group.MapGet("/realms/{realmId:guid}/identities", async (
            HttpContext http, AccessAdministrationService service, Guid realmId, Guid? identityId,
            string? email, string? phone, int? pageSize, string? cursor, CancellationToken cancellationToken) =>
            Results.Ok(await service.ListIdentitiesAsync(Context(http),
                new AdminIdentityQuery(realmId, identityId, email, phone, pageSize ?? 25, cursor), cancellationToken))),
            AccessPermission.ListIdentities);

        Protect(group.MapGet("/realms/{realmId:guid}/identities/{identityId:guid}", async (
            HttpContext http, AccessAdministrationService service, Guid realmId, Guid identityId, CancellationToken cancellationToken) =>
            Results.Ok(await service.ReadIdentityAsync(Context(http), realmId, identityId, cancellationToken))),
            AccessPermission.ReadIdentities);

        Protect(group.MapPost("/realms/{realmId:guid}/identities/{identityId:guid}/sessions/revoke", async (
            HttpContext http, AccessAdministrationService service, Guid realmId, Guid identityId, CancellationToken cancellationToken) =>
            Results.Ok(await service.RevokeSessionsAsync(Context(http), realmId, identityId, OperationId(http), cancellationToken))),
            AccessPermission.RevokeAllSessions);

        Protect(group.MapDelete("/realms/{realmId:guid}/identities/{identityId:guid}", async (
            HttpContext http, AccessAdministrationService service, Guid realmId, Guid identityId, CancellationToken cancellationToken) =>
            Results.Ok(await service.DeleteIdentityAsync(Context(http), realmId, identityId, OperationId(http), cancellationToken))),
            AccessPermission.DeleteIdentities);

        Protect(group.MapGet("/environments", async (
            HttpContext http, AccessAdministrationService service, int? pageSize, string? cursor, CancellationToken cancellationToken) =>
            Results.Ok(await service.ListEnvironmentsAsync(Context(http), pageSize ?? 25, cursor, cancellationToken))),
            AccessPermission.ManageConfiguration);

        Protect(group.MapPut("/environments/{environmentId:guid}/configuration", async (
            HttpContext http, AccessAdministrationService service, Guid environmentId, CancellationToken cancellationToken) =>
        {
            if (http.Request.Headers.IfMatch.Count != 1) throw InvalidInput();
            var configuration = await http.Request.ReadFromJsonAsync<AppEnvironmentConfiguration>(ConfigurationJson, cancellationToken)
                ?? throw InvalidInput();
            var result = await service.ReplaceConfigurationAsync(Context(http), environmentId, OperationId(http),
                http.Request.Headers.IfMatch.ToString(), configuration, cancellationToken);
            http.Response.Headers.ETag = result.Revision;
            return Results.Ok(result);
        }), AccessPermission.ManageConfiguration);
        return endpoints;
    }

    private static void Protect(RouteHandlerBuilder route, string permission)
    {
        route.WithMetadata(new AdminFunction(permission))
            .RequireAuthorization(AdminServiceAuthenticationExtensions.Policy(permission))
            .AddEndpointFilter(async (invocation, next) =>
            {
                try { return await next(invocation); }
                catch (AccessAdministrationException exception)
                { return Results.Json(new { code = exception.Code }, statusCode: exception.StatusCode); }
                catch (Exception exception) when (exception is JsonException or ArgumentException or BadHttpRequestException)
                { return Results.BadRequest(new { code = "admin-input-invalid" }); }
            });
    }

    private static AdminCallContext Context(HttpContext http) =>
        http.Items[AdminServiceAuthenticationExtensions.ContextItem] as AdminCallContext
        ?? throw new AccessAdministrationException(401, "admin-context-invalid");

    private static Guid OperationId(HttpContext http)
    {
        var values = http.Request.Headers["X-Bullgate-Operation-Id"];
        if (values.Count != 1 || !Guid.TryParseExact(values[0], "D", out var id) || id == Guid.Empty)
            throw InvalidInput();
        return id;
    }
    private static AccessAdministrationException InvalidInput() => new(400, "admin-input-invalid");
}
