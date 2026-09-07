using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Bullgate.Access.Application.IntegrationClients;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Bullgate.Access.Api.Authentication;

/// <summary>
/// Converts one Bearer integration credential into a server-derived principal whose
/// claims contain only authenticated topology ids and stored permissions.
/// </summary>
/// <remarks>
/// Missing or malformed authorization input yields no authentication result. A
/// well-formed but invalid credential fails authentication. Both paths receive the
/// same minimal Bearer challenge and do not disclose which credential check failed.
/// </remarks>
internal sealed class IntegrationClientAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IIntegrationClientAuthenticator authenticator)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Accept exactly one Authorization value. Combining repeated values would make
        // bearer selection dependent on framework header parsing rather than protocol.
        if (Request.Headers.Authorization.Count != 1
            || !AuthenticationHeaderValue.TryParse(
                Request.Headers.Authorization.ToString(),
                out var authorization)
            || !string.Equals(
                authorization.Scheme,
                "Bearer",
                StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(authorization.Parameter))
        {
            return AuthenticateResult.NoResult();
        }

        var context = await authenticator.AuthenticateAsync(
            authorization.Parameter,
            Context.RequestAborted);
        if (context is null)
        {
            return AuthenticateResult.Fail("Invalid integration credential.");
        }

        var claims = new List<Claim>
        {
            // Every scope claim comes from the authenticated database candidate. No
            // route, query, or request-body value is promoted into the principal.
            new(ClaimTypes.NameIdentifier, context.IntegrationClientId.ToString("D")),
            new(
                IntegrationClientAuthenticationDefaults.WorkspaceIdClaim,
                context.WorkspaceId.ToString("D")),
            new(
                IntegrationClientAuthenticationDefaults.AppIdClaim,
                context.AppId.ToString("D")),
            new(
                IntegrationClientAuthenticationDefaults.AppEnvironmentIdClaim,
                context.AppEnvironmentId.ToString("D")),
            new(
                IntegrationClientAuthenticationDefaults.RealmIdClaim,
                context.RealmId.ToString("D")),
        };

        claims.AddRange(context.Permissions.Select(permission => new Claim(
            IntegrationClientAuthenticationDefaults.PermissionClaim,
            permission)));

        var identity = new ClaimsIdentity(
            claims,
            IntegrationClientAuthenticationDefaults.Scheme);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(
            principal,
            IntegrationClientAuthenticationDefaults.Scheme);

        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // Keep the challenge intentionally terse: callers learn that Bearer authority
        // is required, not whether id, secret, expiry, revocation, scope, or shape failed.
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "Bearer";
        return Task.CompletedTask;
    }
}
