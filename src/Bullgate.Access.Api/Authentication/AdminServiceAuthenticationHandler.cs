using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bullgate.Access.Application.Administration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace Bullgate.Access.Api.Authentication;

/// <summary>Authenticates the configured Admin server before accepting its human attestation.</summary>
internal sealed class AdminServiceAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger,
    UrlEncoder encoder, IConfiguration configuration)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private static readonly JsonSerializerOptions ContextJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        AllowDuplicateProperties = false,
    };

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        AuthenticateResult Reject() => AuthenticateResult.Fail("Invalid Admin authority.");
        if (!Request.IsHttps && (Context.Connection.RemoteIpAddress is not { } remote || !IPAddress.IsLoopback(remote)))
            return Task.FromResult(Reject());
        if (Request.Headers.Authorization.Count != 1
            || !AuthenticationHeaderValue.TryParse(Request.Headers.Authorization.ToString(), out var authorization)
            || !string.Equals(authorization.Scheme, AdminServiceAuthenticationExtensions.Scheme, StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(AuthenticateResult.NoResult());

        byte[]? secret = null;
        byte[]? actual = null;
        try
        {
            var configured = configuration[AdminServiceAuthenticationExtensions.CredentialHashSetting];
            if (configured is not { Length: 64 } || authorization.Parameter is not { Length: 43 } token)
                return Task.FromResult(Reject());
            var expected = Convert.FromHexString(configured);
            secret = WebEncoders.Base64UrlDecode(token);
            if (secret.Length != 32 || WebEncoders.Base64UrlEncode(secret) != token)
                return Task.FromResult(Reject());
            actual = SHA256.HashData(secret);
            if (!CryptographicOperations.FixedTimeEquals(actual, expected)) return Task.FromResult(Reject());

            var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, AdminCallContext.CallerId) };
            if (Context.GetEndpoint()?.Metadata.GetMetadata<AdminFunction>() is not null)
            {
                var headers = Request.Headers[AdminServiceAuthenticationExtensions.ContextHeader];
                if (headers.Count != 1 || headers[0] is not { Length: > 0 and <= 2048 } encoded)
                    return Task.FromResult(Reject());
                var bytes = WebEncoders.Base64UrlDecode(encoded);
                if (WebEncoders.Base64UrlEncode(bytes) != encoded) return Task.FromResult(Reject());
                var human = JsonSerializer.Deserialize<AdminCallContext>(bytes, ContextJson);
                if (human is null || !human.IsValid()) return Task.FromResult(Reject());
                claims.Add(new Claim(AdminServiceAuthenticationExtensions.PermissionClaim, human.Permission));
                Context.Items[AdminServiceAuthenticationExtensions.ContextItem] = human;
            }
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name)));
        }
        catch (Exception exception) when (exception is FormatException or JsonException or ArgumentException)
        { return Task.FromResult(Reject()); }
        finally
        {
            if (secret is not null) CryptographicOperations.ZeroMemory(secret);
            if (actual is not null) CryptographicOperations.ZeroMemory(actual);
        }
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = AdminServiceAuthenticationExtensions.Scheme;
        return Task.CompletedTask;
    }
}
