using System.Security.Claims;
using System.Text.Json;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Api.Endpoints;

/// <summary>
/// Maps public application-client metadata selected within the integration
/// credential's environment; the public client key is a selector, not authorization.
/// </summary>
internal static class ApplicationClientConfigurationEndpoints
{
    public static IEndpointRouteBuilder MapApplicationClientConfigurationEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
                "/v1/config/application-clients/{applicationClientKey}",
                GetAsync)
            .RequireAuthorization(AccessPermission.ExecuteFlows)
            .WithTags("Configuration");

        return endpoints;
    }

    private static async Task<IResult> GetAsync(
        string applicationClientKey,
        ClaimsPrincipal principal,
        ApplicationClientPublicConfigurationService configurations,
        CancellationToken cancellationToken)
    {
        var environment = principal.FindFirstValue(
            IntegrationClientAuthenticationDefaults.AppEnvironmentIdClaim);
        if (!Guid.TryParseExact(environment, "D", out var appEnvironmentId))
        {
            throw new InvalidOperationException(
                "Authenticated integration client scope is incomplete.");
        }

        var configuration = await configurations.FindAsync(
            appEnvironmentId,
            applicationClientKey,
            cancellationToken);
        return configuration is null
            ? Results.NotFound(new ApplicationClientConfigurationErrorResponse(
                "application-client-invalid",
                "applicationClientKey"))
            : Results.Ok(new ApplicationClientConfigurationResponse(
                configuration.ConfigurationVersion,
                configuration.Common,
                new ApplicationClientConfigurationMetadataResponse(
                    configuration.Client.Key,
                    configuration.Client.Name,
                    configuration.Client.Platform,
                    configuration.Client.ApplicationId,
                    configuration.Client.SigningIdentity,
                    configuration.Client.SmsRetrieverAppHash,
                    configuration.Client.Configuration)));
    }
}

/// <summary>
/// Versioned common and build-specific configuration explicitly classified as public.
/// </summary>
internal sealed record ApplicationClientConfigurationResponse(
    int ConfigurationVersion,
    JsonElement Common,
    ApplicationClientConfigurationMetadataResponse Client);

/// <summary>
/// Public application-build identity and platform metadata selected inside the
/// authenticated environment.
/// </summary>
internal sealed record ApplicationClientConfigurationMetadataResponse(
    string Key,
    string Name,
    string Platform,
    string? ApplicationId,
    string? SigningIdentity,
    string? SmsRetrieverAppHash,
    JsonElement Configuration);

/// <summary>Stable error returned when the public client selector is invalid.</summary>
internal sealed record ApplicationClientConfigurationErrorResponse(
    string Error,
    string Field);
