using System.Security.Claims;
using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Application.IntegrationClients;
using Bullgate.Access.Domain.Topology;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class IntegrationClientAuthenticationHandlerTests
{
    [Fact]
    public async Task ValidBearer_CreatesScopedPrincipalAndEnforcesExactPermission()
    {
        var expected = CreateContext();
        await using var provider = CreateServices(new StubAuthenticator(expected));
        await using var scope = provider.CreateAsyncScope();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
        };
        httpContext.Request.Headers.Authorization = "Bearer valid-token";
        var authentication = scope.ServiceProvider.GetRequiredService<IAuthenticationService>();

        var result = await authentication.AuthenticateAsync(
            httpContext,
            IntegrationClientAuthenticationDefaults.Scheme);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.Equal(
            expected.IntegrationClientId.ToString("D"),
            result.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal(
            expected.AppEnvironmentId.ToString("D"),
            result.Principal.FindFirstValue(
                IntegrationClientAuthenticationDefaults.AppEnvironmentIdClaim));

        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        var executeFlows = await authorization.AuthorizeAsync(
            result.Principal,
            resource: null,
            AccessPermission.ExecuteFlows);
        var blockIdentities = await authorization.AuthorizeAsync(
            result.Principal,
            resource: null,
            AccessPermission.BlockIdentities);

        Assert.True(executeFlows.Succeeded);
        Assert.False(blockIdentities.Succeeded);
    }

    [Fact]
    public async Task InvalidBearer_ChallengesWithGenericUnauthorizedResponse()
    {
        await using var provider = CreateServices(new StubAuthenticator(null));
        await using var scope = provider.CreateAsyncScope();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
        };
        httpContext.Request.Headers.Authorization = "Bearer invalid-token";
        var authentication = scope.ServiceProvider.GetRequiredService<IAuthenticationService>();

        var result = await authentication.AuthenticateAsync(
            httpContext,
            IntegrationClientAuthenticationDefaults.Scheme);
        await authentication.ChallengeAsync(
            httpContext,
            IntegrationClientAuthenticationDefaults.Scheme,
            properties: null);

        Assert.False(result.Succeeded);
        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        Assert.Equal("Bearer", httpContext.Response.Headers.WWWAuthenticate);
        Assert.Equal(0, httpContext.Response.ContentLength ?? 0);
    }

    [Fact]
    public async Task RepeatedBearerValues_AreRejectedBeforeCredentialSelection()
    {
        var authenticator = new StubAuthenticator(CreateContext());
        await using var provider = CreateServices(authenticator);
        await using var scope = provider.CreateAsyncScope();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
        };
        httpContext.Request.Headers.Authorization = new Microsoft.Extensions.Primitives.StringValues(
            ["Bearer first-token", "Bearer second-token"]);
        var authentication = scope.ServiceProvider.GetRequiredService<IAuthenticationService>();

        var result = await authentication.AuthenticateAsync(
            httpContext,
            IntegrationClientAuthenticationDefaults.Scheme);
        await authentication.ChallengeAsync(
            httpContext,
            IntegrationClientAuthenticationDefaults.Scheme,
            properties: null);

        Assert.False(result.Succeeded);
        Assert.True(result.None);
        Assert.Equal(0, authenticator.AuthenticationAttempts);
        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        Assert.Equal("Bearer", httpContext.Response.Headers.WWWAuthenticate);
        Assert.Equal(0, httpContext.Response.ContentLength ?? 0);
    }

    private static ServiceProvider CreateServices(IIntegrationClientAuthenticator authenticator)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddSingleton(authenticator);
        services.AddIntegrationClientAuthentication();
        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        });
    }

    private static IntegrationClientContext CreateContext() =>
        new(
            Guid.Parse("0198f4e8-f048-723a-adf8-2c562434b9d2"),
            Guid.Parse("0198f4e9-2c13-72f1-a665-936d6e06cf48"),
            Guid.Parse("0198f4e9-634b-7bee-b4ce-05e0cae9aeb0"),
            Guid.Parse("0198f4e9-9598-781a-8c76-23d488c5fb8a"),
            Guid.Parse("0198f4e9-c3c2-764c-9469-6156800c8c7d"),
            new HashSet<string>(StringComparer.Ordinal)
            {
                AccessPermission.ExecuteFlows,
                AccessPermission.IntrospectSessions,
            });

    private sealed class StubAuthenticator(IntegrationClientContext? context)
        : IIntegrationClientAuthenticator
    {
        public int AuthenticationAttempts { get; private set; }

        public Task<IntegrationClientContext?> AuthenticateAsync(
            string? credentialToken,
            CancellationToken cancellationToken = default)
        {
            AuthenticationAttempts++;
            return Task.FromResult(context);
        }
    }
}
