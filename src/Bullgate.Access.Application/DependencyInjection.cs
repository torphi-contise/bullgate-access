using Bullgate.Access.Application.Administration;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Application.Identities;
using Bullgate.Access.Application.IntegrationClients;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Application.Social;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.Application;

/// <summary>Registers application-layer orchestrators and their shared time source.</summary>
public static class DependencyInjection
{
    /// <summary>
    /// Adds scoped application use cases and the process-wide UTC time provider.
    /// </summary>
    public static IServiceCollection AddAccessApplication(this IServiceCollection services)
    {
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<BootstrapTopologyHandler>();
        services.AddScoped<AccessAdministrationService>();
        services.AddScoped<EmailPasswordAccessService>();
        services.AddScoped<SocialAccessService>();
        services.AddScoped<AccessFlowService>();
        services.AddScoped<IdentityEmailReader>();
        services.AddScoped<IdentityPhoneReader>();
        services.AddScoped<CurrentIdentityService>();
        services.AddScoped<PasswordResetService>();
        services.AddScoped<EmailPasswordRecoveryService>();
        services.AddScoped<PhonePasswordRecoveryService>();
        services.AddScoped<ApplicationClientPublicConfigurationService>();
        services.AddScoped<IIntegrationClientAuthenticator, IntegrationClientAuthenticator>();

        return services;
    }
}
