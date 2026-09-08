using Bullgate.Access.Application.Administration;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Cryptography;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Application.Identities;
using Bullgate.Access.Application.IntegrationClients;
using Bullgate.Access.Application.Policies;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Application.Social;
using Bullgate.Access.Infrastructure.Administration;
using Bullgate.Access.Infrastructure.Bootstrap;
using Bullgate.Access.Infrastructure.Configuration;
using Bullgate.Access.Infrastructure.Cryptography;
using Bullgate.Access.Infrastructure.EmailPassword;
using Bullgate.Access.Infrastructure.Flows;
using Bullgate.Access.Infrastructure.Identities;
using Bullgate.Access.Infrastructure.IntegrationClients;
using Bullgate.Access.Infrastructure.Persistence;
using Bullgate.Access.Infrastructure.Policies;
using Bullgate.Access.Infrastructure.Recovery;
using Bullgate.Access.Infrastructure.Social;
using Bullgate.Access.Infrastructure.Verification;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.Infrastructure;

/// <summary>Registers PostgreSQL persistence, cryptography, and provider adapters.</summary>
public static class DependencyInjection
{
    /// <summary>Configuration name of the PostgreSQL connection string.</summary>
    public const string ConnectionStringName = "AccessDatabase";

    /// <summary>
    /// Registers PostgreSQL persistence, protected configuration, credentials, provider
    /// adapters, and all application port implementations.
    /// </summary>
    /// <remarks>
    /// This registration validates connection-string presence but does not connect to
    /// PostgreSQL or external providers. The installation master key is decoded when its
    /// singleton service is first resolved.
    /// </remarks>
    public static IServiceCollection AddAccessInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        string? migrationsAssembly = null)
    {
        var connectionString = configuration.GetConnectionString(ConnectionStringName);

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                $"Connection string '{ConnectionStringName}' is required.");
        }

        services.AddDbContextPool<AccessDbContext>(options =>
            options.UseNpgsql(connectionString, postgres =>
            {
                if (!string.IsNullOrWhiteSpace(migrationsAssembly))
                {
                    postgres.MigrationsAssembly(migrationsAssembly);
                }
            }));

        services.AddSingleton<IInstallationKeyDeriver, InstallationKeyDeriver>();
        services.AddSingleton<
            IAppEnvironmentConfigurationProtector,
            AppEnvironmentConfigurationProtector>();
        services.AddScoped<
            IAppEnvironmentConfigurationReader,
            AppEnvironmentConfigurationReader>();
        services.AddScoped<IAccessTopologyStore, AccessTopologyStore>();
        services.AddScoped<IAccessAdministrationStore, AccessAdministrationStore>();
        services.AddScoped<IEmailPasswordAccessStore, EmailPasswordAccessStore>();
        services.AddScoped<ISocialAccessStore, SocialAccessStore>();
        services.AddScoped<IAccessFlowStore, AccessFlowStore>();
        services.AddScoped<IIdentityEmailStore, IdentityEmailStore>();
        services.AddScoped<IIdentityPhoneStore, IdentityPhoneStore>();
        services.AddScoped<ICurrentIdentityStore, CurrentIdentityStore>();
        services.AddScoped<IAppAccessPolicyReader, AppAccessPolicyReader>();
        services.AddScoped<IPasswordResetStore, PasswordResetStore>();
        services.AddScoped<IPhonePasswordRecoveryStore, PhonePasswordRecoveryStore>();
        services.AddSingleton<IPasswordHashService, AspNetPasswordHashService>();
        services.AddScoped<IGoogleIdentityValidator, GoogleIdentityValidator>();
        services.AddScoped<IAppleIdentityValidator, AppleIdentityValidator>();
        services.AddSingleton<ISessionTokenService, OpaqueSessionTokenService>();
        services.AddSingleton<IPasswordResetTokenService, OpaquePasswordResetTokenService>();
        services.AddSingleton<ISmtpTransport, MailKitSmtpTransport>();
        services.AddScoped<
            IPasswordRecoveryEmailSender,
            SmtpPasswordRecoveryEmailSender>();
        services.AddHttpClient();
        services.AddSingleton<ITwilioVerifyTransport, TwilioVerifyTransport>();
        services.AddScoped<IPhoneVerificationSender, TwilioPhoneVerificationSender>();
        services.AddSingleton<IEmailVerificationSender,
            UnavailableEmailVerificationSender>();
        services.AddSingleton<IIntegrationClientCredentialIssuer, IntegrationClientCredentialIssuer>();
        services.AddScoped<
            IIntegrationClientAuthenticationStore,
            IntegrationClientAuthenticationStore>();

        return services;
    }

    /// <summary>
    /// Adds deterministic AccessFlow capability and terminal-session protection for API
    /// hosts that execute flows.
    /// </summary>
    /// <remarks>
    /// Kept separate so migration and bootstrap hosts can use infrastructure without
    /// resolving an unused bearer-protection protocol.
    /// </remarks>
    public static IServiceCollection AddAccessFlowTokenProtection(
        this IServiceCollection services)
    {
        services.AddSingleton<IAccessFlowTokenService, HmacAccessFlowTokenService>();

        return services;
    }
}
