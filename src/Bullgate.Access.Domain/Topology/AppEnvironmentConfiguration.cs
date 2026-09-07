using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bullgate.Access.Domain.Topology;

/// <summary>
/// Complete protected configuration document for one application environment.
/// </summary>
/// <remarks>
/// This model contains provider secrets and must never be returned as public client
/// configuration. The whole serialized document is encrypted before persistence.
/// </remarks>
[method: JsonConstructor]
public sealed record AppEnvironmentConfiguration(
    AppAccessPolicy AccessPolicy,
    AppVerificationPolicy VerificationPolicy,
    AppRecoveryPolicy RecoveryPolicy,
    AppEnvironmentProviders Providers,
    DevelopmentBypassConfiguration DevelopmentBypass,
    AppEnvironmentPublicConfiguration PublicConfiguration,
    IReadOnlyList<AppEnvironmentIntegrationClientConfiguration> IntegrationClients,
    IReadOnlyList<AppEnvironmentApplicationClientConfiguration> ApplicationClients)
{
    /// <summary>
    /// Creates a configuration using the original empty version-1 public document for
    /// callers that do not yet supply public metadata.
    /// </summary>
    public AppEnvironmentConfiguration(
        AppAccessPolicy accessPolicy,
        AppVerificationPolicy verificationPolicy,
        AppRecoveryPolicy recoveryPolicy,
        AppEnvironmentProviders providers,
        DevelopmentBypassConfiguration developmentBypass,
        IReadOnlyList<AppEnvironmentIntegrationClientConfiguration> integrationClients,
        IReadOnlyList<AppEnvironmentApplicationClientConfiguration> applicationClients)
        : this(
            accessPolicy,
            verificationPolicy,
            recoveryPolicy,
            providers,
            developmentBypass,
            new AppEnvironmentPublicConfiguration(
                1,
                JsonSerializer.SerializeToElement(new { })),
            integrationClients,
            applicationClients)
    {
    }
}

/// <summary>Versioned, explicitly public values shared by application clients.</summary>
public sealed record AppEnvironmentPublicConfiguration(
    int Version,
    JsonElement Values);

/// <summary>Attempt, lifetime, resend, rate, and conflict limits for proofs.</summary>
public sealed record AppVerificationPolicy(
    int CodeLifetimeMinutes,
    int MaxAttempts,
    int MaxRequestsPerHourPerIdentity,
    int ResendCooldownSeconds,
    int PhoneConflictLifetimeMinutes,
    int PhoneConflictEmailMaxAttempts);

/// <summary>Token and phone-recovery policy for one environment.</summary>
public sealed record AppRecoveryPolicy(
    string? PasswordRecoveryUrl,
    int TokenLifetimeMinutes,
    int MaxRequestsPerHourPerIdentity,
    int PhoneCodeLifetimeMinutes,
    int PhoneCodeMaxAttempts,
    int PhoneMaxRequestsPerHourPerIdentity,
    int PhoneResendCooldownSeconds);

/// <summary>Optional external provider configurations owned by one environment.</summary>
/// <remarks>
/// Presence means configuration is available to the corresponding adapter; it is not
/// a live provider health result. This object belongs to protected configuration and
/// must never be projected as public application-client metadata.
/// </remarks>
/// <param name="Smtp">Optional password-recovery e-mail delivery configuration.</param>
/// <param name="TwilioVerify">Optional phone-code delivery and lifecycle configuration.</param>
/// <param name="Google">Optional Google server-side token-validation configuration.</param>
/// <param name="Apple">Optional Apple server-side token-validation configuration.</param>
public sealed record AppEnvironmentProviders(
    SmtpProviderConfiguration? Smtp,
    TwilioVerifyProviderConfiguration? TwilioVerify,
    GoogleProviderConfiguration? Google,
    AppleProviderConfiguration? Apple);

/// <summary>SMTP delivery settings, including protected authentication material.</summary>
/// <remarks>
/// Bootstrap requires user and password together, rejects simultaneous STARTTLS and
/// implicit SSL, and validates the sender address. A null user selects anonymous SMTP;
/// leaving both transport-security flags false delegates connection-mode selection to
/// MailKit.
/// </remarks>
/// <param name="Host">SMTP server host name.</param>
/// <param name="Port">TCP port in the inclusive range 1–65535.</param>
/// <param name="User">Optional authentication identity; null selects anonymous SMTP.</param>
/// <param name="Password">Optional clear provider secret paired with <paramref name="User"/>.</param>
/// <param name="FromAddress">Validated envelope and message sender address.</param>
/// <param name="FromName">Display name sanitized before MIME header construction.</param>
/// <param name="UseStartTls">Requires STARTTLS after connecting when true.</param>
/// <param name="UseSsl">Requires implicit TLS on connection when true.</param>
public sealed record SmtpProviderConfiguration(
    string Host,
    int Port,
    string? User,
    string? Password,
    string FromAddress,
    string FromName,
    bool UseStartTls,
    bool UseSsl);

/// <summary>Twilio Verify delivery settings and optional recovery template.</summary>
/// <remarks>
/// All values are server-side protected configuration. The password-reset template is
/// considered only for that journey and is ignored unless it has the expected Twilio
/// template SID shape.
/// </remarks>
/// <param name="KeySid">API-key username used for HTTP Basic authentication.</param>
/// <param name="KeySecret">Clear API-key secret used only at the provider boundary.</param>
/// <param name="ServiceSid">Verify service containing created verification resources.</param>
/// <param name="Channel">Provider delivery channel, such as <c>sms</c>.</param>
/// <param name="Locale">Provider message locale.</param>
/// <param name="PasswordResetTemplateSid">Optional recovery-only content template.</param>
public sealed record TwilioVerifyProviderConfiguration(
    string KeySid,
    string KeySecret,
    string ServiceSid,
    string Channel,
    string Locale,
    string? PasswordResetTemplateSid);

/// <summary>Server-side Google token-validation configuration.</summary>
/// <param name="ClientId">
/// Trusted audience or authorized-party value loaded from protected configuration.
/// </param>
public sealed record GoogleProviderConfiguration(string ClientId);

/// <summary>Server-side Apple token-validation configuration.</summary>
/// <param name="ClientId">
/// Trusted audience value loaded from protected configuration, such as an application
/// or service identifier accepted by Apple.
/// </param>
public sealed record AppleProviderConfiguration(string ClientId);

/// <summary>
/// Explicit development-only bypass. Production manifests must not enable it.
/// </summary>
public sealed record DevelopmentBypassConfiguration(
    bool Enabled,
    string? Phone,
    string? Code);

/// <summary>Protected configuration projection for a trusted integration client.</summary>
public sealed record AppEnvironmentIntegrationClientConfiguration(
    string Key,
    string Name,
    IReadOnlyList<string> Permissions);

/// <summary>Public metadata and configuration for one application-client key.</summary>
public sealed record AppEnvironmentApplicationClientConfiguration(
    string Key,
    string Name,
    ApplicationClientPlatform Platform,
    string? ApplicationId,
    string? SigningIdentity,
    string? SmsRetrieverAppHash,
    JsonElement PublicConfiguration);
