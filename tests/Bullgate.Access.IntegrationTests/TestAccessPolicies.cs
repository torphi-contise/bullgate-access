using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.IntegrationTests;

internal static class TestAccessPolicies
{
    public static AppAccessPolicy Create(
        bool emailEnabled = true,
        bool emailRequired = true,
        bool cpfEnabled = false,
        bool phoneEnabled = true,
        bool phoneRequired = false,
        bool phoneVerificationEnabled = true,
        bool passwordEnabled = true,
        bool googleEnabled = false,
        bool appleEnabled = false,
        CpfCollectionPosition? cpfCollectionPosition = null) =>
        new(
            new IdentifierAccessPolicy(
                emailEnabled,
                emailRequired,
                IdentifierVerificationPolicy.Disabled),
            new IdentifierAccessPolicy(
                phoneEnabled,
                phoneRequired,
                phoneEnabled && phoneVerificationEnabled
                    ? new IdentifierVerificationPolicy(
                        true,
                        VerificationProviderKey.TwilioVerify)
                    : IdentifierVerificationPolicy.Disabled),
            new AuthenticatorAccessPolicy(
                passwordEnabled,
                googleEnabled,
                appleEnabled),
            new IdentifierAccessPolicy(
                cpfEnabled,
                cpfEnabled,
                IdentifierVerificationPolicy.Disabled),
            cpfCollectionPosition);
}

internal static class TestEnvironmentConfigurations
{
    public static AppVerificationPolicy VerificationPolicy { get; } = new(
        CodeLifetimeMinutes: 10,
        MaxAttempts: 5,
        MaxRequestsPerHourPerIdentity: 5,
        ResendCooldownSeconds: 120,
        PhoneConflictLifetimeMinutes: 15,
        PhoneConflictEmailMaxAttempts: 5);

    public static AppRecoveryPolicy RecoveryPolicy(string? passwordRecoveryUrl = null) => new(
        PasswordRecoveryUrl: passwordRecoveryUrl,
        TokenLifetimeMinutes: 60,
        MaxRequestsPerHourPerIdentity: 5,
        PhoneCodeLifetimeMinutes: 10,
        PhoneCodeMaxAttempts: 5,
        PhoneMaxRequestsPerHourPerIdentity: 5,
        PhoneResendCooldownSeconds: 120);

    public static AppEnvironmentProviders Providers(
        AppAccessPolicy accessPolicy,
        string? passwordRecoveryUrl = null) =>
        new(
            passwordRecoveryUrl is null
                ? null
                : new SmtpProviderConfiguration(
                    Host: "smtp.example.test",
                    Port: 587,
                    User: "test-user",
                    Password: "test-password",
                    FromAddress: "access@example.test",
                    FromName: "Bullgate tests",
                    UseStartTls: true,
                    UseSsl: false),
            accessPolicy.Phone.Enabled
                ? new TwilioVerifyProviderConfiguration(
                    KeySid: "test-key-sid",
                    KeySecret: "test-secret",
                    ServiceSid: "test-service-sid",
                    Channel: "sms",
                    Locale: "en-US",
                    PasswordResetTemplateSid: "test-reset-template-sid")
                : null,
            accessPolicy.Authenticators.GoogleEnabled
                ? new GoogleProviderConfiguration("test-google-client-id")
                : null,
            accessPolicy.Authenticators.AppleEnabled
                ? new AppleProviderConfiguration("test-apple-client-id")
                : null);

    public static DevelopmentBypassConfiguration DevelopmentBypass(
        AppAccessPolicy accessPolicy) =>
        accessPolicy.Phone.Enabled
            ? new DevelopmentBypassConfiguration(
                Enabled: true,
                Phone: "+15555550123",
                Code: "123456")
            : new DevelopmentBypassConfiguration(
                Enabled: false,
                Phone: null,
                Code: null);
}
