using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Topology;

/// <summary>
/// Root of the strict version 2 bootstrap document and adapter to the application-layer
/// topology command.
/// </summary>
internal sealed class BootstrapManifest
{
    /// <summary>Explicit schema version interpreted before any nested conversion.</summary>
    public required int ManifestVersion { get; init; }

    /// <summary>Single workspace topology owned by this bootstrap document.</summary>
    public required BootstrapWorkspaceManifest Workspace { get; init; }

    /// <summary>
    /// Validates the version and complete nullable JSON shape, then creates the
    /// application-layer command without retaining serializer-owned JSON elements.
    /// </summary>
    public BootstrapTopologyCommand ToCommand()
    {
        // Version is checked before interpreting nested data. A future shape must have
        // an explicit adapter rather than being guessed by this version 2 reader.
        if (ManifestVersion != 2)
        {
            throw new BootstrapTopologyException(
                $"Unsupported manifestVersion '{ManifestVersion}'. Supported version: 2.");
        }

        ValidateShape();

        return new BootstrapTopologyCommand(
            Workspace.Key,
            Workspace.Name,
            Workspace.Apps.Select(app => new BootstrapAppDefinition(
                app.Key,
                app.Name,
                app.Realms.Select(realm => new BootstrapRealmDefinition(
                    realm.Key,
                    realm.Name)).ToArray(),
                app.Environments.Select(environment => new BootstrapEnvironmentDefinition(
                    environment.Key,
                    environment.Name,
                    environment.RealmKey,
                    CreateAccessPolicy(
                        environment.AccessPolicy,
                        $"workspace.apps[{app.Key}].environments[{environment.Key}]"
                        + ".accessPolicy"),
                    CreateVerificationPolicy(environment.VerificationPolicy),
                    CreateRecoveryPolicy(environment.RecoveryPolicy),
                    CreateProviders(environment.Providers),
                    new DevelopmentBypassConfiguration(
                        environment.DevelopmentBypass.Enabled,
                        environment.DevelopmentBypass.Phone,
                        environment.DevelopmentBypass.Code),
                    new AppEnvironmentPublicConfiguration(
                        environment.PublicConfiguration.Version,
                        // Detach public JSON from the deserializer-owned element before
                        // it crosses into the longer-lived application command.
                        environment.PublicConfiguration.Values.Clone()),
                    environment.IntegrationClients.Select(client =>
                        new BootstrapIntegrationClientDefinition(
                            client.Key,
                            client.Name,
                            client.Permissions)).ToArray(),
                    environment.ApplicationClients.Select(client =>
                        new BootstrapApplicationClientDefinition(
                            client.Key,
                            client.Name,
                            ParsePlatform(client.Platform, client.Key),
                            client.ApplicationId,
                            client.SigningIdentity,
                            client.SmsRetrieverAppHash,
                            // Application-client JSON is opaque public metadata, but it
                            // still receives an independent element lifetime.
                            client.PublicConfiguration.Clone())).ToArray())).ToArray())).ToArray());
    }

    private void ValidateShape()
    {
        // `required` protects typed construction but nested reference values can still
        // deserialize as null. Validate the complete tree before creating any domain
        // value or opening the bootstrap transaction.
        Require(Workspace, "workspace");
        Require(Workspace.Apps, "workspace.apps");

        for (var appIndex = 0; appIndex < Workspace.Apps.Count; appIndex++)
        {
            var app = Require(Workspace.Apps[appIndex], $"workspace.apps[{appIndex}]");
            Require(app.Realms, $"workspace.apps[{appIndex}].realms");
            Require(app.Environments, $"workspace.apps[{appIndex}].environments");

            for (var realmIndex = 0; realmIndex < app.Realms.Count; realmIndex++)
            {
                Require(app.Realms[realmIndex], $"workspace.apps[{appIndex}].realms[{realmIndex}]");
            }

            for (var environmentIndex = 0;
                 environmentIndex < app.Environments.Count;
                 environmentIndex++)
            {
                var path = $"workspace.apps[{appIndex}].environments[{environmentIndex}]";
                var environment = Require(app.Environments[environmentIndex], path);
                Require(environment.IntegrationClients, $"{path}.integrationClients");
                Require(environment.ApplicationClients, $"{path}.applicationClients");
                Require(environment.VerificationPolicy, $"{path}.verificationPolicy");
                Require(environment.RecoveryPolicy, $"{path}.recoveryPolicy");
                Require(environment.Providers, $"{path}.providers");
                Require(environment.DevelopmentBypass, $"{path}.developmentBypass");
                Require(environment.PublicConfiguration, $"{path}.publicConfiguration");
                RequireJsonObject(
                    environment.PublicConfiguration.Values,
                    $"{path}.publicConfiguration.values");

                var policyPath = $"{path}.accessPolicy";
                var policy = Require(environment.AccessPolicy, policyPath);
                var identifiers = Require(policy.Identifiers, $"{policyPath}.identifiers");
                var email = Require(identifiers.Email, $"{policyPath}.identifiers.email");
                var phone = Require(identifiers.Phone, $"{policyPath}.identifiers.phone");
                Require(email.Verification, $"{policyPath}.identifiers.email.verification");
                Require(phone.Verification, $"{policyPath}.identifiers.phone.verification");
                Require(policy.Authenticators, $"{policyPath}.authenticators");

                for (var clientIndex = 0;
                     clientIndex < environment.IntegrationClients.Count;
                     clientIndex++)
                {
                    var client = Require(
                        environment.IntegrationClients[clientIndex],
                        $"{path}.integrationClients[{clientIndex}]");
                    Require(client.Permissions, $"{path}.integrationClients[{clientIndex}].permissions");
                }

                for (var clientIndex = 0;
                     clientIndex < environment.ApplicationClients.Count;
                     clientIndex++)
                {
                    var client = Require(
                        environment.ApplicationClients[clientIndex],
                        $"{path}.applicationClients[{clientIndex}]");
                    RequireJsonObject(
                        client.PublicConfiguration,
                        $"{path}.applicationClients[{clientIndex}].publicConfiguration");
                }
            }
        }
    }

    private static T Require<T>(T? value, string path)
        where T : class =>
        value ?? throw new BootstrapTopologyException($"'{path}' cannot be null.");

    private static void RequireJsonObject(JsonElement value, string path)
    {
        // Public configuration is intentionally open-ended JSON, but its top-level
        // object shape is stable so consumers never receive a scalar or array instead.
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new BootstrapTopologyException($"'{path}' must be a JSON object.");
        }
    }

    private static AppAccessPolicy CreateAccessPolicy(
        BootstrapAccessPolicyManifest policy,
        string path)
    {
        try
        {
            return new AppAccessPolicy(
                CreateIdentifierPolicy(policy.Identifiers.Email),
                CreateIdentifierPolicy(policy.Identifiers.Phone),
                new AuthenticatorAccessPolicy(
                    policy.Authenticators.Password,
                    policy.Authenticators.Google,
                    policy.Authenticators.Apple));
        }
        catch (ArgumentException exception)
        {
            // Preserve the manifest path when a domain invariant rejects policy. The
            // operator should not need to infer which environment supplied the value.
            throw new BootstrapTopologyException(
                $"Invalid access policy at '{path}': {exception.Message}");
        }
    }

    private static IdentifierAccessPolicy CreateIdentifierPolicy(
        BootstrapIdentifierPolicyManifest policy) =>
        new(
            policy.Enabled,
            policy.Required,
            new IdentifierVerificationPolicy(
                policy.Verification.Enabled,
                policy.Verification.Provider));

    private static AppVerificationPolicy CreateVerificationPolicy(
        BootstrapEnvironmentVerificationPolicyManifest policy) =>
        new(
            policy.CodeLifetimeMinutes,
            policy.MaxAttempts,
            policy.MaxRequestsPerHourPerIdentity,
            policy.ResendCooldownSeconds,
            policy.PhoneConflictLifetimeMinutes,
            policy.PhoneConflictEmailMaxAttempts);

    private static AppRecoveryPolicy CreateRecoveryPolicy(
        BootstrapRecoveryPolicyManifest policy) =>
        new(
            policy.PasswordRecoveryUrl,
            policy.TokenLifetimeMinutes,
            policy.MaxRequestsPerHourPerIdentity,
            policy.PhoneCodeLifetimeMinutes,
            policy.PhoneCodeMaxAttempts,
            policy.PhoneMaxRequestsPerHourPerIdentity,
            policy.PhoneResendCooldownSeconds);

    private static AppEnvironmentProviders CreateProviders(
        BootstrapProvidersManifest providers) =>
        new(
            providers.Smtp is null
                ? null
                : new SmtpProviderConfiguration(
                    providers.Smtp.Host,
                    providers.Smtp.Port,
                    providers.Smtp.User,
                    providers.Smtp.Password,
                    providers.Smtp.FromAddress,
                    providers.Smtp.FromName,
                    providers.Smtp.UseStartTls,
                    providers.Smtp.UseSsl),
            providers.TwilioVerify is null
                ? null
                : new TwilioVerifyProviderConfiguration(
                    providers.TwilioVerify.KeySid,
                    providers.TwilioVerify.KeySecret,
                    providers.TwilioVerify.ServiceSid,
                    providers.TwilioVerify.Channel,
                    providers.TwilioVerify.Locale,
                    providers.TwilioVerify.PasswordResetTemplateSid),
            providers.Google is null
                ? null
                : new GoogleProviderConfiguration(providers.Google.ClientId),
            providers.Apple is null
                ? null
                : new AppleProviderConfiguration(providers.Apple.ClientId));

    private static ApplicationClientPlatform ParsePlatform(string platform, string key) =>
        // Exact lowercase wire names keep the manifest deterministic and independent of
        // enum member casing or future enum aliases.
        platform switch
        {
            "android" => ApplicationClientPlatform.Android,
            "ios" => ApplicationClientPlatform.Ios,
            "web" => ApplicationClientPlatform.Web,
            _ => throw new BootstrapTopologyException(
                $"Application client '{key}' has unsupported platform '{platform}'."),
        };
}

/// <summary>Manifest workspace and its complete application collection.</summary>
internal sealed class BootstrapWorkspaceManifest
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public required IReadOnlyList<BootstrapAppManifest> Apps { get; init; }
}

/// <summary>Manifest application with realm definitions and deployable environments.</summary>
internal sealed class BootstrapAppManifest
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public required IReadOnlyList<BootstrapRealmManifest> Realms { get; init; }
    public required IReadOnlyList<BootstrapEnvironmentManifest> Environments { get; init; }
}

/// <summary>Manifest realm that defines an identity uniqueness boundary.</summary>
internal sealed class BootstrapRealmManifest
{
    public required string Key { get; init; }
    public required string Name { get; init; }
}

/// <summary>
/// Manifest environment containing policy, providers, clients, and public metadata.
/// </summary>
internal sealed class BootstrapEnvironmentManifest
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public required string RealmKey { get; init; }
    public required BootstrapAccessPolicyManifest AccessPolicy { get; init; }
    public required BootstrapEnvironmentVerificationPolicyManifest VerificationPolicy { get; init; }
    public required BootstrapRecoveryPolicyManifest RecoveryPolicy { get; init; }
    public required BootstrapProvidersManifest Providers { get; init; }
    public required BootstrapDevelopmentBypassManifest DevelopmentBypass { get; init; }
    public required BootstrapPublicConfigurationManifest PublicConfiguration { get; init; }
    public required IReadOnlyList<BootstrapIntegrationClientManifest> IntegrationClients { get; init; }
    public required IReadOnlyList<BootstrapApplicationClientManifest> ApplicationClients { get; init; }
}

/// <summary>Versioned public environment JSON safe to return to application clients.</summary>
internal sealed class BootstrapPublicConfigurationManifest
{
    public required int Version { get; init; }
    public required JsonElement Values { get; init; }
}

/// <summary>Manifest identifier and authenticator policy for one environment.</summary>
internal sealed class BootstrapAccessPolicyManifest
{
    public required BootstrapIdentifierPoliciesManifest Identifiers { get; init; }
    public required BootstrapAuthenticatorPolicyManifest Authenticators { get; init; }
}

/// <summary>Manifest e-mail and phone policy pair.</summary>
internal sealed class BootstrapIdentifierPoliciesManifest
{
    public required BootstrapIdentifierPolicyManifest Email { get; init; }
    public required BootstrapIdentifierPolicyManifest Phone { get; init; }
}

/// <summary>Manifest enablement, requirement, and verification rules for one identifier.</summary>
internal sealed class BootstrapIdentifierPolicyManifest
{
    public required bool Enabled { get; init; }
    public required bool Required { get; init; }
    public required BootstrapIdentifierVerificationPolicyManifest Verification { get; init; }
}

/// <summary>Manifest verification enablement and optional provider key.</summary>
internal sealed class BootstrapIdentifierVerificationPolicyManifest
{
    public required bool Enabled { get; init; }
    public string? Provider { get; init; }
}

/// <summary>Manifest enablement flags for password, Google, and Apple authenticators.</summary>
internal sealed class BootstrapAuthenticatorPolicyManifest
{
    public required bool Password { get; init; }
    public required bool Google { get; init; }
    public required bool Apple { get; init; }
}

/// <summary>Manifest limits for proof codes, retries, cooldown, and phone conflicts.</summary>
internal sealed class BootstrapEnvironmentVerificationPolicyManifest
{
    public required int CodeLifetimeMinutes { get; init; }
    public required int MaxAttempts { get; init; }
    public required int MaxRequestsPerHourPerIdentity { get; init; }
    public required int ResendCooldownSeconds { get; init; }
    public required int PhoneConflictLifetimeMinutes { get; init; }
    public required int PhoneConflictEmailMaxAttempts { get; init; }
}

/// <summary>Manifest limits and callback URL for e-mail and phone password recovery.</summary>
internal sealed class BootstrapRecoveryPolicyManifest
{
    public string? PasswordRecoveryUrl { get; init; }
    public required int TokenLifetimeMinutes { get; init; }
    public required int MaxRequestsPerHourPerIdentity { get; init; }
    public required int PhoneCodeLifetimeMinutes { get; init; }
    public required int PhoneCodeMaxAttempts { get; init; }
    public required int PhoneMaxRequestsPerHourPerIdentity { get; init; }
    public required int PhoneResendCooldownSeconds { get; init; }
}

/// <summary>Optional environment-owned external provider configurations.</summary>
internal sealed class BootstrapProvidersManifest
{
    public BootstrapSmtpProviderManifest? Smtp { get; init; }
    public BootstrapTwilioVerifyProviderManifest? TwilioVerify { get; init; }
    public BootstrapGoogleProviderManifest? Google { get; init; }
    public BootstrapAppleProviderManifest? Apple { get; init; }
}

/// <summary>Manifest SMTP connection, authentication, and sender configuration.</summary>
internal sealed class BootstrapSmtpProviderManifest
{
    public required string Host { get; init; }
    public required int Port { get; init; }
    public string? User { get; init; }
    public string? Password { get; init; }
    public required string FromAddress { get; init; }
    public required string FromName { get; init; }
    public required bool UseStartTls { get; init; }
    public required bool UseSsl { get; init; }
}

/// <summary>Manifest Twilio Verify credentials, service, channel, and locale.</summary>
internal sealed class BootstrapTwilioVerifyProviderManifest
{
    public required string KeySid { get; init; }
    public required string KeySecret { get; init; }
    public required string ServiceSid { get; init; }
    public required string Channel { get; init; }
    public required string Locale { get; init; }
    public string? PasswordResetTemplateSid { get; init; }
}

/// <summary>Manifest Google OAuth client id for server-side token validation.</summary>
internal sealed class BootstrapGoogleProviderManifest
{
    public required string ClientId { get; init; }
}

/// <summary>Manifest Apple service or application client id used as token audience.</summary>
internal sealed class BootstrapAppleProviderManifest
{
    public required string ClientId { get; init; }
}

/// <summary>Explicit development-only phone and code bypass configuration.</summary>
internal sealed class BootstrapDevelopmentBypassManifest
{
    public required bool Enabled { get; init; }
    public string? Phone { get; init; }
    public string? Code { get; init; }
}

/// <summary>Manifest trusted backend client and its closed permission set.</summary>
internal sealed class BootstrapIntegrationClientManifest
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public required IReadOnlyList<string> Permissions { get; init; }
}

/// <summary>Manifest public build identity and platform-specific metadata.</summary>
internal sealed class BootstrapApplicationClientManifest
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public required string Platform { get; init; }
    public string? ApplicationId { get; init; }
    public string? SigningIdentity { get; init; }
    public string? SmsRetrieverAppHash { get; init; }
    public required JsonElement PublicConfiguration { get; init; }
}
