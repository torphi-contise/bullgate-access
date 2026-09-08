using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Configuration;

/// <summary>Shared complete-document validation for bootstrap and administrative replacement.</summary>
/// <remarks>Validates shape and domain relationships only; it never contacts a provider.</remarks>
public static class AppEnvironmentConfigurationValidator
{
    public static void Validate(AppEnvironmentConfiguration environment, string environmentPath = "configuration")
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(environment.IntegrationClients);
        ArgumentNullException.ThrowIfNull(environment.ApplicationClients);
        if (environment.IntegrationClients.Any(client => client is null)
            || environment.ApplicationClients.Any(client => client is null))
            throw new BootstrapTopologyException("Configuration contains a null client.");
        ValidateImplementedPolicy(environment.AccessPolicy, environmentPath);
        ValidateEnvironmentConfiguration(environment, environmentPath);
        ArgumentNullException.ThrowIfNull(environment.IntegrationClients);
        ArgumentNullException.ThrowIfNull(environment.ApplicationClients);
        EnsureDistinct(
            environment.IntegrationClients.Select(client => client.Key),
            $"{environmentPath}.integrationClients");
        EnsureDistinct(
            environment.ApplicationClients.Select(client => client.Key),
            $"{environmentPath}.applicationClients");

        foreach (var client in environment.IntegrationClients)
        {
            TopologyValue.Key(client.Key, $"{environmentPath}.integrationClients.key");
            TopologyValue.Name(client.Name, $"{environmentPath}.integrationClients.name");
            ArgumentNullException.ThrowIfNull(client.Permissions);
            EnsureDistinct(client.Permissions, $"{environmentPath}.permissions");

            foreach (var permission in client.Permissions)
            {
                TopologyValue.Permission(permission, $"{environmentPath}.permissions");

                if (!AccessPermission.IsDefined(permission))
                {
                    throw new BootstrapTopologyException(
                        $"Permission '{permission}' is not defined by Bullgate Access.");
                }
            }
        }

        foreach (var client in environment.ApplicationClients)
        {
            TopologyValue.Key(client.Key, $"{environmentPath}.applicationClients.key");
            TopologyValue.Name(client.Name, $"{environmentPath}.applicationClients.name");
            TopologyValue.OptionalApplicationId(
                client.ApplicationId,
                $"{environmentPath}.applicationClients.applicationId");
            TopologyValue.OptionalSigningIdentity(
                client.SigningIdentity,
                $"{environmentPath}.applicationClients.signingIdentity");
            TopologyValue.SmsRetrieverAppHash(
                client.SmsRetrieverAppHash,
                $"{environmentPath}.applicationClients.smsRetrieverAppHash");

            if (!Enum.IsDefined(client.Platform))
            {
                throw new BootstrapTopologyException(
                    $"Application client '{client.Key}' has an unsupported platform.");
            }

            if (client.Platform is ApplicationClientPlatform.Android
                    or ApplicationClientPlatform.Ios
                && client.ApplicationId is null)
            {
                throw new BootstrapTopologyException(
                    $"Application client '{client.Key}' requires an application id.");
            }

            if (client.SmsRetrieverAppHash is not null
                && client.Platform != ApplicationClientPlatform.Android)
            {
                throw new BootstrapTopologyException(
                    $"Application client '{client.Key}' cannot define an SMS Retriever app hash "
                    + "for a non-Android platform.");
            }
        }
    }

    private static void ValidateEnvironmentConfiguration(
        AppEnvironmentConfiguration environment,
        string environmentPath)
    {
        if (environment.VerificationPolicy is null)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.verificationPolicy' cannot be null.");
        }
        if (environment.RecoveryPolicy is null)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.recoveryPolicy' cannot be null.");
        }
        if (environment.Providers is null)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.providers' cannot be null.");
        }
        if (environment.DevelopmentBypass is null)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.developmentBypass' cannot be null.");
        }
        if (environment.PublicConfiguration is null
            || environment.PublicConfiguration.Version <= 0
            || environment.PublicConfiguration.Values.ValueKind != JsonValueKind.Object)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.publicConfiguration' must have a positive version "
                + "and JSON object values.");
        }
        if (environment.ApplicationClients.Any(client =>
                client.PublicConfiguration.ValueKind != JsonValueKind.Object))
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.applicationClients.publicConfiguration' must be "
                + "a JSON object.");
        }

        var verification = environment.VerificationPolicy;
        if (verification.CodeLifetimeMinutes <= 0
            || verification.MaxAttempts <= 0
            || verification.MaxRequestsPerHourPerIdentity <= 0
            || verification.ResendCooldownSeconds < 0
            || verification.PhoneConflictLifetimeMinutes <= 0
            || verification.PhoneConflictEmailMaxAttempts <= 0)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.verificationPolicy' contains an invalid limit.");
        }

        var recovery = environment.RecoveryPolicy;
        if (recovery.TokenLifetimeMinutes <= 0
            || recovery.MaxRequestsPerHourPerIdentity <= 0
            || recovery.PhoneCodeLifetimeMinutes <= 0
            || recovery.PhoneCodeMaxAttempts <= 0
            || recovery.PhoneMaxRequestsPerHourPerIdentity <= 0
            || recovery.PhoneResendCooldownSeconds < 0)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.recoveryPolicy' contains an invalid limit.");
        }

        try
        {
            TopologyValue.PasswordRecoveryUrl(
                recovery.PasswordRecoveryUrl,
                $"{environmentPath}.recoveryPolicy.passwordRecoveryUrl");
        }
        catch (ArgumentException exception)
        {
            throw new BootstrapTopologyException(exception.Message);
        }

        ValidateProviders(environment, environmentPath);
        ValidateDevelopmentBypass(environment, environmentPath);
    }

    /// <summary>
    /// Rejects provider and feature combinations that would create an impossible or
    /// misleading runtime journey.
    /// </summary>
    /// <remarks>
    /// This validation establishes configuration consistency only. It performs no
    /// provider health, credential, destination, or network check.
    /// </remarks>
    private static void ValidateProviders(
        AppEnvironmentConfiguration environment,
        string environmentPath)
    {
        var providers = environment.Providers;
        var policy = environment.AccessPolicy;

        // Phone verification has no provider-free production adapter. Allowing the
        // policy without Twilio would advertise a journey that cannot deliver its code.
        if (policy.Phone.Verification.Enabled && providers.TwilioVerify is null)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.providers.twilioVerify' is required when phone "
                + "verification is enabled.");
        }
        // Social feature flags and trusted audiences are separate fields, so both must
        // be present before an environment can advertise that authenticator.
        if (policy.Authenticators.GoogleEnabled && providers.Google is null)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.providers.google' is required when Google "
                + "authentication is enabled.");
        }
        if (policy.Authenticators.AppleEnabled && providers.Apple is null)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.providers.apple' is required when Apple "
                + "authentication is enabled.");
        }

        // A recovery URL without SMTP creates undeliverable bearer authority; SMTP
        // without a recovery URL can send no usable link. Require the pair atomically.
        var hasRecoveryUrl = environment.RecoveryPolicy.PasswordRecoveryUrl is not null;
        if (hasRecoveryUrl != (providers.Smtp is not null))
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.recoveryPolicy.passwordRecoveryUrl' and "
                + $"'{environmentPath}.providers.smtp' must be configured together.");
        }

        if (providers.Smtp is { } smtp)
        {
            // Validate the transport and sender shape before encrypting configuration.
            // This is deliberately not a network or credential-authentication probe.
            if (string.IsNullOrWhiteSpace(smtp.Host)
                || smtp.Port is < 1 or > 65535
                || string.IsNullOrWhiteSpace(smtp.FromAddress)
                || string.IsNullOrWhiteSpace(smtp.FromName))
            {
                throw new BootstrapTopologyException(
                    $"'{environmentPath}.providers.smtp' is incomplete or invalid.");
            }
            // STARTTLS upgrades an established connection; implicit SSL begins inside
            // TLS. Selecting both would give the transport contradictory instructions.
            if (smtp.UseStartTls && smtp.UseSsl)
            {
                throw new BootstrapTopologyException(
                    $"'{environmentPath}.providers.smtp' cannot enable STARTTLS and "
                    + "implicit SSL together.");
            }
            // Anonymous SMTP omits both values. Authenticated SMTP requires both so a
            // missing secret is rejected here rather than converted into a provider
            // authentication failure at runtime.
            if ((smtp.User is null) != (smtp.Password is null))
            {
                throw new BootstrapTopologyException(
                    $"'{environmentPath}.providers.smtp.user' and password must be "
                    + "configured together.");
            }
            // Require the parser's canonical address to equal the supplied value so a
            // display-name form cannot be smuggled into a field documented as address-only.
            if (!System.Net.Mail.MailAddress.TryCreate(smtp.FromAddress, out var address)
                || !string.Equals(
                    address.Address,
                    smtp.FromAddress,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new BootstrapTopologyException(
                    $"'{environmentPath}.providers.smtp.fromAddress' is invalid.");
            }
            // Password recovery resolves an identity through its e-mail identifier.
            // SMTP configuration without that identifier feature has no valid owner path.
            if (!policy.Email.Enabled)
            {
                throw new BootstrapTopologyException(
                    $"'{environmentPath}.providers.smtp' requires the email identifier.");
            }
        }

        // Non-empty fields are structural validation only. Twilio remains the authority
        // for whether these credentials, service, channel, and locale are operational.
        if (providers.TwilioVerify is { } twilio
            && (string.IsNullOrWhiteSpace(twilio.KeySid)
                || string.IsNullOrWhiteSpace(twilio.KeySecret)
                || string.IsNullOrWhiteSpace(twilio.ServiceSid)
                || string.IsNullOrWhiteSpace(twilio.Channel)
                || string.IsNullOrWhiteSpace(twilio.Locale)))
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.providers.twilioVerify' is incomplete.");
        }
        // A delivery provider must not be retained where no phone identifier journey
        // may consume it; doing so stores unused secrets and implies unsupported behavior.
        if (providers.TwilioVerify is not null && !policy.Phone.Enabled)
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.providers.twilioVerify' requires the phone identifier.");
        }
        // Client ids are trusted audiences used by server-side validators. Empty values
        // cannot safely fall back to request input or global configuration.
        if (providers.Google is { } google && string.IsNullOrWhiteSpace(google.ClientId))
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.providers.google.clientId' cannot be empty.");
        }
        if (providers.Apple is { } apple && string.IsNullOrWhiteSpace(apple.ClientId))
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.providers.apple.clientId' cannot be empty.");
        }
    }

    private static void ValidateDevelopmentBypass(
        AppEnvironmentConfiguration environment,
        string environmentPath)
    {
        var bypass = environment.DevelopmentBypass;
        if (!bypass.Enabled)
        {
            if (bypass.Phone is not null || bypass.Code is not null)
            {
                throw new BootstrapTopologyException(
                    $"'{environmentPath}.developmentBypass' cannot define phone or code "
                    + "when disabled.");
            }
            return;
        }

        if (!environment.AccessPolicy.Phone.Enabled
            || !IsE164Phone(bypass.Phone)
            || bypass.Code is null
            || bypass.Code.Length != 6
            || !bypass.Code.All(char.IsAsciiDigit))
        {
            throw new BootstrapTopologyException(
                $"'{environmentPath}.developmentBypass' is invalid.");
        }
    }

    private static bool IsE164Phone(string? value)
    {
        if (value is null
            || value.Length is < 9 or > 16
            || value[0] != '+'
            || value[1] is < '1' or > '9')
        {
            return false;
        }

        return value.AsSpan(2).IndexOfAnyExceptInRange('0', '9') < 0;
    }

    private static void ValidateImplementedPolicy(
        AppAccessPolicy policy,
        string environmentPath)
    {
        ArgumentNullException.ThrowIfNull(policy);

        if (policy.Email.Verification.Enabled)
        {
            throw new BootstrapTopologyException(
                $"Environment '{environmentPath}' enables email verification, "
                + "which is not supported.");
        }

        if (policy.Phone.Verification.Enabled
            && !string.Equals(
                policy.Phone.Verification.Provider,
                VerificationProviderKey.TwilioVerify,
                StringComparison.Ordinal))
        {
            throw new BootstrapTopologyException(
                $"Environment '{environmentPath}' selects unsupported phone verification "
                + $"provider '{policy.Phone.Verification.Provider}'.");
        }

    }

    private static void EnsureDistinct(IEnumerable<string> values, string path)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (!seen.Add(value))
            {
                throw new BootstrapTopologyException(
                    $"'{path}' contains duplicate value '{value}'.");
            }
        }
    }

}
