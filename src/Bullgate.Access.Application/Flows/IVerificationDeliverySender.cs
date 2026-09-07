namespace Bullgate.Access.Application.Flows;

/// <summary>Names the user journey so the delivery adapter can select correct messaging.</summary>
public enum PhoneVerificationPurpose
{
    /// <summary>Registration or authenticated phone-management possession proof.</summary>
    PhoneVerification,

    /// <summary>Password-recovery possession proof with recovery-specific messaging.</summary>
    PasswordReset,
}

/// <summary>Contains one Access-generated code and its provider delivery metadata.</summary>
/// <remarks>
/// The phone and clear code are sensitive proof-delivery material. Do not log,
/// persist, or serialize this object outside the provider call boundary.
/// </remarks>
/// <param name="Phone">Canonical destination selected by trusted orchestration.</param>
/// <param name="Code">Clear Access-generated OTP delivered only through the provider.</param>
/// <param name="SmsRetrieverAppHash">Optional Android app hash appended by compatible SMS templates.</param>
/// <param name="Purpose">Journey purpose used only to select the correct message contract.</param>
public sealed record PhoneVerificationDelivery(
    string Phone,
    string Code,
    string? SmsRetrieverAppHash,
    PhoneVerificationPurpose Purpose = PhoneVerificationPurpose.PhoneVerification);

/// <summary>
/// Delivers an Access-generated phone verification code through the environment's
/// configured provider.
/// </summary>
/// <remarks>
/// Delivery does not make the provider the proof authority for AccessFlow; the local
/// stored hash remains authoritative there. Availability reports configuration
/// presence, not provider reachability or service health.
/// </remarks>
public interface IPhoneVerificationSender
{
    /// <summary>
    /// Reports whether the target environment currently has a configured phone
    /// verification provider.
    /// </summary>
    /// <remarks>
    /// A successful result does not prove that a provider request would currently
    /// succeed or that a destination is reachable.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment that owns provider configuration.</param>
    /// <param name="cancellationToken">Cancels configuration lookup.</param>
    Task<bool> IsAvailableAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken);

    /// <summary>Starts delivery of an Access-generated code through the target provider.</summary>
    /// <returns>
    /// An opaque provider reference for later lifecycle updates, or
    /// <see langword="null"/> when an implementation has no external provider resource.
    /// Successful return means provider acceptance, not handset receipt or proof completion.
    /// </returns>
    /// <param name="appEnvironmentId">Environment that owns provider configuration.</param>
    /// <param name="delivery">Sensitive destination, clear code, and message metadata.</param>
    /// <param name="cancellationToken">Cancels provider submission.</param>
    Task<string?> SendAsync(
        Guid appEnvironmentId,
        PhoneVerificationDelivery delivery,
        CancellationToken cancellationToken);

    /// <summary>
    /// Marks the referenced provider verification approved after Access has accepted
    /// the local proof required by the journey.
    /// </summary>
    /// <remarks>This is provider lifecycle synchronization, not a second proof decision.</remarks>
    /// <param name="appEnvironmentId">Environment that owns the provider resource.</param>
    /// <param name="providerReference">Opaque id returned by successful provider submission.</param>
    /// <param name="cancellationToken">Cancels the provider update.</param>
    Task ApproveAsync(
        Guid appEnvironmentId,
        string? providerReference,
        CancellationToken cancellationToken);

    /// <summary>Cancels provider work that no longer backs a usable local challenge.</summary>
    /// <remarks>
    /// Callers use this as bounded compensation. Cancellation cannot prove that a message
    /// was not already delivered.
    /// </remarks>
    /// <param name="appEnvironmentId">Environment that owns the provider resource.</param>
    /// <param name="providerReference">Opaque id returned by successful provider submission.</param>
    /// <param name="cancellationToken">Cancels the compensation attempt.</param>
    Task CancelAsync(
        Guid appEnvironmentId,
        string? providerReference,
        CancellationToken cancellationToken);
}

/// <summary>Contains one Access-generated e-mail verification code.</summary>
/// <remarks>
/// Both fields are sensitive delivery material and must remain inside the configured
/// delivery boundary.
/// </remarks>
/// <param name="Email">Normalized destination selected by trusted orchestration.</param>
/// <param name="Code">Clear Access-generated OTP delivered only through e-mail.</param>
public sealed record EmailVerificationDelivery(
    string Email,
    string Code);

/// <summary>Delivers an email verification code when environment policy enables it.</summary>
/// <remarks>
/// The baseline implementation is deliberately unavailable because bootstrap does not
/// permit this journey. Password-recovery e-mail uses a separate adapter contract.
/// </remarks>
public interface IEmailVerificationSender
{
    /// <summary>Sends one Access-generated code to the intended e-mail destination.</summary>
    Task SendAsync(
        EmailVerificationDelivery delivery,
        CancellationToken cancellationToken);
}

internal static class PhoneValue
{
    // Accept an already canonical international shape: '+' plus 8-15 ASCII digits,
    // with a non-zero first digit. This deliberately does not infer a country, remove
    // punctuation, validate allocation, or claim that the destination is reachable.
    public static bool TryNormalize(string? value, out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length is < 9 or > 16
            || normalized[0] != '+'
            || normalized[1] is < '1' or > '9')
        {
            normalized = string.Empty;
            return false;
        }

        for (var index = 2; index < normalized.Length; index++)
        {
            // ASCII-only digits keep stored uniqueness canonical and reject Unicode
            // lookalikes that external SMS providers may interpret inconsistently.
            if (!char.IsAsciiDigit(normalized[index]))
            {
                normalized = string.Empty;
                return false;
            }
        }

        return true;
    }
}
