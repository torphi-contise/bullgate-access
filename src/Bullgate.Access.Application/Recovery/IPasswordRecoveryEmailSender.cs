namespace Bullgate.Access.Application.Recovery;

/// <summary>Sensitive message inputs required by a recovery e-mail adapter.</summary>
/// <remarks>
/// <see cref="ResetUrl"/> contains clear bearer authority. The delivery object and its
/// formatted message must not be logged, retained as ordinary diagnostics, or exposed
/// outside the intended recovery channel.
/// </remarks>
/// <param name="Email">Private destination selected from current Access state.</param>
/// <param name="AppName">Environment-owned display name used in message content.</param>
/// <param name="ResetUrl">Clear reset bearer embedded in the intended delivery channel.</param>
/// <param name="TokenLifetimeMinutes">Displayed lifetime of the persisted token.</param>
public sealed record PasswordRecoveryEmailDelivery(
    string Email,
    string AppName,
    string ResetUrl,
    int TokenLifetimeMinutes);

/// <summary>
/// Sends a password-recovery link through the SMTP provider owned by an environment.
/// </summary>
/// <remarks>
/// Availability is configuration presence rather than an SMTP health probe. Provider
/// acceptance means the send operation completed at the transport boundary; it does
/// not prove inbox placement, message reading, or reset-token consumption.
/// </remarks>
public interface IPasswordRecoveryEmailSender
{
    /// <summary>
    /// Reports whether the target environment currently has usable SMTP configuration.
    /// </summary>
    /// <remarks>This method performs no network request to the configured SMTP host.</remarks>
    /// <param name="appEnvironmentId">Environment that owns provider configuration.</param>
    /// <param name="cancellationToken">Cancels configuration lookup.</param>
    Task<bool> IsAvailableAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken);

    /// <summary>Sends one recovery message using only the target environment's provider.</summary>
    /// <param name="appEnvironmentId">Environment that owns provider configuration.</param>
    /// <param name="delivery">Sensitive destination and clear recovery authority.</param>
    /// <param name="cancellationToken">Cancels the provider operation.</param>
    /// <returns>
    /// <see langword="true"/> when the provider accepted the send operation; otherwise
    /// <see langword="false"/> for unavailable configuration or provider failure.
    /// </returns>
    /// <remarks>Caller cancellation is propagated rather than converted to a false result.</remarks>
    Task<bool> TrySendAsync(
        Guid appEnvironmentId,
        PasswordRecoveryEmailDelivery delivery,
        CancellationToken cancellationToken);
}
