using System.Net;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Topology;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace Bullgate.Access.Infrastructure.Recovery;

/// <summary>
/// Isolates SMTP I/O from recovery orchestration so delivery can be tested and treated
/// as an external effect.
/// </summary>
internal interface ISmtpTransport
{
    /// <summary>Connects, optionally authenticates, submits one message, and disconnects.</summary>
    /// <param name="message">
    /// MIME message containing a private destination and clear recovery URL.
    /// </param>
    /// <param name="host">Configured SMTP host.</param>
    /// <param name="port">Configured SMTP port.</param>
    /// <param name="secure">Selected MailKit transport-security mode.</param>
    /// <param name="user">Optional configured authentication identity.</param>
    /// <param name="password">Optional clear provider password paired with the user.</param>
    /// <param name="cancellationToken">Cancels connection, authentication, send, or disconnect.</param>
    Task SendAsync(
        MimeMessage message,
        string host,
        int port,
        SecureSocketOptions secure,
        string? user,
        string? password,
        CancellationToken cancellationToken);
}

/// <summary>Performs one authenticated or anonymous MailKit SMTP delivery.</summary>
internal sealed class MailKitSmtpTransport : ISmtpTransport
{
    /// <inheritdoc />
    public async Task SendAsync(
        MimeMessage message,
        string host,
        int port,
        SecureSocketOptions secure,
        string? user,
        string? password,
        CancellationToken cancellationToken)
    {
        using var client = new SmtpClient();
        await client.ConnectAsync(host, port, secure, cancellationToken);
        if (!string.IsNullOrWhiteSpace(user))
        {
            // Bootstrap requires the password to be configured with the user. The empty
            // fallback protects this low-level boundary from a null library argument;
            // it does not turn incomplete configuration into valid authentication.
            await client.AuthenticateAsync(user, password ?? string.Empty, cancellationToken);
        }
        await client.SendAsync(message, cancellationToken);
        await client.DisconnectAsync(true, cancellationToken);
    }
}

/// <summary>
/// Builds and sends a password-recovery message using the provider configuration owned
/// by the target app environment.
/// </summary>
/// <remarks>
/// A false result means the provider was unavailable or rejected delivery. It does not
/// reveal whether the destination belongs to an identity. Caller cancellation is
/// propagated because it has different orchestration and retry meaning.
///
/// Provider exception detail is deliberately omitted from logging because external
/// diagnostics may contain destination, server, or credential-related information.
/// </remarks>
internal sealed class SmtpPasswordRecoveryEmailSender(
    IAppEnvironmentConfigurationReader configurations,
    ISmtpTransport transport,
    ILogger<SmtpPasswordRecoveryEmailSender> logger)
    : IPasswordRecoveryEmailSender
{
    /// <inheritdoc />
    public async Task<bool> IsAvailableAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        await FindOptionsAsync(appEnvironmentId, cancellationToken) is not null;

    /// <inheritdoc />
    public async Task<bool> TrySendAsync(
        Guid appEnvironmentId,
        PasswordRecoveryEmailDelivery delivery,
        CancellationToken cancellationToken)
    {
        var options = await FindOptionsAsync(
            appEnvironmentId,
            cancellationToken);
        if (options is null)
        {
            // Configuration absence is an unavailable delivery channel, not evidence
            // about whether the requested e-mail belongs to an identity.
            return false;
        }

        try
        {
            var appName = SanitizeHeader(delivery.AppName);
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(
                SanitizeHeader(options.FromName),
                options.FromAddress));
            message.To.Add(MailboxAddress.Parse(delivery.Email));
            message.Subject = $"Redefinição de senha — {appName}";
            message.Body = new BodyBuilder
            {
                HtmlBody = RenderHtml(delivery, appName),
                TextBody = RenderText(delivery, appName),
            }.ToMessageBody();

            await transport.SendAsync(
                message,
                options.Host,
                options.Port,
                SelectSecureMode(options),
                options.User,
                options.Password,
                cancellationToken);
            logger.LogInformation(
                "Password recovery email was delivered for app {AppName}.",
                appName);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Caller cancellation has different retry meaning from provider failure;
            // preserve it so orchestration can inspect durable reservation state.
            throw;
        }
        catch (Exception)
        {
            // The application contract collapses SMTP setup, connection,
            // authentication, submission, and disconnect failures to false. Keep the
            // failure category in server diagnostics, but omit the exception,
            // destination, and clear reset URL because provider detail may be sensitive.
            logger.LogError(
                "Password recovery email delivery failed for app {AppName}.",
                delivery.AppName);
            return false;
        }
    }

    /// <summary>Maps mutually exclusive manifest flags to MailKit connection policy.</summary>
    /// <remarks>
    /// Implicit SSL takes precedence, then required STARTTLS. When neither flag is set,
    /// <see cref="SecureSocketOptions.Auto"/> delegates protocol selection to MailKit;
    /// availability and bootstrap validity do not prove a live secure connection.
    /// </remarks>
    private static SecureSocketOptions SelectSecureMode(
        SmtpProviderConfiguration options) =>
        options.UseSsl
            ? SecureSocketOptions.SslOnConnect
            : options.UseStartTls
                ? SecureSocketOptions.StartTls
                : SecureSocketOptions.Auto;

    /// <summary>Builds the HTML alternative while encoding every dynamic HTML value.</summary>
    /// <remarks>
    /// The reset URL contains clear bearer authority. Encoding preserves its value for
    /// HTML rendering; it does not make the URL safe to log or expose elsewhere.
    /// </remarks>
    private static string RenderHtml(
        PasswordRecoveryEmailDelivery delivery,
        string appName)
    {
        var encodedAppName = WebUtility.HtmlEncode(appName);
        var encodedResetUrl = WebUtility.HtmlEncode(delivery.ResetUrl);
        return """
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head><title>Redefinição de senha</title></head>
            <body style="font-family:Arial,sans-serif;background:#121620;color:#e5e7eb;padding:24px">
              <h2 style="color:#fff">Redefinição de senha</h2>
              <p>Recebemos um pedido para redefinir sua senha no {{APP_NAME}}.</p>
              <p>O link abaixo expira em {{LIFETIME}} minutos.</p>
              <p><a href="{{RESET_URL}}" style="display:inline-block;background:#2563eb;color:#fff;padding:12px 20px;border-radius:6px;text-decoration:none">Redefinir senha</a></p>
              <p style="font-size:12px;color:#9ca3af">Se você não pediu, ignore este e-mail.</p>
              <p style="font-size:12px;color:#9ca3af">Link direto: {{RESET_URL}}</p>
            </body>
            </html>
            """
            .Replace("{{APP_NAME}}", encodedAppName, StringComparison.Ordinal)
            .Replace(
                "{{LIFETIME}}",
                delivery.TokenLifetimeMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture),
                StringComparison.Ordinal)
            .Replace("{{RESET_URL}}", encodedResetUrl, StringComparison.Ordinal);
    }

    /// <summary>Builds the plain-text alternative containing the clear reset URL.</summary>
    private static string RenderText(
        PasswordRecoveryEmailDelivery delivery,
        string appName) =>
        $"Redefinição de senha — {appName}{Environment.NewLine}{Environment.NewLine}"
        + $"Recebemos um pedido para redefinir sua senha. O link expira em "
        + $"{delivery.TokenLifetimeMinutes} minutos.{Environment.NewLine}{Environment.NewLine}"
        + delivery.ResetUrl;

    /// <summary>Removes CR and LF so configured display text cannot inject MIME headers.</summary>
    private static string SanitizeHeader(string value) =>
        // Display names originate in environment configuration. Removing CR/LF keeps
        // them from creating additional MIME headers.
        value.Replace('\r', ' ').Replace('\n', ' ');

    /// <summary>Loads only the SMTP settings protected by the selected environment.</summary>
    /// <returns>
    /// Configuration when present; otherwise <see langword="null"/>. No provider
    /// connection is attempted by this lookup.
    /// </returns>
    private async Task<SmtpProviderConfiguration?> FindOptionsAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken)
    {
        if (appEnvironmentId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(appEnvironmentId));
        }
        return (await configurations.FindAsync(appEnvironmentId, cancellationToken))?
            .Providers.Smtp;
    }
}
