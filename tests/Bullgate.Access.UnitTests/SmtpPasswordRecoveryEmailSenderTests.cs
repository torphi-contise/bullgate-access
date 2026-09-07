using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Recovery;
using MailKit.Security;
using Microsoft.Extensions.Logging.Abstractions;
using MimeKit;

namespace Bullgate.Access.UnitTests;

public sealed class SmtpPasswordRecoveryEmailSenderTests
{
    private static readonly Guid AppEnvironmentId = Guid.NewGuid();

    [Fact]
    public async Task TrySendAsync_ResolvesEnvironmentAndBuildsEncodedMessage()
    {
        var token = new string('A', 43);
        var resetUrl = $"https://baybo.app/reset-password?token={token}&next=<unsafe>";
        var reader = new ConfigurationReader(
            AppEnvironmentId,
            CreateConfiguration(CreateSmtp()));
        var transport = new RecordingSmtpTransport();
        var sender = new SmtpPasswordRecoveryEmailSender(
            reader,
            transport,
            NullLogger<SmtpPasswordRecoveryEmailSender>.Instance);

        var sent = await sender.TrySendAsync(
            AppEnvironmentId,
            new PasswordRecoveryEmailDelivery(
                "person@example.test",
                "BAYBO <Produto>",
                resetUrl,
                60),
            CancellationToken.None);

        Assert.True(sent);
        Assert.Equal(AppEnvironmentId, reader.LastAppEnvironmentId);
        Assert.Equal("smtp.example.test", transport.Host);
        Assert.Equal(2525, transport.Port);
        Assert.Equal(SecureSocketOptions.StartTls, transport.Secure);
        var message = Assert.IsType<MimeMessage>(transport.Message);
        Assert.Equal("noreply@example.test", message.From.Mailboxes.Single().Address);
        Assert.Equal("person@example.test", message.To.Mailboxes.Single().Address);
        Assert.Equal("Redefinição de senha — BAYBO <Produto>", message.Subject);
        Assert.Contains("BAYBO &lt;Produto&gt;", message.HtmlBody, StringComparison.Ordinal);
        Assert.Contains($"?token={token}", message.HtmlBody, StringComparison.Ordinal);
        Assert.Contains("&amp;next=&lt;unsafe&gt;", message.HtmlBody, StringComparison.Ordinal);
        Assert.Contains(resetUrl, message.TextBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TrySendAsync_ReturnsFalseWhenEnvironmentHasNoSmtpProvider()
    {
        var reader = new ConfigurationReader(
            AppEnvironmentId,
            CreateConfiguration(smtp: null));
        var sender = new SmtpPasswordRecoveryEmailSender(
            reader,
            new RecordingSmtpTransport(),
            NullLogger<SmtpPasswordRecoveryEmailSender>.Instance);

        Assert.False(await sender.IsAvailableAsync(
            AppEnvironmentId,
            CancellationToken.None));
        Assert.False(await sender.TrySendAsync(
            AppEnvironmentId,
            CreateDelivery(),
            CancellationToken.None));
    }

    [Fact]
    public async Task TrySendAsync_ReturnsFalseWhenTransportFails()
    {
        var transport = new RecordingSmtpTransport
        {
            Exception = new InvalidOperationException("SMTP unavailable"),
        };
        var sender = CreateSender(transport);

        var sent = await sender.TrySendAsync(
            AppEnvironmentId,
            CreateDelivery(),
            CancellationToken.None);

        Assert.False(sent);
    }

    [Fact]
    public async Task TrySendAsync_PropagatesCallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var sender = CreateSender(new RecordingSmtpTransport());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            sender.TrySendAsync(
                AppEnvironmentId,
                CreateDelivery(),
                cancellation.Token));
    }

    private static SmtpPasswordRecoveryEmailSender CreateSender(
        ISmtpTransport transport) =>
        new(
            new ConfigurationReader(
                AppEnvironmentId,
                CreateConfiguration(CreateSmtp())),
            transport,
            NullLogger<SmtpPasswordRecoveryEmailSender>.Instance);

    private static SmtpProviderConfiguration CreateSmtp() =>
        new(
            "smtp.example.test",
            2525,
            "smtp-user",
            "smtp-password",
            "noreply@example.test",
            "Bullgate",
            UseStartTls: true,
            UseSsl: false);

    private static AppEnvironmentConfiguration CreateConfiguration(
        SmtpProviderConfiguration? smtp) =>
        new(
            DisabledAccessPolicy(),
            new AppVerificationPolicy(10, 5, 5, 120, 15, 5),
            new AppRecoveryPolicy(null, 60, 5, 10, 5, 5, 120),
            new AppEnvironmentProviders(smtp, null, null, null),
            new DevelopmentBypassConfiguration(false, null, null),
            [],
            []);

    private static AppAccessPolicy DisabledAccessPolicy() =>
        new(
            new IdentifierAccessPolicy(
                false,
                false,
                IdentifierVerificationPolicy.Disabled),
            new IdentifierAccessPolicy(
                false,
                false,
                IdentifierVerificationPolicy.Disabled),
            new AuthenticatorAccessPolicy(false, false, false));

    private static PasswordRecoveryEmailDelivery CreateDelivery() =>
        new(
            "person@example.test",
            "BAYBO",
            $"https://baybo.app/reset-password?token={new string('A', 43)}",
            60);

    private sealed class ConfigurationReader(
        Guid expectedAppEnvironmentId,
        AppEnvironmentConfiguration configuration)
        : IAppEnvironmentConfigurationReader
    {
        public Guid? LastAppEnvironmentId { get; private set; }

        public Task<AppEnvironmentConfiguration?> FindAsync(
            Guid appEnvironmentId,
            CancellationToken cancellationToken)
        {
            LastAppEnvironmentId = appEnvironmentId;
            return Task.FromResult<AppEnvironmentConfiguration?>(
                appEnvironmentId == expectedAppEnvironmentId
                    ? configuration
                    : null);
        }
    }

    private sealed class RecordingSmtpTransport : ISmtpTransport
    {
        public Exception? Exception { get; init; }
        public MimeMessage? Message { get; private set; }
        public string? Host { get; private set; }
        public int Port { get; private set; }
        public SecureSocketOptions Secure { get; private set; }

        public Task SendAsync(
            MimeMessage message,
            string host,
            int port,
            SecureSocketOptions secure,
            string? user,
            string? password,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Exception is not null)
            {
                return Task.FromException(Exception);
            }

            Message = message;
            Host = host;
            Port = port;
            Secure = secure;
            return Task.CompletedTask;
        }
    }
}
