using System.Net;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Verification;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bullgate.Access.UnitTests;

public sealed class TwilioPhoneVerificationSenderTests
{
    private static readonly Guid AppEnvironmentId = Guid.NewGuid();
    private const string VerificationSid =
        "VE11111111111111111111111111111111";
    private const string PasswordResetTemplateSid =
        "HJ11111111111111111111111111111111";

    [Fact]
    public async Task SendAsync_UsesEnvironmentPasswordResetTemplateOnlyForPasswordReset()
    {
        var transport = new RecordingTwilioVerifyTransport();
        var reader = new ConfigurationReader(
            AppEnvironmentId,
            CreateConfiguration(CreateTwilio()));
        var sender = CreateSender(reader, transport);

        await sender.SendAsync(
            AppEnvironmentId,
            new PhoneVerificationDelivery(
                "+5511999999999",
                "123456",
                "app-hash",
                PhoneVerificationPurpose.PasswordReset),
            CancellationToken.None);
        var passwordResetRequest = Assert.IsType<TwilioVerifySendRequest>(
            transport.SendRequest);

        await sender.SendAsync(
            AppEnvironmentId,
            new PhoneVerificationDelivery(
                "+5511999999999",
                "654321",
                "app-hash"),
            CancellationToken.None);
        var phoneVerificationRequest = Assert.IsType<TwilioVerifySendRequest>(
            transport.SendRequest);

        Assert.Equal(AppEnvironmentId, reader.LastAppEnvironmentId);
        Assert.True(await sender.IsAvailableAsync(
            AppEnvironmentId,
            CancellationToken.None));
        Assert.Equal(PasswordResetTemplateSid, passwordResetRequest.TemplateSid);
        Assert.Null(phoneVerificationRequest.TemplateSid);
    }

    [Fact]
    public async Task SendAsync_UsesCredentialsFromTheRequestedEnvironment()
    {
        var otherEnvironmentId = Guid.NewGuid();
        var otherTwilio = CreateTwilio() with
        {
            KeySid = "SK22222222222222222222222222222222",
            KeySecret = "other-secret",
            ServiceSid = "VA22222222222222222222222222222222",
        };
        var reader = new MultipleConfigurationReader(new Dictionary<
            Guid,
            AppEnvironmentConfiguration>
        {
            [AppEnvironmentId] = CreateConfiguration(CreateTwilio()),
            [otherEnvironmentId] = CreateConfiguration(otherTwilio),
        });
        var transport = new RecordingTwilioVerifyTransport();
        var sender = CreateSender(reader, transport);

        await sender.SendAsync(
            otherEnvironmentId,
            new PhoneVerificationDelivery(
                "+5511999999999",
                "123456",
                null),
            CancellationToken.None);

        var request = Assert.IsType<TwilioVerifySendRequest>(transport.SendRequest);
        Assert.Equal(otherTwilio.KeySid, request.KeySid);
        Assert.Equal(otherTwilio.KeySecret, request.KeySecret);
        Assert.Equal(otherTwilio.ServiceSid, request.ServiceSid);
    }

    [Fact]
    public async Task SendAsync_IgnoresInvalidPasswordResetTemplate()
    {
        var options = CreateTwilio() with
        {
            PasswordResetTemplateSid = "invalid-template",
        };
        var transport = new RecordingTwilioVerifyTransport();
        var sender = CreateSender(
            new ConfigurationReader(
                AppEnvironmentId,
                CreateConfiguration(options)),
            transport);

        await sender.SendAsync(
            AppEnvironmentId,
            new PhoneVerificationDelivery(
                "+5511999999999",
                "123456",
                null,
                PhoneVerificationPurpose.PasswordReset),
            CancellationToken.None);

        Assert.Null(Assert.IsType<TwilioVerifySendRequest>(
            transport.SendRequest).TemplateSid);
    }

    [Fact]
    public async Task ApproveAndCancelAsync_UpdateTheExactVerificationStatus()
    {
        var transport = new RecordingTwilioVerifyTransport();
        var sender = CreateSender(
            new ConfigurationReader(
                AppEnvironmentId,
                CreateConfiguration(CreateTwilio())),
            transport);

        await sender.ApproveAsync(
            AppEnvironmentId,
            VerificationSid,
            CancellationToken.None);
        await sender.CancelAsync(
            AppEnvironmentId,
            VerificationSid,
            CancellationToken.None);

        Assert.Collection(
            transport.StatusRequests,
            approved =>
            {
                Assert.Equal(VerificationSid, approved.VerificationSid);
                Assert.Equal("approved", approved.Status);
            },
            canceled =>
            {
                Assert.Equal(VerificationSid, canceled.VerificationSid);
                Assert.Equal("canceled", canceled.Status);
            });
    }

    [Fact]
    public async Task IsAvailableAsync_ReflectsEnvironmentProviderConfiguration()
    {
        var sender = CreateSender(
            new ConfigurationReader(
                AppEnvironmentId,
                CreateConfiguration(twilio: null)),
            new RecordingTwilioVerifyTransport());

        Assert.False(await sender.IsAvailableAsync(
            AppEnvironmentId,
            CancellationToken.None));
    }

    [Fact]
    public async Task Transport_UpdateStatusAsync_SendsCanceledAndRequiresCanceledResponse()
    {
        var handler = new RecordingHttpMessageHandler(
            HttpStatusCode.OK,
            "{\"status\":\"canceled\"}");
        var transport = new TwilioVerifyTransport(
            new SingleClientFactory(handler));

        await transport.UpdateStatusAsync(
            new TwilioVerifyStatusRequest(
                "VA11111111111111111111111111111111",
                "SK11111111111111111111111111111111",
                "secret",
                VerificationSid,
                "canceled"),
            CancellationToken.None);

        Assert.Equal(HttpMethod.Post, handler.Method);
        Assert.EndsWith(
            $"/Verifications/{VerificationSid}",
            handler.RequestUri?.AbsoluteUri,
            StringComparison.Ordinal);
        Assert.Equal("Status=canceled", handler.Content);
    }

    private static TwilioPhoneVerificationSender CreateSender(
        IAppEnvironmentConfigurationReader configurations,
        ITwilioVerifyTransport transport) =>
        new(
            configurations,
            transport,
            NullLogger<TwilioPhoneVerificationSender>.Instance);

    private static TwilioVerifyProviderConfiguration CreateTwilio() =>
        new(
            "SK11111111111111111111111111111111",
            "secret",
            "VA11111111111111111111111111111111",
            "sms",
            "pt-BR",
            PasswordResetTemplateSid);

    private static AppEnvironmentConfiguration CreateConfiguration(
        TwilioVerifyProviderConfiguration? twilio) =>
        new(
            DisabledAccessPolicy(),
            new AppVerificationPolicy(10, 5, 5, 120, 15, 5),
            new AppRecoveryPolicy(null, 60, 5, 10, 5, 5, 120),
            new AppEnvironmentProviders(null, twilio, null, null),
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

    private sealed class MultipleConfigurationReader(
        IReadOnlyDictionary<Guid, AppEnvironmentConfiguration> configurations)
        : IAppEnvironmentConfigurationReader
    {
        public Task<AppEnvironmentConfiguration?> FindAsync(
            Guid appEnvironmentId,
            CancellationToken cancellationToken) =>
            Task.FromResult(configurations.GetValueOrDefault(appEnvironmentId));
    }

    private sealed class RecordingTwilioVerifyTransport : ITwilioVerifyTransport
    {
        public TwilioVerifySendRequest? SendRequest { get; private set; }

        public List<TwilioVerifyStatusRequest> StatusRequests { get; } = [];

        public Task<string> SendAsync(
            TwilioVerifySendRequest request,
            CancellationToken cancellationToken)
        {
            SendRequest = request;
            return Task.FromResult(VerificationSid);
        }

        public Task UpdateStatusAsync(
            TwilioVerifyStatusRequest request,
            CancellationToken cancellationToken)
        {
            StatusRequests.Add(request);
            return Task.CompletedTask;
        }
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler)
        : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class RecordingHttpMessageHandler(
        HttpStatusCode responseStatus,
        string responseContent)
        : HttpMessageHandler
    {
        public HttpMethod? Method { get; private set; }
        public Uri? RequestUri { get; private set; }
        public string? Content { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Method = request.Method;
            RequestUri = request.RequestUri;
            Content = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(responseStatus)
            {
                Content = new StringContent(responseContent),
            };
        }
    }
}
