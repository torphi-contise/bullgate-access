using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Domain.Topology;
using Microsoft.Extensions.Logging;

namespace Bullgate.Access.Infrastructure.Verification;

/// <summary>Sensitive provider input required to create a Twilio Verify delivery.</summary>
/// <remarks>
/// This record contains provider credentials, a destination phone, and a clear OTP.
/// It must never be emitted as structured log state or retained after the request.
/// </remarks>
/// <param name="ServiceSid">Environment-owned Twilio Verify service id.</param>
/// <param name="KeySid">Environment-owned API-key username.</param>
/// <param name="KeySecret">Environment-owned clear API-key secret.</param>
/// <param name="Phone">Canonical private delivery destination.</param>
/// <param name="Code">Clear Access-generated OTP.</param>
/// <param name="Channel">Configured Twilio delivery channel.</param>
/// <param name="Locale">Configured provider message locale.</param>
/// <param name="TemplateSid">Optional journey-specific provider template.</param>
/// <param name="AppHash">Optional Android SMS Retriever suffix.</param>
internal sealed record TwilioVerifySendRequest(
    string ServiceSid,
    string KeySid,
    string KeySecret,
    string Phone,
    string Code,
    string Channel,
    string Locale,
    string? TemplateSid,
    string? AppHash);

/// <summary>Sensitive provider input required to finalize a Twilio verification.</summary>
/// <remarks>Provider credentials remain confined to the transport call.</remarks>
/// <param name="ServiceSid">Environment-owned Twilio Verify service id.</param>
/// <param name="KeySid">Environment-owned API-key username.</param>
/// <param name="KeySecret">Environment-owned clear API-key secret.</param>
/// <param name="VerificationSid">Opaque provider resource selected for update.</param>
/// <param name="Status">Expected terminal provider lifecycle status.</param>
internal sealed record TwilioVerifyStatusRequest(
    string ServiceSid,
    string KeySid,
    string KeySecret,
    string VerificationSid,
    string Status);

/// <summary>Isolates Twilio Verify HTTP operations from phone-proof orchestration.</summary>
internal interface ITwilioVerifyTransport
{
    /// <summary>Creates one provider verification and returns its validated opaque SID.</summary>
    /// <remarks>
    /// Successful return means Twilio accepted creation and returned a syntactically
    /// usable resource reference. It does not prove handset receipt or possession.
    /// </remarks>
    /// <param name="request">Sensitive provider credentials and delivery data.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    Task<string> SendAsync(
        TwilioVerifySendRequest request,
        CancellationToken cancellationToken);

    /// <summary>Applies one terminal lifecycle status to an existing provider SID.</summary>
    /// <remarks>
    /// This synchronizes provider lifecycle after Access has made its local decision;
    /// it never decides whether a submitted OTP matched.
    /// </remarks>
    /// <param name="request">Sensitive provider credentials and resource update.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    Task UpdateStatusAsync(
        TwilioVerifyStatusRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Implements the narrow Twilio Verify HTTP contract used by Access without exposing
/// raw provider responses to application services.
/// </summary>
internal sealed class TwilioVerifyTransport(IHttpClientFactory httpClientFactory)
    : ITwilioVerifyTransport
{
    private const string ApiBase = "https://verify.twilio.com/v2";

    /// <inheritdoc />
    public async Task<string> SendAsync(
        TwilioVerifySendRequest request,
        CancellationToken cancellationToken)
    {
        using var message = CreateMessage(
            $"{ApiBase}/Services/{request.ServiceSid}/Verifications",
            request.KeySid,
            request.KeySecret);
        var form = new Dictionary<string, string>
        {
            ["To"] = request.Phone,
            ["Channel"] = request.Channel,
            ["CustomCode"] = request.Code,
            ["Locale"] = request.Locale,
        };
        if (string.Equals(request.Channel, "sms", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(request.AppHash))
        {
            // Twilio's AppHash option is meaningful only for SMS Retriever messages.
            // Sending it on another channel would create provider-specific ambiguity.
            form["AppHash"] = request.AppHash;
        }
        if (!string.IsNullOrWhiteSpace(request.TemplateSid))
        {
            form["TemplateSid"] = request.TemplateSid;
        }
        message.Content = new FormUrlEncodedContent(form);

        using var client = httpClientFactory.CreateClient();
        using var response = await client.SendAsync(message, cancellationToken);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);
        EnsureSuccess(response, payload);
        using var document = JsonDocument.Parse(payload);
        var sid = document.RootElement.TryGetProperty("sid", out var value)
            ? value.GetString()
            : null;
        if (sid is null || !sid.StartsWith("VE", StringComparison.Ordinal))
        {
            // A successful HTTP status without a usable provider reference cannot be
            // finalized durably, so treat it as delivery failure.
            throw new InvalidOperationException(
                "Twilio Verify returned an invalid verification reference.");
        }
        return sid;
    }

    /// <inheritdoc />
    public async Task UpdateStatusAsync(
        TwilioVerifyStatusRequest request,
        CancellationToken cancellationToken)
    {
        using var message = CreateMessage(
            $"{ApiBase}/Services/{request.ServiceSid}/Verifications/"
            + request.VerificationSid,
            request.KeySid,
            request.KeySecret);
        message.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Status"] = request.Status,
        });

        using var client = httpClientFactory.CreateClient();
        using var response = await client.SendAsync(message, cancellationToken);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);
        EnsureSuccess(response, payload);
        using var document = JsonDocument.Parse(payload);
        var status = document.RootElement.TryGetProperty("status", out var value)
            ? value.GetString()
            : null;
        if (!string.Equals(status, request.Status, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Twilio Verify did not update the verification to '{request.Status}'.");
        }
    }

    /// <summary>Creates one form request with short-lived provider authentication state.</summary>
    private static HttpRequestMessage CreateMessage(
        string url,
        string keySid,
        string keySecret)
    {
        var message = new HttpRequestMessage(HttpMethod.Post, url);
        // Provider credentials exist only long enough to build the Authorization header.
        // Callers dispose the message and never expose this value as diagnostic state.
        var credential = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{keySid}:{keySecret}"));
        message.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            credential);
        return message;
    }

    /// <summary>
    /// Accepts a successful HTTP result or throws a bounded provider exception without
    /// copying the arbitrary response body.
    /// </summary>
    /// <remarks>
    /// A structured Twilio error code is diagnostic metadata, not a public application
    /// error contract and not evidence about message delivery.
    /// </remarks>
    private static void EnsureSuccess(HttpResponseMessage response, string payload)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        // Retain only Twilio's structured error code. The raw body is untrusted and may
        // contain destination or provider details that do not belong in exceptions.
        var detail = "unknown-error";
        try
        {
            using var document = JsonDocument.Parse(payload);
            if (document.RootElement.TryGetProperty("code", out var code))
            {
                detail = code.ToString();
            }
        }
        catch (JsonException)
        {
            // Provider error bodies are untrusted and may contain contact details. Do
            // not copy an unparsable payload into the exception or application logs.
        }
        throw new HttpRequestException(
            $"Twilio Verify rejected the request ({detail}).",
            inner: null,
            response.StatusCode);
    }
}

/// <summary>
/// Resolves environment-scoped Twilio configuration and translates phone-proof
/// delivery, approval, and cancellation into the narrow provider transport contract.
/// </summary>
/// <remarks>
/// <see cref="IsAvailableAsync"/> checks configuration presence only. Delivery uses
/// Access-generated <c>CustomCode</c>; later approval is provider lifecycle
/// synchronization after Access has validated the local hash, never a second proof
/// decision. Clear credentials, destination, and code remain inside the transport call.
/// </remarks>
internal sealed class TwilioPhoneVerificationSender(
    IAppEnvironmentConfigurationReader configurations,
    ITwilioVerifyTransport transport,
    ILogger<TwilioPhoneVerificationSender> logger)
    : IPhoneVerificationSender
{
    /// <inheritdoc />
    public async Task<bool> IsAvailableAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        await FindOptionsAsync(appEnvironmentId, cancellationToken) is not null;

    /// <inheritdoc />
    public async Task<string?> SendAsync(
        Guid appEnvironmentId,
        PhoneVerificationDelivery delivery,
        CancellationToken cancellationToken)
    {
        var options = await RequireOptionsAsync(
            appEnvironmentId,
            cancellationToken);
        var sid = await transport.SendAsync(
            new TwilioVerifySendRequest(
                options.ServiceSid,
                options.KeySid,
                options.KeySecret,
                delivery.Phone,
                delivery.Code,
                options.Channel,
                options.Locale,
                ResolveTemplateSid(options, delivery.Purpose),
                delivery.SmsRetrieverAppHash),
            cancellationToken);
        // A provider SID is useful correlation metadata; the destination and clear code
        // deliberately remain absent from the log event.
        logger.LogInformation(
            "Phone verification {VerificationReference} was created.",
            sid);
        return sid;
    }

    /// <summary>Selects a validated recovery-only template without changing other journeys.</summary>
    /// <returns>
    /// A Twilio content-template SID for password recovery, or <see langword="null"/>
    /// for every other purpose and for invalid optional configuration.
    /// </returns>
    private string? ResolveTemplateSid(
        TwilioVerifyProviderConfiguration options,
        PhoneVerificationPurpose purpose)
    {
        if (purpose != PhoneVerificationPurpose.PasswordReset
            || options.PasswordResetTemplateSid is null)
        {
            // A password-reset template must not change the message contract of
            // registration or phone-management proofs.
            return null;
        }

        var sid = options.PasswordResetTemplateSid;
        if (sid.Length == 34
            && sid.StartsWith("HJ", StringComparison.Ordinal)
            && !sid.Any(char.IsWhiteSpace))
        {
            return sid;
        }

        logger.LogWarning(
            "Password reset Verify template was ignored because its SID is invalid.");
        return null;
    }

    /// <inheritdoc />
    public async Task ApproveAsync(
        Guid appEnvironmentId,
        string? providerReference,
        CancellationToken cancellationToken) =>
        await UpdateStatusAsync(
            appEnvironmentId,
            providerReference,
            "approved",
            cancellationToken);

    /// <inheritdoc />
    public async Task CancelAsync(
        Guid appEnvironmentId,
        string? providerReference,
        CancellationToken cancellationToken) =>
        await UpdateStatusAsync(
            appEnvironmentId,
            providerReference,
            "canceled",
            cancellationToken);

    /// <summary>Validates resource type and updates one exact provider resource.</summary>
    /// <remarks>
    /// The <c>VE</c> prefix check prevents constructing a verification URL from an
    /// absent or different Twilio resource type. It does not authenticate the reference;
    /// the environment-owned service and provider credentials still scope the request.
    /// </remarks>
    private async Task UpdateStatusAsync(
        Guid appEnvironmentId,
        string? providerReference,
        string status,
        CancellationToken cancellationToken)
    {
        var options = await RequireOptionsAsync(
            appEnvironmentId,
            cancellationToken);
        if (string.IsNullOrWhiteSpace(providerReference)
            || !providerReference.StartsWith("VE", StringComparison.Ordinal))
        {
            // Never construct a provider URL from an absent or wrong resource type.
            // The reference must have come from a successfully created verification.
            throw new InvalidOperationException(
                "Twilio verification reference is missing.");
        }
        await transport.UpdateStatusAsync(
            new TwilioVerifyStatusRequest(
                options.ServiceSid,
                options.KeySid,
                options.KeySecret,
                providerReference,
                status),
            cancellationToken);
        logger.LogInformation(
            "Phone verification {VerificationReference} was updated to {Status}.",
            providerReference,
            status);
    }

    /// <summary>Loads only the Twilio settings protected by the selected environment.</summary>
    /// <returns>
    /// Configuration when present; otherwise <see langword="null"/>. No provider health
    /// check is performed.
    /// </returns>
    private async Task<TwilioVerifyProviderConfiguration?> FindOptionsAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken)
    {
        if (appEnvironmentId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(appEnvironmentId));
        }
        return (await configurations.FindAsync(appEnvironmentId, cancellationToken))?
            .Providers.TwilioVerify;
    }

    /// <summary>Requires environment-owned Twilio settings before an external effect.</summary>
    private async Task<TwilioVerifyProviderConfiguration> RequireOptionsAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        await FindOptionsAsync(appEnvironmentId, cancellationToken)
        ?? throw new InvalidOperationException(
            "Twilio Verify is not configured for the app environment.");
}

/// <summary>
/// Explicitly rejects e-mail verification delivery in the baseline, whose bootstrap
/// validation does not permit enabling that unsupported journey.
/// </summary>
internal sealed class UnavailableEmailVerificationSender
    : IEmailVerificationSender
{
    /// <inheritdoc />
    public Task SendAsync(
        EmailVerificationDelivery delivery,
        CancellationToken cancellationToken) =>
        Task.FromException(
            new InvalidOperationException(
                "Email verification delivery is not configured."));
}
