using System.Text.Json;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Social;
using Google.Apis.Auth;
using Microsoft.Extensions.Logging;

namespace Bullgate.Access.Infrastructure.Social;

/// <summary>
/// Validates Google ID or access tokens against the client id protected in the target
/// app environment and emits only verified email/subject assertions.
/// </summary>
/// <remarks>
/// ID tokens use Google's signed-token validator. Access tokens use tokeninfo for
/// audience and identity claims; UserInfo is optional display-name enrichment and is
/// never identity authority. Rejected or malformed provider assertions return
/// <see langword="null"/> through the validator contract; raw token values and provider
/// response bodies are not returned to application services.
/// </remarks>
public sealed class GoogleIdentityValidator : IGoogleIdentityValidator
{
    private const string TokenInfoUrl =
        "https://www.googleapis.com/oauth2/v3/tokeninfo";
    private const string UserInfoUrl =
        "https://www.googleapis.com/oauth2/v3/userinfo";

    private readonly IAppEnvironmentConfigurationReader configurations;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly ILogger<GoogleIdentityValidator> logger;
    private readonly Func<
        string,
        GoogleJsonWebSignature.ValidationSettings,
        Task<GoogleJsonWebSignature.Payload>> validateIdToken;

    /// <summary>Creates the production validator backed by Google's signed-token API.</summary>
    /// <param name="configurations">Reader for protected environment-owned client ids.</param>
    /// <param name="httpClientFactory">Factory used for tokeninfo and optional UserInfo calls.</param>
    /// <param name="logger">Server diagnostic sink that must never receive raw tokens.</param>
    public GoogleIdentityValidator(
        IAppEnvironmentConfigurationReader configurations,
        IHttpClientFactory httpClientFactory,
        ILogger<GoogleIdentityValidator> logger)
        : this(
            configurations,
            httpClientFactory,
            logger,
            GoogleJsonWebSignature.ValidateAsync)
    {
    }

    /// <summary>Creates a validator with an injectable signed-token verifier for tests.</summary>
    internal GoogleIdentityValidator(
        IAppEnvironmentConfigurationReader configurations,
        IHttpClientFactory httpClientFactory,
        ILogger<GoogleIdentityValidator> logger,
        Func<
            string,
            GoogleJsonWebSignature.ValidationSettings,
            Task<GoogleJsonWebSignature.Payload>> validateIdToken)
    {
        this.configurations = configurations;
        this.httpClientFactory = httpClientFactory;
        this.logger = logger;
        this.validateIdToken = validateIdToken;
    }

    /// <inheritdoc />
    public async Task<SocialIdentityAssertion?> ValidateIdTokenAsync(
        Guid appEnvironmentId,
        string idToken,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var clientId = await RequireClientIdAsync(
                appEnvironmentId,
                cancellationToken);
            var payload = await validateIdToken(
                idToken,
                new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = [clientId],
                });
            // A provider subject is the stable credential key. Verified email is still
            // required because Access also creates verified contact metadata from it.
            if (string.IsNullOrWhiteSpace(payload.Email)
                || string.IsNullOrWhiteSpace(payload.Subject)
                || !payload.EmailVerified)
            {
                return null;
            }

            return new SocialIdentityAssertion(
                payload.Email,
                payload.Subject,
                payload.Name);
        }
        catch (InvalidJwtException)
        {
            // Signature, issuer, lifetime, audience, and token-shape rejection all map
            // to the same null assertion. Provider validation detail is not a public
            // authentication oracle.
            return null;
        }
    }

    /// <inheritdoc />
    public async Task<SocialIdentityAssertion?> ValidateAccessTokenAsync(
        Guid appEnvironmentId,
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var clientId = await RequireClientIdAsync(
            appEnvironmentId,
            cancellationToken);
        // Token validation is always bound to the provider client id protected in this
        // environment; a client id supplied alongside the request is never accepted.
        try
        {
            var http = httpClientFactory.CreateClient();
            // Google's tokeninfo contract receives the bearer in the query string.
            // URI/request telemetry must therefore apply secret redaction just as it
            // would for an Authorization header.
            var url = TokenInfoUrl + "?access_token=" + Uri.EscapeDataString(accessToken);
            using var response = await http.GetAsync(url, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                // Do not reflect provider status or body to the caller. Social service
                // exposes one stable invalid-token outcome for a rejected assertion.
                return null;
            }

            using var document = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync(cancellationToken));
            var root = document.RootElement;
            var aud = root.TryGetProperty("aud", out var audElement)
                ? audElement.GetString()
                : null;
            var azp = root.TryGetProperty("azp", out var azpElement)
                ? azpElement.GetString()
                : null;
            // Token validity alone is insufficient: audience/authorized-party binding
            // prevents a token minted for another app from authenticating here.
            if (!string.Equals(aud, clientId, StringComparison.Ordinal)
                && !string.Equals(azp, clientId, StringComparison.Ordinal))
            {
                logger.LogWarning(
                    "Google access token rejected because audience did not match.");
                return null;
            }

            var email = root.TryGetProperty("email", out var emailElement)
                ? emailElement.GetString()
                : null;
            var subject = root.TryGetProperty("sub", out var subjectElement)
                ? subjectElement.GetString()
                : null;
            var emailVerified = root.TryGetProperty("email_verified", out var verified)
                && (verified.ValueKind == JsonValueKind.True
                    || (verified.ValueKind == JsonValueKind.String
                        && string.Equals(
                            verified.GetString(),
                            "true",
                            StringComparison.OrdinalIgnoreCase)));
            if (string.IsNullOrWhiteSpace(email)
                || string.IsNullOrWhiteSpace(subject)
                || !emailVerified)
            {
                return null;
            }

            // UserInfo enriches display name only. Failure there must not invalidate an
            // access token whose identity and email claims already passed validation.
            return new SocialIdentityAssertion(
                email,
                subject,
                await TryFetchNameAsync(http, accessToken, cancellationToken));
        }
        catch (HttpRequestException exception)
        {
            // Network/provider failure is collapsed to no assertion at this adapter
            // boundary. Callers must not interpret null as proof that a person or
            // provider account does not exist.
            logger.LogWarning(exception, "Failed to validate Google access token.");
            return null;
        }
        catch (JsonException exception)
        {
            logger.LogWarning(exception, "Unexpected Google tokeninfo response.");
            return null;
        }
        catch (InvalidOperationException exception)
        {
            logger.LogWarning(exception, "Unexpected Google tokeninfo response.");
            return null;
        }
    }

    /// <summary>Attempts non-authoritative display-name enrichment through UserInfo.</summary>
    /// <remarks>
    /// Once tokeninfo has established audience, subject, and verified e-mail, absence
    /// or failure of this optional request changes only <c>DisplayName</c>. Caller
    /// cancellation is not caught and therefore still propagates.
    /// </remarks>
    private static async Task<string?> TryFetchNameAsync(
        HttpClient http,
        string accessToken,
        CancellationToken cancellationToken)
    {
        try
        {
            // The access token is used only for this provider call and is never written
            // to logs or included in the normalized assertion.
            using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoUrl);
            request.Headers.Add("Authorization", "Bearer " + accessToken);
            using var response = await http.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var document = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync(cancellationToken));
            return document.RootElement.TryGetProperty("name", out var name)
                ? name.GetString()
                : null;
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Loads the trusted client id from the selected protected environment.</summary>
    /// <remarks>
    /// A request-supplied audience is never accepted. Missing configuration is an
    /// operational configuration failure rather than a rejected Google identity claim.
    /// </remarks>
    private async Task<string> RequireClientIdAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken)
    {
        if (appEnvironmentId == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", nameof(appEnvironmentId));
        }
        var clientId = (await configurations.FindAsync(
            appEnvironmentId,
            cancellationToken))?.Providers.Google?.ClientId;
        return string.IsNullOrWhiteSpace(clientId)
            ? throw new InvalidOperationException(
                "Google client id is not configured for the app environment.")
            : clientId.Trim();
    }
}
