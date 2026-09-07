using System.Net;
using System.Text;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Social;
using Google.Apis.Auth;
using Microsoft.Extensions.Logging.Abstractions;

namespace Bullgate.Access.UnitTests;

public sealed class GoogleIdentityValidatorTests
{
    private static readonly Guid AppEnvironmentId = Guid.NewGuid();
    private const string ClientId = "google-client-id";

    [Fact]
    public async Task ValidateIdTokenAsync_AcceptsVerifiedIdentityForConfiguredAudience()
    {
        string? receivedToken = null;
        GoogleJsonWebSignature.ValidationSettings? receivedSettings = null;
        var validator = CreateValidator((token, settings) =>
        {
            receivedToken = token;
            receivedSettings = settings;
            return Task.FromResult(new GoogleJsonWebSignature.Payload
            {
                Email = "person@example.test",
                Subject = "google-subject",
                EmailVerified = true,
                Name = "Person Name",
            });
        });

        var assertion = await validator.ValidateIdTokenAsync(
            AppEnvironmentId,
            "google-id-token",
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("person@example.test", assertion.Email);
        Assert.Equal("google-subject", assertion.Subject);
        Assert.Equal("Person Name", assertion.DisplayName);
        Assert.Equal("google-id-token", receivedToken);
        Assert.Equal([ClientId], receivedSettings?.Audience);
    }

    [Fact]
    public async Task ValidateIdTokenAsync_RejectsUnverifiedEmail()
    {
        var validator = CreateValidator((_, _) =>
            Task.FromResult(new GoogleJsonWebSignature.Payload
            {
                Email = "person@example.test",
                Subject = "google-subject",
                EmailVerified = false,
            }));

        var assertion = await validator.ValidateIdTokenAsync(
            AppEnvironmentId,
            "google-id-token",
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Theory]
    [InlineData("email")]
    [InlineData("sub")]
    public async Task ValidateIdTokenAsync_RejectsIdentityWithoutRequiredClaim(
        string omittedClaim)
    {
        var validator = CreateValidator((_, _) =>
            Task.FromResult(new GoogleJsonWebSignature.Payload
            {
                Email = omittedClaim == "email" ? null : "person@example.test",
                Subject = omittedClaim == "sub" ? null : "google-subject",
                EmailVerified = true,
            }));

        var assertion = await validator.ValidateIdTokenAsync(
            AppEnvironmentId,
            "google-id-token",
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_AcceptsVerifiedIdentityForConfiguredAudience()
    {
        var handler = new ScriptedHttpMessageHandler(request =>
            request.RequestUri?.AbsolutePath.EndsWith("/tokeninfo", StringComparison.Ordinal) == true
                ? Json(HttpStatusCode.OK, """
                    {
                      "aud": "google-client-id",
                      "email": "person@example.test",
                      "sub": "google-subject",
                      "email_verified": true
                    }
                    """)
                : Json(HttpStatusCode.OK, """{"name":"Person Name"}"""));
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("person@example.test", assertion.Email);
        Assert.Equal("google-subject", assertion.Subject);
        Assert.Equal("Person Name", assertion.DisplayName);
        Assert.Collection(
            handler.Requests,
            tokenInfo => Assert.Contains(
                "access_token=access-token",
                tokenInfo.RequestUri?.Query,
                StringComparison.Ordinal),
            userInfo => Assert.Equal(
                "Bearer access-token",
                userInfo.Headers.Authorization?.ToString()));
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_AcceptsAuthorizedPartyWhenAudienceDiffers()
    {
        var handler = TokenInfoHandler("""
            {
              "aud": "google-api",
              "azp": "google-client-id",
              "email": "person@example.test",
              "sub": "google-subject",
              "email_verified": "true"
            }
            """);
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("google-subject", assertion.Subject);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_UsesProviderConfigurationFromRequestedEnvironment()
    {
        var otherEnvironmentId = Guid.NewGuid();
        const string otherClientId = "other-google-client-id";
        var configurations = new MultipleConfigurationReader(new Dictionary<
            Guid,
            AppEnvironmentConfiguration>
        {
            [AppEnvironmentId] = CreateConfiguration(ClientId),
            [otherEnvironmentId] = CreateConfiguration(otherClientId),
        });
        var handler = TokenInfoHandler("""
            {
              "aud": "other-google-client-id",
              "email": "other@example.test",
              "sub": "other-google-subject",
              "email_verified": true
            }
            """);
        var validator = CreateValidator(configurations, handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            otherEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("other@example.test", assertion.Email);
        Assert.Equal("other-google-subject", assertion.Subject);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_RejectsTokenIssuedForAnotherApplication()
    {
        var handler = TokenInfoHandler("""
            {
              "aud": "another-client",
              "azp": "another-authorized-party",
              "email": "person@example.test",
              "sub": "google-subject",
              "email_verified": true
            }
            """);
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.Null(assertion);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_RejectsUnverifiedEmail()
    {
        var handler = TokenInfoHandler("""
            {
              "aud": "google-client-id",
              "email": "person@example.test",
              "sub": "google-subject",
              "email_verified": false
            }
            """);
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.Null(assertion);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData("email")]
    [InlineData("sub")]
    public async Task ValidateAccessTokenAsync_RejectsIdentityWithoutRequiredClaim(
        string omittedClaim)
    {
        var email = omittedClaim == "email"
            ? string.Empty
            : "\"email\":\"person@example.test\",";
        var subject = omittedClaim == "sub"
            ? string.Empty
            : "\"sub\":\"google-subject\",";
        var handler = TokenInfoHandler(
            $$"""
            {
              "aud": "google-client-id",
              {{email}}
              {{subject}}
              "email_verified": true
            }
            """);
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.Null(assertion);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_RejectsProviderErrorResponse()
    {
        var handler = new ScriptedHttpMessageHandler(_ =>
            Json(HttpStatusCode.Unauthorized, """{"error":"invalid_token"}"""));
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.Null(assertion);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_RejectsMalformedProviderResponse()
    {
        var handler = new ScriptedHttpMessageHandler(_ =>
            Json(HttpStatusCode.OK, "not-json"));
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_RejectsUnexpectedAudienceShape()
    {
        var handler = TokenInfoHandler("""
            {
              "aud": ["google-client-id"],
              "email": "person@example.test",
              "sub": "google-subject",
              "email_verified": true
            }
            """);
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.Null(assertion);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_PreservesOpaqueTokenAcrossGoogleRequests()
    {
        const string accessToken = "opaque+/token=&value";
        var handler = new ScriptedHttpMessageHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath.EndsWith(
                    "/tokeninfo",
                    StringComparison.Ordinal) == true)
            {
                Assert.Equal(
                    "?access_token=" + Uri.EscapeDataString(accessToken),
                    request.RequestUri.Query);
                return Json(HttpStatusCode.OK, """
                    {
                      "aud": "google-client-id",
                      "email": "person@example.test",
                      "sub": "google-subject",
                      "email_verified": true
                    }
                    """);
            }

            Assert.Equal(
                "Bearer " + accessToken,
                request.Headers.Authorization?.ToString());
            return Json(HttpStatusCode.OK, "{}");
        });
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            accessToken,
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("google-subject", assertion.Subject);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_KeepsValidatedIdentityWhenProfileIsUnavailable()
    {
        var handler = new ScriptedHttpMessageHandler(request =>
            request.RequestUri?.AbsolutePath.EndsWith("/tokeninfo", StringComparison.Ordinal) == true
                ? Json(HttpStatusCode.OK, """
                    {
                      "aud": "google-client-id",
                      "email": "person@example.test",
                      "sub": "google-subject",
                      "email_verified": true
                    }
                    """)
                : Json(HttpStatusCode.ServiceUnavailable, ""));
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("person@example.test", assertion.Email);
        Assert.Equal("google-subject", assertion.Subject);
        Assert.Null(assertion.DisplayName);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_KeepsValidatedIdentityWhenProfileIsMalformed()
    {
        var handler = new ScriptedHttpMessageHandler(request =>
            request.RequestUri?.AbsolutePath.EndsWith("/tokeninfo", StringComparison.Ordinal) == true
                ? Json(HttpStatusCode.OK, """
                    {
                      "aud": "google-client-id",
                      "email": "person@example.test",
                      "sub": "google-subject",
                      "email_verified": true
                    }
                    """)
                : Json(HttpStatusCode.OK, "not-json"));
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("person@example.test", assertion.Email);
        Assert.Equal("google-subject", assertion.Subject);
        Assert.Null(assertion.DisplayName);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_RejectsWhenGoogleCannotValidateToken()
    {
        var handler = new ScriptedHttpMessageHandler(_ =>
            throw new HttpRequestException("Google unavailable"));
        var validator = CreateValidator(handler);

        var assertion = await validator.ValidateAccessTokenAsync(
            AppEnvironmentId,
            "access-token",
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateIdTokenAsync_RejectsMalformedToken()
    {
        var validator = CreateValidator(new ScriptedHttpMessageHandler(_ =>
            throw new InvalidOperationException("No HTTP request was expected.")));

        var assertion = await validator.ValidateIdTokenAsync(
            AppEnvironmentId,
            "not-a-jwt",
            CancellationToken.None);

        Assert.Null(assertion);
    }

    private static GoogleIdentityValidator CreateValidator(
        HttpMessageHandler handler) =>
        CreateValidator(
            new ConfigurationReader(CreateConfiguration(ClientId)),
            handler);

    private static GoogleIdentityValidator CreateValidator(
        Func<
            string,
            GoogleJsonWebSignature.ValidationSettings,
            Task<GoogleJsonWebSignature.Payload>> validateIdToken) =>
        new(
            new ConfigurationReader(CreateConfiguration(ClientId)),
            new SingleClientFactory(new ScriptedHttpMessageHandler(_ =>
                throw new InvalidOperationException("No HTTP request was expected."))),
            NullLogger<GoogleIdentityValidator>.Instance,
            validateIdToken);

    private static GoogleIdentityValidator CreateValidator(
        IAppEnvironmentConfigurationReader configurations,
        HttpMessageHandler handler) =>
        new(
            configurations,
            new SingleClientFactory(handler),
            NullLogger<GoogleIdentityValidator>.Instance);

    private static ScriptedHttpMessageHandler TokenInfoHandler(string content) =>
        new(request =>
            request.RequestUri?.AbsolutePath.EndsWith("/tokeninfo", StringComparison.Ordinal) == true
                ? Json(HttpStatusCode.OK, content)
                : Json(HttpStatusCode.OK, "{}"));

    private static HttpResponseMessage Json(HttpStatusCode status, string content) =>
        new(status)
        {
            Content = new StringContent(content, Encoding.UTF8, "application/json"),
        };

    private static AppEnvironmentConfiguration CreateConfiguration(
        string googleClientId) =>
        new(
            new AppAccessPolicy(
                new IdentifierAccessPolicy(false, false, IdentifierVerificationPolicy.Disabled),
                new IdentifierAccessPolicy(false, false, IdentifierVerificationPolicy.Disabled),
                new AuthenticatorAccessPolicy(false, true, false)),
            new AppVerificationPolicy(10, 5, 5, 120, 15, 5),
            new AppRecoveryPolicy(null, 60, 5, 10, 5, 5, 120),
            new AppEnvironmentProviders(
                null,
                null,
                new GoogleProviderConfiguration(googleClientId),
                null),
            new DevelopmentBypassConfiguration(false, null, null),
            [],
            []);

    private sealed class ConfigurationReader(AppEnvironmentConfiguration configuration)
        : IAppEnvironmentConfigurationReader
    {
        public Task<AppEnvironmentConfiguration?> FindAsync(
            Guid appEnvironmentId,
            CancellationToken cancellationToken) =>
            Task.FromResult<AppEnvironmentConfiguration?>(
                appEnvironmentId == AppEnvironmentId ? configuration : null);
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

    private sealed class SingleClientFactory(HttpMessageHandler handler)
        : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false);
    }

    private sealed class ScriptedHttpMessageHandler(
        Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(respond(request));
        }
    }
}
