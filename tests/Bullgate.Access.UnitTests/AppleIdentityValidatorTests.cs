using System.Security.Cryptography;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Social;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Bullgate.Access.UnitTests;

public sealed class AppleIdentityValidatorTests
{
    private static readonly Guid AppEnvironmentId = Guid.NewGuid();
    private const string ClientId = "app.bullgate.test";
    private const string AppleIssuer = "https://appleid.apple.com";
    private const string KeyId = "apple-test-key";

    [Fact]
    public async Task ValidateAsync_AcceptsIdentitySignedByAppleForConfiguredApplication()
    {
        using var appleKey = RSA.Create(2048);
        var validator = CreateValidator(appleKey);
        var token = CreateToken(appleKey);

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            token,
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("person@example.test", assertion.Email);
        Assert.Equal("apple-subject", assertion.Subject);
        Assert.Null(assertion.DisplayName);
    }

    [Fact]
    public async Task ValidateAsync_UsesProviderConfigurationFromRequestedEnvironment()
    {
        using var appleKey = RSA.Create(2048);
        var otherEnvironmentId = Guid.NewGuid();
        const string otherClientId = "app.other.test";
        var configurations = new MultipleConfigurationReader(new Dictionary<
            Guid,
            AppEnvironmentConfiguration>
        {
            [AppEnvironmentId] = CreateConfiguration(ClientId),
            [otherEnvironmentId] = CreateConfiguration(otherClientId),
        });
        var validator = CreateValidator(appleKey, configurations);
        var token = CreateToken(appleKey, audience: otherClientId);

        var assertion = await validator.ValidateAsync(
            otherEnvironmentId,
            token,
            CancellationToken.None);

        Assert.NotNull(assertion);
        Assert.Equal("apple-subject", assertion.Subject);
    }

    [Fact]
    public async Task ValidateAsync_RejectsTokenIssuedForAnotherApplication()
    {
        using var appleKey = RSA.Create(2048);
        var validator = CreateValidator(appleKey);
        var token = CreateToken(appleKey, audience: "another.application");

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            token,
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateAsync_RejectsTokenIssuedByAnotherAuthority()
    {
        using var appleKey = RSA.Create(2048);
        var validator = CreateValidator(appleKey);
        var token = CreateToken(appleKey, issuer: "https://attacker.example");

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            token,
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateAsync_RejectsExpiredToken()
    {
        using var appleKey = RSA.Create(2048);
        var validator = CreateValidator(appleKey);
        var token = CreateToken(
            appleKey,
            issuedAt: DateTime.UtcNow.AddHours(-2),
            expires: DateTime.UtcNow.AddHours(-1));

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            token,
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateAsync_RejectsTokenThatIsNotValidYet()
    {
        using var appleKey = RSA.Create(2048);
        var validator = CreateValidator(appleKey);
        var token = CreateToken(
            appleKey,
            notBefore: DateTime.UtcNow.AddHours(1));

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            token,
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateAsync_RejectsTokenSignedByUntrustedKey()
    {
        using var appleKey = RSA.Create(2048);
        using var attackerKey = RSA.Create(2048);
        var validator = CreateValidator(appleKey);
        var token = CreateToken(attackerKey);

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            token,
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Theory]
    [InlineData("email")]
    [InlineData("sub")]
    public async Task ValidateAsync_RejectsIdentityWithoutRequiredClaim(
        string omittedClaim)
    {
        using var appleKey = RSA.Create(2048);
        var validator = CreateValidator(appleKey);
        var claims = ValidClaims();
        claims.Remove(omittedClaim);
        var token = CreateToken(appleKey, claims: claims);

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            token,
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateAsync_RejectsWhenAppleSigningConfigurationIsUnavailable()
    {
        using var appleKey = RSA.Create(2048);
        var validator = new AppleIdentityValidator(
            new ConfigurationReader(CreateConfiguration(ClientId)),
            NullLogger<AppleIdentityValidator>.Instance,
            _ => Task.FromException<OpenIdConnectConfiguration>(
                new HttpRequestException("Apple unavailable")));
        var token = CreateToken(appleKey);

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            token,
            CancellationToken.None);

        Assert.Null(assertion);
    }

    [Fact]
    public async Task ValidateAsync_PropagatesCallerCancellation()
    {
        using var appleKey = RSA.Create(2048);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var validator = new AppleIdentityValidator(
            new ConfigurationReader(CreateConfiguration(ClientId)),
            NullLogger<AppleIdentityValidator>.Instance,
            token => Task.FromCanceled<OpenIdConnectConfiguration>(token));
        var identityToken = CreateToken(appleKey);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            validator.ValidateAsync(
                AppEnvironmentId,
                identityToken,
                cancellation.Token));
    }

    [Fact]
    public async Task ValidateAsync_RejectsMalformedToken()
    {
        using var appleKey = RSA.Create(2048);
        var validator = CreateValidator(appleKey);

        var assertion = await validator.ValidateAsync(
            AppEnvironmentId,
            "not-a-jwt",
            CancellationToken.None);

        Assert.Null(assertion);
    }

    private static AppleIdentityValidator CreateValidator(RSA appleKey) =>
        CreateValidator(
            appleKey,
            new ConfigurationReader(CreateConfiguration(ClientId)));

    private static AppleIdentityValidator CreateValidator(
        RSA appleKey,
        IAppEnvironmentConfigurationReader configurations)
    {
        var publicKey = new RsaSecurityKey(appleKey.ExportParameters(false))
        {
            KeyId = KeyId,
        };
        var oidc = new OpenIdConnectConfiguration();
        oidc.SigningKeys.Add(publicKey);
        return new AppleIdentityValidator(
            configurations,
            NullLogger<AppleIdentityValidator>.Instance,
            _ => Task.FromResult(oidc));
    }

    private static string CreateToken(
        RSA signingKey,
        string audience = ClientId,
        string issuer = AppleIssuer,
        DateTime? issuedAt = null,
        DateTime? notBefore = null,
        DateTime? expires = null,
        IDictionary<string, object>? claims = null)
    {
        var key = new RsaSecurityKey(signingKey)
        {
            KeyId = KeyId,
        };
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(
            new SecurityTokenDescriptor
            {
                Audience = audience,
                Issuer = issuer,
                IssuedAt = issuedAt ?? now,
                NotBefore = notBefore ?? issuedAt ?? now.AddMinutes(-1),
                Expires = expires ?? now.AddMinutes(10),
                Claims = claims ?? ValidClaims(),
                SigningCredentials = new SigningCredentials(
                    key,
                    SecurityAlgorithms.RsaSha256),
            });
    }

    private static Dictionary<string, object> ValidClaims() =>
        new(StringComparer.Ordinal)
        {
            ["email"] = "person@example.test",
            ["sub"] = "apple-subject",
        };

    private static AppEnvironmentConfiguration CreateConfiguration(
        string appleClientId) =>
        new(
            new AppAccessPolicy(
                new IdentifierAccessPolicy(false, false, IdentifierVerificationPolicy.Disabled),
                new IdentifierAccessPolicy(false, false, IdentifierVerificationPolicy.Disabled),
                new AuthenticatorAccessPolicy(false, false, true)),
            new AppVerificationPolicy(10, 5, 5, 120, 15, 5),
            new AppRecoveryPolicy(null, 60, 5, 10, 5, 5, 120),
            new AppEnvironmentProviders(
                null,
                null,
                null,
                new AppleProviderConfiguration(appleClientId)),
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
}
