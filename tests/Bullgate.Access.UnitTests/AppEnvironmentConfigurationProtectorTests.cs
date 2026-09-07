using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bullgate.Access.Application.Cryptography;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Configuration;
using Bullgate.Access.Infrastructure.Cryptography;
using Microsoft.Extensions.Configuration;

namespace Bullgate.Access.UnitTests;

public sealed class AppEnvironmentConfigurationProtectorTests
{
    [Fact]
    public void Protect_RoundTripsCompleteConfigurationWithoutPlaintextSecrets()
    {
        using var keyDeriver = CreateKeyDeriver();
        var protector = new AppEnvironmentConfigurationProtector(keyDeriver);
        var environmentId = Guid.Parse("019b8d00-84fb-71eb-a169-6cbfa9327321");
        var configuration = CreateConfiguration();

        var protectedConfiguration = protector.Protect(environmentId, configuration);
        var restored = protector.Unprotect(environmentId, protectedConfiguration);

        Assert.Equivalent(configuration, restored, strict: true);
        Assert.Equal(2, protectedConfiguration.FormatVersion);
        Assert.Equal(12, protectedConfiguration.Nonce.Length);
        Assert.Equal(16, protectedConfiguration.Tag.Length);
        Assert.DoesNotContain(
            "smtp-demo-password",
            Encoding.UTF8.GetString(protectedConfiguration.Ciphertext),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "twilio-demo-secret",
            Encoding.UTF8.GetString(protectedConfiguration.Ciphertext),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Protect_UsesFreshNonceForEveryWrite()
    {
        using var keyDeriver = CreateKeyDeriver();
        var protector = new AppEnvironmentConfigurationProtector(keyDeriver);
        var environmentId = Guid.Parse("019b8d00-84fb-71eb-a169-6cbfa9327321");

        var first = protector.Protect(environmentId, CreateConfiguration());
        var second = protector.Protect(environmentId, CreateConfiguration());

        Assert.NotEqual(first.Nonce, second.Nonce);
        Assert.NotEqual(first.Ciphertext, second.Ciphertext);
    }

    [Fact]
    public void Unprotect_RejectsAnotherEnvironmentOrTamperedPayload()
    {
        using var keyDeriver = CreateKeyDeriver();
        var protector = new AppEnvironmentConfigurationProtector(keyDeriver);
        var environmentId = Guid.Parse("019b8d00-84fb-71eb-a169-6cbfa9327321");
        var protectedConfiguration = protector.Protect(
            environmentId,
            CreateConfiguration());

        Assert.Throws<InvalidOperationException>(() =>
            protector.Unprotect(Guid.CreateVersion7(), protectedConfiguration));

        protectedConfiguration.Ciphertext[0] ^= 1;
        Assert.Throws<InvalidOperationException>(() =>
            protector.Unprotect(environmentId, protectedConfiguration));

        var tagTampered = protector.Protect(environmentId, CreateConfiguration());
        tagTampered.Tag[^1] ^= 1;
        Assert.Throws<InvalidOperationException>(() =>
            protector.Unprotect(environmentId, tagTampered));
    }

    [Fact]
    public void InstallationKeyDeriver_DerivesStablePurposeSeparatedKeys()
    {
        using var keyDeriver = CreateKeyDeriver();

        var first = keyDeriver.DeriveKey("configuration");
        var samePurpose = keyDeriver.DeriveKey("configuration");
        var anotherPurpose = keyDeriver.DeriveKey("access-flow");

        Assert.Equal(32, first.Length);
        Assert.Equal(first, samePurpose);
        Assert.NotEqual(first, anotherPurpose);
        Assert.False(
            CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(MasterKey),
                first));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-base64")]
    [InlineData("c2hvcnQ=")]
    public void InstallationKeyDeriver_RejectsInvalidMasterKey(string? value)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Bullgate:MasterKey"] = value,
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            new InstallationKeyDeriver(configuration));
    }

    private const string MasterKey =
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    private static InstallationKeyDeriver CreateKeyDeriver()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Bullgate:MasterKey"] = MasterKey,
            })
            .Build();
        return new InstallationKeyDeriver(configuration);
    }

    private static AppEnvironmentConfiguration CreateConfiguration() =>
        new(
            new AppAccessPolicy(
                new IdentifierAccessPolicy(
                    true,
                    true,
                    IdentifierVerificationPolicy.Disabled),
                new IdentifierAccessPolicy(
                    true,
                    false,
                    new IdentifierVerificationPolicy(
                        true,
                        VerificationProviderKey.TwilioVerify)),
                new AuthenticatorAccessPolicy(true, true, false)),
            new AppVerificationPolicy(10, 5, 5, 120, 15, 5),
            new AppRecoveryPolicy(
                "https://example.test/reset-password",
                60,
                5,
                10,
                5,
                5,
                120),
            new AppEnvironmentProviders(
                new SmtpProviderConfiguration(
                    "smtp.example.test",
                    587,
                    "demo",
                    "smtp-demo-password",
                    "access@example.test",
                    "Example",
                    true,
                    false),
                new TwilioVerifyProviderConfiguration(
                    "SK-demo",
                    "twilio-demo-secret",
                    "VA-demo",
                    "sms",
                    "pt-BR",
                    "HJ-demo"),
                new GoogleProviderConfiguration("google-client"),
                null),
            new DevelopmentBypassConfiguration(true, "+5511999999999", "123456"),
            [
                new AppEnvironmentIntegrationClientConfiguration(
                    "api",
                    "API",
                    [AccessPermission.ExecuteFlows]),
            ],
            [
                new AppEnvironmentApplicationClientConfiguration(
                    "android",
                    "Android",
                    ApplicationClientPlatform.Android,
                    "com.example",
                    "sha256:certificate",
                    "92TvTC0UfaA",
                    JsonSerializer.SerializeToElement(new { })),
            ]);
}
