using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Application.Social;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Bullgate.Access.Infrastructure.Social;

/// <summary>
/// Validates Apple identity tokens against OIDC signing keys, issuer, lifetime, and the
/// client id protected in the target app environment.
/// </summary>
/// <remarks>
/// Signing keys come from Apple's OpenID Connect discovery metadata. The normalized
/// assertion contains only the token's non-empty subject and e-mail; no display name is
/// inferred because Apple does not repeat it in ordinary identity-token validation.
/// The current contract does not separately require an <c>email_verified</c> claim;
/// adding one would be an acceptance-policy change, not documentation cleanup.
///
/// Except for caller cancellation, discovery, cryptographic, claim, and unexpected
/// validation failures collapse to a null assertion. Logged exception detail is server
/// diagnostic input and must not be exposed as a public authentication response.
/// </remarks>
public sealed class AppleIdentityValidator(
    IAppEnvironmentConfigurationReader configurations,
    ILogger<AppleIdentityValidator> logger,
    Func<CancellationToken, Task<OpenIdConnectConfiguration>>? oidcConfigSource = null)
    : IAppleIdentityValidator
{
    /// <summary>Shared provider metadata and signing-key cache with rollover support.</summary>
    private static readonly ConfigurationManager<OpenIdConnectConfiguration>
        AppleOidc = new(
            "https://appleid.apple.com/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever());

    // Injection is retained for deterministic validation of discovery and key
    // rollover behavior without replacing production trust metadata.
    private readonly Func<CancellationToken, Task<OpenIdConnectConfiguration>>
        oidcConfigSource = oidcConfigSource ?? (ct => AppleOidc.GetConfigurationAsync(ct));

    /// <inheritdoc />
    public async Task<SocialIdentityAssertion?> ValidateAsync(
        Guid appEnvironmentId,
        string identityToken,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var audience = await RequireClientIdAsync(
                appEnvironmentId,
                cancellationToken);

            var oidc = await oidcConfigSource(cancellationToken);
            // The environment-specific audience is as important as signature validity;
            // it prevents a token issued to another app or service id from crossing scope.
            var result = await new JsonWebTokenHandler().ValidateTokenAsync(
                identityToken,
                new TokenValidationParameters
                {
                    ValidIssuer = "https://appleid.apple.com",
                    ValidAudience = audience,
                    IssuerSigningKeys = oidc.SigningKeys,
                    ValidateLifetime = true,
                });
            if (!result.IsValid)
            {
                logger.LogWarning(
                    "Apple identity token rejected: {Reason}",
                    result.Exception?.Message);
                return null;
            }

            var email = result.Claims.TryGetValue("email", out var emailValue)
                ? emailValue?.ToString()
                : null;
            var subject = result.Claims.TryGetValue("sub", out var subjectValue)
                ? subjectValue?.ToString()
                : null;
            // The current Apple contract accepts a non-empty e-mail from an otherwise
            // validated identity token. Unlike Google validation, it does not inspect a
            // separate email_verified claim; adding that check would change acceptance.
            if (string.IsNullOrWhiteSpace(email)
                || string.IsNullOrWhiteSpace(subject))
            {
                // A cryptographically valid token without both identifiers is unusable
                // for the current Access social-identity contract.
                return null;
            }

            return new SocialIdentityAssertion(email, subject, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Failed to validate Apple identity token.");
            return null;
        }
    }

    /// <summary>Loads the trusted Apple audience from the selected protected environment.</summary>
    /// <remarks>
    /// A client-supplied audience is never accepted. In the concrete validator, missing
    /// configuration is caught with other validation failures and produces no assertion;
    /// the social application service normally rejects absent provider configuration
    /// before invoking this boundary.
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
            cancellationToken))?.Providers.Apple?.ClientId;
        return string.IsNullOrWhiteSpace(clientId)
            ? throw new InvalidOperationException(
                "Apple client id is not configured for the app environment.")
            : clientId.Trim();
    }
}
