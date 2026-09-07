namespace Bullgate.Access.Application.Social;

/// <summary>
/// Provider-validated identity material normalized for the application layer.
/// </summary>
/// <remarks>
/// The provider subject is identity authority. E-mail and display name are metadata
/// emitted only after the validator has applied its provider-specific trust contract.
/// </remarks>
/// <param name="Email">Provider e-mail accepted by the validator.</param>
/// <param name="Subject">Stable provider account identifier used as credential ownership.</param>
/// <param name="DisplayName">Optional presentation metadata; never an identity key.</param>
public sealed record SocialIdentityAssertion(
    string Email,
    string Subject,
    string? DisplayName);

/// <summary>Validates Google tokens server-side and returns a normalized assertion.</summary>
/// <remarks>
/// A rejected assertion is intentionally represented by <see langword="null"/> rather
/// than provider diagnostic details. Configuration and cancellation failures are not
/// identity claims and retain their implementation-specific behavior.
/// </remarks>
public interface IGoogleIdentityValidator
{
    /// <summary>
    /// Validates a signed Google ID token against the client id protected in the target
    /// environment.
    /// </summary>
    /// <param name="appEnvironmentId">Environment that owns the trusted Google client id.</param>
    /// <param name="idToken">Untrusted clear ID token; it must not be logged.</param>
    /// <param name="cancellationToken">Cancels provider validation.</param>
    /// <returns>A normalized assertion, or <see langword="null"/> for any rejected claim set.</returns>
    Task<SocialIdentityAssertion?> ValidateIdTokenAsync(
        Guid appEnvironmentId,
        string idToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a Google access token through provider endpoints while binding its
    /// audience or authorized party to the target environment.
    /// </summary>
    /// <param name="appEnvironmentId">Environment that owns the trusted Google client id.</param>
    /// <param name="accessToken">Untrusted clear bearer used only with Google endpoints.</param>
    /// <param name="cancellationToken">Cancels provider validation.</param>
    /// <returns>A normalized assertion, or <see langword="null"/> for any rejected claim set.</returns>
    Task<SocialIdentityAssertion?> ValidateAccessTokenAsync(
        Guid appEnvironmentId,
        string accessToken,
        CancellationToken cancellationToken = default);
}

/// <summary>Validates an Apple identity token server-side and returns its assertion.</summary>
/// <remarks>
/// The normalized assertion contains no raw token or signing metadata. Callers must not
/// infer whether null resulted from claims, cryptography, discovery, or provider
/// availability unless the concrete validator documents a narrower distinction.
/// </remarks>
public interface IAppleIdentityValidator
{
    /// <summary>
    /// Validates Apple issuer, signature, lifetime, audience, subject, and e-mail against
    /// configuration protected in the target environment.
    /// </summary>
    /// <param name="appEnvironmentId">Environment that owns the trusted Apple client id.</param>
    /// <param name="identityToken">Untrusted clear identity token; it must not be logged.</param>
    /// <param name="cancellationToken">Cancels provider validation.</param>
    /// <returns>A normalized assertion, or <see langword="null"/> for any rejected claim set.</returns>
    Task<SocialIdentityAssertion?> ValidateAsync(
        Guid appEnvironmentId,
        string identityToken,
        CancellationToken cancellationToken = default);
}
