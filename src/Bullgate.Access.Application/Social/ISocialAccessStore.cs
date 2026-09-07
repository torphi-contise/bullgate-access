using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.Application.Social;

/// <summary>
/// Transactional persistence boundary for social authentication and current-identity
/// link/unlink operations.
/// </summary>
/// <remarks>
/// A matching provider email is metadata, not authorization to merge identities.
/// Subject ownership is arbitrated inside the realm.
/// </remarks>
public interface ISocialAccessStore
{
    /// <summary>
    /// Finds an active identity by the realm-scoped provider and immutable provider
    /// subject, including current registration and authenticator state.
    /// </summary>
    /// <param name="realmId">Realm that owns provider-subject uniqueness.</param>
    /// <param name="appEnvironmentId">Environment used to resolve open registration.</param>
    /// <param name="provider">Canonical provider discriminator.</param>
    /// <param name="subject">Stable provider account identifier.</param>
    /// <param name="cancellationToken">Cancels the persistence query.</param>
    Task<SocialIdentityCandidate?> FindByProviderAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string provider,
        string subject,
        CancellationToken cancellationToken);

    /// <summary>Persists a newly issued session for an existing social identity.</summary>
    /// <param name="session">Registration or product session containing only token hash.</param>
    /// <param name="cancellationToken">Cancels persistence.</param>
    Task AddSessionAsync(IdentitySession session, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically persists a new identity, verified e-mail, social credential,
    /// registration context, and initial session.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when concurrent e-mail or provider-subject ownership
    /// prevents creation without an account merge.
    /// </returns>
    /// <param name="identity">New realm-owned identity aggregate root.</param>
    /// <param name="emailIdentifier">Verified primary e-mail from the accepted assertion.</param>
    /// <param name="socialCredential">Provider-subject ownership record.</param>
    /// <param name="registrationContext">Environment registration lifecycle.</param>
    /// <param name="session">Initial registration or product session.</param>
    /// <param name="cancellationToken">Cancels the atomic creation operation.</param>
    Task<bool> TryCreateRegistrationAsync(
        Identity identity,
        IdentityIdentifier emailIdentifier,
        SocialCredential socialCredential,
        RegistrationContext registrationContext,
        IdentitySession session,
        CancellationToken cancellationToken);

    /// <summary>
    /// Resolves session and current authenticator state for a link or unlink request
    /// inside the authenticated realm and environment.
    /// </summary>
    /// <remarks>
    /// Revocation, expiry, and purpose remain in the returned projection so the
    /// application layer, rather than the query shape, owns stable error mapping.
    /// </remarks>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="appEnvironmentId">Environment fixed by authenticated integration scope.</param>
    /// <param name="tokenHash">Hash of the untrusted presented product bearer.</param>
    /// <param name="cancellationToken">Cancels the persistence query.</param>
    Task<SocialSessionCandidate?> FindSessionAsync(
        Guid realmId,
        Guid appEnvironmentId,
        byte[] tokenHash,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically attaches one provider subject, preserving one-provider-per-identity
    /// and one-owner-per-subject invariants.
    /// </summary>
    /// <remarks>
    /// Repeating the same subject is idempotent and may refresh provider e-mail
    /// metadata. A different subject is never substituted for the existing one.
    /// </remarks>
    /// <param name="realmId">Realm that owns provider-subject uniqueness.</param>
    /// <param name="identityId">Product identity receiving the credential.</param>
    /// <param name="provider">Canonical provider discriminator.</param>
    /// <param name="subject">Stable provider account identifier.</param>
    /// <param name="email">Provider metadata accepted by server-side validation.</param>
    /// <param name="linkedAt">UTC link or metadata-refresh time.</param>
    /// <param name="cancellationToken">Cancels the transactional operation.</param>
    Task<SocialLinkStoreStatus> LinkAsync(
        Guid realmId,
        Guid identityId,
        string provider,
        string subject,
        string email,
        DateTimeOffset linkedAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// Atomically removes one provider credential only when another authenticator keeps
    /// the identity accessible.
    /// </summary>
    /// <remarks>
    /// The last-authenticator decision must be serialized with concurrent removals;
    /// a preliminary application-layer count is not authoritative.
    /// </remarks>
    /// <param name="realmId">Realm containing the credential.</param>
    /// <param name="identityId">Product identity losing the credential.</param>
    /// <param name="provider">Canonical provider discriminator.</param>
    /// <param name="cancellationToken">Cancels the transactional operation.</param>
    Task<SocialUnlinkStoreStatus> UnlinkAsync(
        Guid realmId,
        Guid identityId,
        string provider,
        CancellationToken cancellationToken);
}

/// <summary>Identity and registration state resolved by provider subject.</summary>
/// <param name="IdentityId">Identity that owns the provider subject.</param>
/// <param name="NormalizedEmail">Current canonical primary e-mail.</param>
/// <param name="HasOpenRegistrationContext">Whether target-environment registration remains open.</param>
/// <param name="Authenticators">Current authenticator availability.</param>
/// <param name="Phone">Optional current canonical phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone-possession proof time.</param>
public sealed record SocialIdentityCandidate(
    Guid IdentityId,
    string NormalizedEmail,
    bool HasOpenRegistrationContext,
    AccessAuthenticatorSnapshot Authenticators,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null);

/// <summary>Scoped session candidate used to authorize social link and unlink operations.</summary>
/// <remarks>
/// A returned candidate may still be expired, revoked, or registration-purpose. The
/// application service evaluates those fields before granting management authority.
/// </remarks>
/// <param name="IdentityId">Identity that owns the session.</param>
/// <param name="SessionId">Durable session selector, not bearer authority.</param>
/// <param name="NormalizedEmail">Current canonical primary e-mail.</param>
/// <param name="ExpiresAt">UTC session inactivity boundary.</param>
/// <param name="RevokedAt">UTC first-revocation time, when present.</param>
/// <param name="Purpose">Registration or product authority class.</param>
/// <param name="Authenticators">Current authenticator availability.</param>
/// <param name="Phone">Optional current canonical phone.</param>
/// <param name="PhoneVerifiedAt">Optional phone-possession proof time.</param>
public sealed record SocialSessionCandidate(
    Guid IdentityId,
    Guid SessionId,
    string NormalizedEmail,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? RevokedAt,
    IdentitySessionPurpose Purpose,
    AccessAuthenticatorSnapshot Authenticators,
    string? Phone = null,
    DateTimeOffset? PhoneVerifiedAt = null);

/// <summary>Atomic outcomes of attaching a provider subject to an identity.</summary>
public enum SocialLinkStoreStatus
{
    /// <summary>A new credential was attached.</summary>
    Linked,

    /// <summary>The same subject was already attached; metadata is now current.</summary>
    AlreadyLinked,

    /// <summary>The identity already owns another subject for this provider.</summary>
    ProviderAlreadyLinked,

    /// <summary>Another identity owns the provider subject or won a uniqueness race.</summary>
    CredentialAlreadyInUse,
}

/// <summary>Atomic outcomes of removing a provider without removing the last authenticator.</summary>
public enum SocialUnlinkStoreStatus
{
    /// <summary>The credential was removed while another authenticator remained.</summary>
    Unlinked,

    /// <summary>The identity did not own the requested provider credential.</summary>
    NotLinked,

    /// <summary>Removal was rejected because it would eliminate the final authenticator.</summary>
    LastAuthenticator,
}
