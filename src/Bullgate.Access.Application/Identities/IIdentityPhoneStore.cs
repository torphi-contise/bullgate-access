namespace Bullgate.Access.Application.Identities;

/// <summary>
/// Reads an active identity phone and verification time within authenticated realm
/// scope.
/// </summary>
public interface IIdentityPhoneStore
{
    /// <summary>Finds current phone state for an active identity in the given realm.</summary>
    /// <returns>
    /// The phone state, or <see langword="null"/> when the identity is absent, inactive,
    /// outside the realm, or has no phone identifier.
    /// </returns>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="identityId">Caller-controlled durable identity selector.</param>
    /// <param name="cancellationToken">Cancels the scoped query.</param>
    Task<IdentityPhone?> FindAsync(
        Guid realmId,
        Guid identityId,
        CancellationToken cancellationToken);
}

/// <summary>Current normalized phone and its optional possession-proof time.</summary>
/// <param name="Phone">Canonical stored phone value.</param>
/// <param name="VerifiedAt">UTC proof time, or <see langword="null"/> without possession proof.</param>
public sealed record IdentityPhone(string Phone, DateTimeOffset? VerifiedAt);
