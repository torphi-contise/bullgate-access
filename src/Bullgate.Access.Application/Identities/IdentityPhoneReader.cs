namespace Bullgate.Access.Application.Identities;

/// <summary>Reads current phone and verification state inside an explicit realm.</summary>
public sealed class IdentityPhoneReader(IIdentityPhoneStore store)
{
    /// <summary>
    /// Reads an active identity's phone and proof time without broadening the explicit
    /// realm supplied by authenticated integration scope.
    /// </summary>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="identityId">Caller-controlled durable identity selector.</param>
    /// <param name="cancellationToken">Cancels the scoped query.</param>
    public Task<IdentityPhone?> GetAsync(
        Guid realmId,
        Guid identityId,
        CancellationToken cancellationToken = default)
    {
        if (realmId == Guid.Empty)
        {
            throw new ArgumentException("Realm id cannot be empty.", nameof(realmId));
        }

        if (identityId == Guid.Empty)
        {
            throw new ArgumentException("Identity id cannot be empty.", nameof(identityId));
        }

        return store.FindAsync(realmId, identityId, cancellationToken);
    }
}
