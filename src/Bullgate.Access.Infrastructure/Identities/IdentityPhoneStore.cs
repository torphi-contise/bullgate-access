using Bullgate.Access.Application.Identities;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Identities;

/// <summary>
/// Reads the normalized phone and verification time of an active identity inside the
/// authenticated realm.
/// </summary>
internal sealed class IdentityPhoneStore(AccessDbContext dbContext)
    : IIdentityPhoneStore
{
    /// <inheritdoc />
    public Task<IdentityPhone?> FindAsync(
        Guid realmId,
        Guid identityId,
        CancellationToken cancellationToken) =>
        (
            from identity in dbContext.Identities.AsNoTracking()
            join identifier in dbContext.IdentityIdentifiers.AsNoTracking()
                // Realm participates in the join and filter. Possession of a valid
                // identity UUID alone never authorizes a cross-realm contact lookup.
                on new { identity.RealmId, IdentityId = identity.Id }
                equals new { identifier.RealmId, identifier.IdentityId }
            where identity.Id == identityId
                && identity.RealmId == realmId
                && identity.LifecycleState == IdentityLifecycleState.Active
                && identifier.Scheme == IdentifierScheme.Phone
            select new IdentityPhone(
                identifier.NormalizedValue,
                identifier.VerifiedAt)
        ).SingleOrDefaultAsync(cancellationToken);
}
