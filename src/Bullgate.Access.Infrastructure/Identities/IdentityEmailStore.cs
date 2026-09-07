using Bullgate.Access.Application.Identities;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Identities;

/// <summary>
/// Reads the normalized e-mail of an active identity only when identity and identifier
/// both belong to the authenticated realm.
/// </summary>
internal sealed class IdentityEmailStore(AccessDbContext dbContext)
    : IIdentityEmailStore
{
    /// <inheritdoc />
    public Task<string?> FindAsync(
        Guid realmId,
        Guid identityId,
        CancellationToken cancellationToken) =>
        (
            from identity in dbContext.Identities.AsNoTracking()
            join identifier in dbContext.IdentityIdentifiers.AsNoTracking()
                // Join on realm as well as identity id so a caller-supplied UUID cannot
                // cross the tenancy boundary even if a malformed row were present.
                on new { identity.RealmId, IdentityId = identity.Id }
                equals new { identifier.RealmId, identifier.IdentityId }
            where identity.Id == identityId
                && identity.RealmId == realmId
                && identity.LifecycleState == IdentityLifecycleState.Active
                && identifier.Scheme == IdentifierScheme.Email
            select identifier.NormalizedValue
        ).SingleOrDefaultAsync(cancellationToken);
}
