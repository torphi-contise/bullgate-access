using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Identities;

/// <summary>Shared Access erasure effect below the consumer or Admin authorization gate.</summary>
internal static class IdentityErasure
{
    /// <remarks>The caller must authorize and lock the identity inside its own transaction.</remarks>
    internal static async Task<int> DeleteGraphAsync(
        AccessDbContext dbContext, Guid realmId, Guid identityId, CancellationToken cancellationToken)
    {
        var affectedFlowIds = await dbContext.AccessFlowDataSubjects.AsNoTracking()
            .Where(subject => subject.RealmId == realmId
                && subject.IdentityId == identityId)
            .Select(subject => subject.FlowId)
            .ToArrayAsync(cancellationToken);
        // Data-subject links are append-only erasure reachability. Delete the complete
        // flow when any linked identity is erased because historical snapshots may
        // contain that identity's personal data (ACCESS-016).
        // Deleting the flow root cascades through data-subject links, immutable
        // revisions, idempotency requests, proof challenges and attempts, durable
        // proofs, and phone-conflict evidence. It intentionally does not delete other
        // identities merely because their data is described by the same flow.
        await dbContext.AccessFlows
            .Where(flow => affectedFlowIds.Contains(flow.Id))
            .ExecuteDeleteAsync(cancellationToken);
        // Identity-owned identifiers, authenticators, sessions, and recovery artifacts
        // use database cascades. Topology remains protected by restrictive relationships
        // because erasure removes personal identity data, not installation configuration.
        var deleted = await dbContext.Identities
            .Where(item => item.Id == identityId && item.RealmId == realmId)
            .ExecuteDeleteAsync(cancellationToken);


        return deleted;
    }
}
