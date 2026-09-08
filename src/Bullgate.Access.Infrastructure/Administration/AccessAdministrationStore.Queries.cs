using System.Linq.Expressions;
using Bullgate.Access.Application.Administration;
using Bullgate.Access.Domain.Identities;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Administration;

internal sealed partial class AccessAdministrationStore
{
    public async Task<IReadOnlyList<AdminIdentity>> ListIdentitiesAsync(
        AdminIdentityQuery query, Guid? afterId, CancellationToken cancellationToken)
    {
        if (!await dbContext.Realms.AnyAsync(realm => realm.Id == query.RealmId, cancellationToken)) throw NotFound();
        var identities = dbContext.Identities.AsNoTracking().Where(identity => identity.RealmId == query.RealmId);
        if (afterId is not null) identities = identities.Where(identity => identity.Id.CompareTo(afterId.Value) > 0);
        if (query.IdentityId is not null) identities = identities.Where(identity => identity.Id == query.IdentityId);
        if (query.Email is not null) identities = identities.Where(identity => dbContext.IdentityIdentifiers.Any(
            contact => contact.IdentityId == identity.Id && contact.RealmId == query.RealmId
                && contact.Scheme == IdentifierScheme.Email && contact.NormalizedValue == query.Email));
        if (query.Phone is not null) identities = identities.Where(identity => dbContext.IdentityIdentifiers.Any(
            contact => contact.IdentityId == identity.Id && contact.RealmId == query.RealmId
                && contact.Scheme == IdentifierScheme.Phone && contact.NormalizedValue == query.Phone));
        return await identities.OrderBy(identity => identity.Id).Take(query.PageSize + 1)
            .Select(IdentityProjection()).ToArrayAsync(cancellationToken);
    }

    public Task<AdminIdentity?> ReadIdentityAsync(Guid realmId, Guid identityId, CancellationToken cancellationToken) =>
        dbContext.Identities.AsNoTracking().Where(identity => identity.RealmId == realmId && identity.Id == identityId)
            .Select(IdentityProjection()).SingleOrDefaultAsync(cancellationToken);

    private Expression<Func<Identity, AdminIdentity>> IdentityProjection() => identity => new AdminIdentity(
        identity.Id, identity.RealmId, identity.LifecycleState.ToString(), identity.CreatedAt,
        dbContext.IdentityIdentifiers.Where(contact => contact.IdentityId == identity.Id
                && contact.RealmId == identity.RealmId && contact.Scheme == IdentifierScheme.Email)
            .Select(contact => new AdminContact(contact.NormalizedValue, contact.VerifiedAt != null)).SingleOrDefault(),
        dbContext.IdentityIdentifiers.Where(contact => contact.IdentityId == identity.Id
                && contact.RealmId == identity.RealmId && contact.Scheme == IdentifierScheme.Phone)
            .Select(contact => new AdminContact(contact.NormalizedValue, contact.VerifiedAt != null)).SingleOrDefault());

    public async Task<IReadOnlyList<AdminEnvironment>> ListEnvironmentsAsync(
        int pageSize, Guid? afterId, CancellationToken cancellationToken)
    {
        var rows = await (
            from environment in dbContext.AppEnvironments.AsNoTracking()
            join app in dbContext.Apps on environment.AppId equals app.Id
            join realm in dbContext.Realms on environment.RealmId equals realm.Id
            join workspace in dbContext.Workspaces on environment.WorkspaceId equals workspace.Id
            where environment.IsActive && app.IsActive && realm.IsActive && workspace.IsActive
                && app.WorkspaceId == workspace.Id && realm.WorkspaceId == workspace.Id
                && (afterId == null || environment.Id.CompareTo(afterId.Value) > 0)
            orderby environment.Id
            select new
            {
                environment.Id, environment.RealmId, environment.AppId, AppName = app.Name,
                environment.Key, environment.Name, environment.ConfigurationFormatVersion,
                environment.ConfigurationNonce, environment.ConfigurationCiphertext, environment.ConfigurationTag,
            }).Take(pageSize + 1).ToArrayAsync(cancellationToken);
        return rows.Select(row => new AdminEnvironment(row.Id, row.RealmId, row.AppId, row.AppName, row.Key, row.Name,
            Revision(row.Id, row.ConfigurationFormatVersion, row.ConfigurationNonce, row.ConfigurationCiphertext, row.ConfigurationTag))).ToArray();
    }
}
