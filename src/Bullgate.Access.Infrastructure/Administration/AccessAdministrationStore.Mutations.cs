using Bullgate.Access.Application.Administration;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Identities;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Administration;

internal sealed partial class AccessAdministrationStore
{
    private async Task<AdminOperationResult> MutateIdentityAsync(
        AdminCallContext context, AdminMutation mutation, CancellationToken cancellationToken)
    {
        var identity = await dbContext.Identities.FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {mutation.TargetId} AND realm_id = {mutation.RealmId} FOR UPDATE")
            .AsNoTracking().SingleOrDefaultAsync(cancellationToken) ?? throw NotFound();
        var now = timeProvider.GetUtcNow();
        if (context.Permission == AccessPermission.DeleteIdentities)
        {
            await IdentityErasure.DeleteGraphAsync(dbContext, identity.RealmId, identity.Id, cancellationToken);
            return new AdminOperationResult(mutation.OperationId, context.Permission, identity.Id, now);
        }
        // FOR UPDATE also conflicts with the session FK's KEY SHARE lock. Issuance that
        // committed before this lock is visible to the next ReadCommitted statement;
        // a new login inserted after this cut remains allowed. Flow writers already lock
        // the identity before revalidating their source session and issuing a successor.
        var count = await dbContext.IdentitySessions.Where(session => session.IdentityId == identity.Id
                && session.RevokedAt == null && session.ExpiresAt > now)
            .ExecuteUpdateAsync(setters => setters.SetProperty(session => session.RevokedAt, now), cancellationToken);
        return new AdminOperationResult(mutation.OperationId, context.Permission, identity.Id, now, count);
    }

    private async Task<AdminOperationResult> ReplaceConfigurationAsync(
        AdminCallContext context, AdminMutation mutation, CancellationToken cancellationToken)
    {
        // Same installation-wide lock as explicit CLI bootstrap; no writer handover.
        await dbContext.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(1101700001)", cancellationToken);
        var environment = await dbContext.AppEnvironments.SingleOrDefaultAsync(
            item => item.Id == mutation.TargetId && item.IsActive, cancellationToken) ?? throw NotFound();
        if (!await dbContext.Workspaces.AnyAsync(item => item.Id == environment.WorkspaceId && item.IsActive, cancellationToken)
            || !await dbContext.Apps.AnyAsync(item => item.Id == environment.AppId
                && item.WorkspaceId == environment.WorkspaceId && item.IsActive, cancellationToken)
            || !await dbContext.Realms.AnyAsync(item => item.Id == environment.RealmId
                && item.WorkspaceId == environment.WorkspaceId && item.IsActive, cancellationToken)) throw NotFound();
        if (Revision(environment.Id, environment.ConfigurationFormatVersion, environment.ConfigurationNonce,
                environment.ConfigurationCiphertext, environment.ConfigurationTag) != mutation.ExpectedRevision)
            throw new AccessAdministrationException(412, "configuration-revision-stale");
        var configuration = mutation.Configuration ?? throw InvalidInput();

        foreach (var declaration in configuration.IntegrationClients)
        {
            var client = await topologyStore.FindIntegrationClientAsync(environment.Id, declaration.Key, cancellationToken);
            if (client is null || !client.IsActive || client.Name != declaration.Name) throw InvalidInput();
            var actual = await topologyStore.GetIntegrationClientPermissionsAsync(client.Id, cancellationToken);
            if (!actual.Order(StringComparer.Ordinal).SequenceEqual(declaration.Permissions.Order(StringComparer.Ordinal)))
                throw InvalidInput();
        }
        foreach (var declaration in configuration.ApplicationClients)
        {
            var client = await topologyStore.FindApplicationClientAsync(environment.Id, declaration.Key, cancellationToken);
            if (client is null || !client.IsActive) throw InvalidInput();
            client.Configure(declaration.Name, declaration.Platform, declaration.ApplicationId,
                declaration.SigningIdentity, declaration.SmsRetrieverAppHash);
        }

        var now = timeProvider.GetUtcNow();
        environment.ConfigureAccess(configuration.AccessPolicy);
        environment.ConfigurePasswordRecoveryUrl(configuration.RecoveryPolicy.PasswordRecoveryUrl);
        topologyStore.StoreConfiguration(environment, configuration, now);
        var revision = Revision(environment.Id, environment.ConfigurationFormatVersion, environment.ConfigurationNonce,
            environment.ConfigurationCiphertext, environment.ConfigurationTag);
        return new AdminOperationResult(mutation.OperationId, context.Permission, environment.Id, now, Revision: revision);
    }
}
