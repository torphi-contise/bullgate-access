using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Application.Social;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Bullgate.Access.Infrastructure.Social;

/// <summary>
/// Persists social credentials and sessions without treating provider e-mail claims
/// as authority to merge independently created identities.
/// </summary>
/// <remarks>
/// Provider subjects are unique within a realm. Linking and unlinking return explicit
/// conflict states because silent reassignment can transfer account control.
/// </remarks>
internal sealed class SocialAccessStore(AccessDbContext dbContext)
    : ISocialAccessStore
{
    private static readonly string[] UniqueConstraints =
    [
        "ux_identity_identifiers_realm_scheme_value",
        "ux_social_credentials_realm_provider_subject",
    ];

    public Task<SocialIdentityCandidate?> FindByProviderAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string provider,
        string subject,
        CancellationToken cancellationToken) =>
        // Provider plus subject selects identity ownership. E-mail participates only in
        // the returned contact snapshot and never in the credential lookup predicate.
        (
            from credential in dbContext.SocialCredentials.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on credential.IdentityId equals identity.Id
            join identifier in dbContext.IdentityIdentifiers.AsNoTracking()
                on credential.IdentityId equals identifier.IdentityId
            from phone in dbContext.IdentityIdentifiers.AsNoTracking()
                .Where(phone =>
                    phone.RealmId == realmId
                    && phone.IdentityId == credential.IdentityId
                    && phone.Scheme == IdentifierScheme.Phone)
                .DefaultIfEmpty()
            where credential.RealmId == realmId
                && credential.Provider == provider
                && credential.Subject == subject
                && identifier.Scheme == IdentifierScheme.Email
                && identity.LifecycleState == IdentityLifecycleState.Active
            select new SocialIdentityCandidate(
                credential.IdentityId,
                identifier.NormalizedValue,
                dbContext.RegistrationContexts.Any(context =>
                    context.AppEnvironmentId == appEnvironmentId
                    && context.IdentityId == credential.IdentityId
                    && context.Status == RegistrationContextStatus.Open),
                new AccessAuthenticatorSnapshot(
                    dbContext.PasswordCredentials.Any(password =>
                        password.IdentityId == credential.IdentityId),
                    dbContext.SocialCredentials.Any(item =>
                        item.RealmId == realmId
                        && item.IdentityId == credential.IdentityId
                        && item.Provider == SocialProvider.Google),
                    dbContext.SocialCredentials
                        .Where(item =>
                            item.RealmId == realmId
                            && item.IdentityId == credential.IdentityId
                            && item.Provider == SocialProvider.Google)
                        .Select(item => item.Email)
                        .FirstOrDefault(),
                    dbContext.SocialCredentials.Any(item =>
                        item.RealmId == realmId
                        && item.IdentityId == credential.IdentityId
                        && item.Provider == SocialProvider.Apple),
                    dbContext.SocialCredentials
                        .Where(item =>
                            item.RealmId == realmId
                            && item.IdentityId == credential.IdentityId
                            && item.Provider == SocialProvider.Apple)
                        .Select(item => item.Email)
                        .FirstOrDefault()),
                phone == null ? null : phone.NormalizedValue,
                phone == null ? null : phone.VerifiedAt)
        ).SingleOrDefaultAsync(cancellationToken);

    public Task AddSessionAsync(
        IdentitySession session,
        CancellationToken cancellationToken)
    {
        dbContext.IdentitySessions.Add(session);
        return dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> TryCreateRegistrationAsync(
        Identity identity,
        IdentityIdentifier emailIdentifier,
        SocialCredential socialCredential,
        RegistrationContext registrationContext,
        IdentitySession session,
        CancellationToken cancellationToken)
    {
        dbContext.Identities.Add(identity);
        dbContext.IdentityIdentifiers.Add(emailIdentifier);
        dbContext.SocialCredentials.Add(socialCredential);
        dbContext.RegistrationContexts.Add(registrationContext);
        dbContext.IdentitySessions.Add(session);

        try
        {
            // One SaveChanges transaction prevents a partial identity graph if either
            // e-mail ownership or provider-subject ownership loses a concurrent race.
            await dbContext.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException exception)
            when (exception.InnerException is PostgresException
            {
                SqlState: PostgresErrorCodes.UniqueViolation,
                ConstraintName: var constraintName,
            } && UniqueConstraints.Contains(constraintName, StringComparer.Ordinal))
        {
            // Another registration may have claimed the e-mail or provider subject
            // after the lookup. Preserve the no-merge rule by returning a conflict
            // instead of attaching either credential to an existing identity.
            dbContext.ChangeTracker.Clear();
            return false;
        }
    }

    public Task<SocialSessionCandidate?> FindSessionAsync(
        Guid realmId,
        Guid appEnvironmentId,
        byte[] tokenHash,
        CancellationToken cancellationToken) =>
        // Revocation, expiry, and purpose remain in the projection so the application
        // can map every ineligible session to its stable management outcome.
        (
            from session in dbContext.IdentitySessions.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on session.IdentityId equals identity.Id
            join identifier in dbContext.IdentityIdentifiers.AsNoTracking()
                on session.IdentityId equals identifier.IdentityId
            from phone in dbContext.IdentityIdentifiers.AsNoTracking()
                .Where(phone =>
                    phone.RealmId == realmId
                    && phone.IdentityId == session.IdentityId
                    && phone.Scheme == IdentifierScheme.Phone)
                .DefaultIfEmpty()
            where session.AppEnvironmentId == appEnvironmentId
                && session.TokenHash.SequenceEqual(tokenHash)
                && identity.RealmId == realmId
                && identifier.RealmId == realmId
                && identifier.Scheme == IdentifierScheme.Email
                && identity.LifecycleState == IdentityLifecycleState.Active
            select new SocialSessionCandidate(
                session.IdentityId,
                session.Id,
                identifier.NormalizedValue,
                session.ExpiresAt,
                session.RevokedAt,
                session.Purpose,
                new AccessAuthenticatorSnapshot(
                    dbContext.PasswordCredentials.Any(password =>
                        password.IdentityId == session.IdentityId),
                    dbContext.SocialCredentials.Any(item =>
                        item.RealmId == realmId
                        && item.IdentityId == session.IdentityId
                        && item.Provider == SocialProvider.Google),
                    dbContext.SocialCredentials
                        .Where(item =>
                            item.RealmId == realmId
                            && item.IdentityId == session.IdentityId
                            && item.Provider == SocialProvider.Google)
                        .Select(item => item.Email)
                        .FirstOrDefault(),
                    dbContext.SocialCredentials.Any(item =>
                        item.RealmId == realmId
                        && item.IdentityId == session.IdentityId
                        && item.Provider == SocialProvider.Apple),
                    dbContext.SocialCredentials
                        .Where(item =>
                            item.RealmId == realmId
                            && item.IdentityId == session.IdentityId
                            && item.Provider == SocialProvider.Apple)
                        .Select(item => item.Email)
                        .FirstOrDefault()),
                phone == null ? null : phone.NormalizedValue,
                phone == null ? null : phone.VerifiedAt)
        ).SingleOrDefaultAsync(cancellationToken);

    public async Task<SocialLinkStoreStatus> LinkAsync(
        Guid realmId,
        Guid identityId,
        string provider,
        string subject,
        string email,
        DateTimeOffset linkedAt,
        CancellationToken cancellationToken)
    {
        var current = await dbContext.SocialCredentials.SingleOrDefaultAsync(
            item => item.RealmId == realmId
                && item.IdentityId == identityId
                && item.Provider == provider,
            cancellationToken);
        if (current is not null)
        {
            // Repeating the same provider subject is idempotent. A changed provider
            // e-mail refreshes metadata only and does not change credential ownership.
            if (!string.Equals(current.Subject, subject, StringComparison.Ordinal))
            {
                return SocialLinkStoreStatus.ProviderAlreadyLinked;
            }
            if (!string.Equals(current.Email, email, StringComparison.Ordinal))
            {
                current.UpdateEmail(email, linkedAt);
                await dbContext.SaveChangesAsync(cancellationToken);
            }
            return SocialLinkStoreStatus.AlreadyLinked;
        }

        // This read provides a clear conflict result in the normal path, but the unique
        // constraint below remains authoritative when another link commits concurrently.
        var owner = await dbContext.SocialCredentials
            .AsNoTracking()
            .Where(item =>
                item.RealmId == realmId
                && item.Provider == provider
                && item.Subject == subject)
            .Select(item => (Guid?)item.IdentityId)
            .SingleOrDefaultAsync(cancellationToken);
        if (owner is not null && owner.Value != identityId)
        {
            return SocialLinkStoreStatus.CredentialAlreadyInUse;
        }

        dbContext.SocialCredentials.Add(new SocialCredential(
            Guid.CreateVersion7(linkedAt),
            identityId,
            realmId,
            provider,
            subject,
            email,
            linkedAt));
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return SocialLinkStoreStatus.Linked;
        }
        catch (DbUpdateException exception)
            when (exception.InnerException is PostgresException
            {
                SqlState: PostgresErrorCodes.UniqueViolation,
            })
        {
            // Do not retry by reassigning or merging. Any lost uniqueness race means the
            // submitted credential cannot be attached to this identity.
            dbContext.ChangeTracker.Clear();
            return SocialLinkStoreStatus.CredentialAlreadyInUse;
        }
    }

    public async Task<SocialUnlinkStoreStatus> UnlinkAsync(
        Guid realmId,
        Guid identityId,
        string provider,
        CancellationToken cancellationToken)
    {
        // Lock the identity so two simultaneous unlink requests cannot each observe a
        // different remaining authenticator and together remove the final login path.
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        _ = await dbContext.Identities
            .FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {identityId} FOR UPDATE")
            .SingleAsync(cancellationToken);

        var credentials = await dbContext.SocialCredentials
            .Where(item => item.RealmId == realmId && item.IdentityId == identityId)
            .ToListAsync(cancellationToken);
        var target = credentials.SingleOrDefault(item => item.Provider == provider);
        if (target is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return SocialUnlinkStoreStatus.NotLinked;
        }
        var hasPassword = await dbContext.PasswordCredentials.AnyAsync(
            item => item.IdentityId == identityId,
            cancellationToken);
        if (!hasPassword && credentials.Count == 1)
        {
            // An identity must retain at least one authenticator. This guard is kept
            // inside the identity lock because it is a concurrency invariant, not only
            // a user-interface restriction.
            await transaction.RollbackAsync(cancellationToken);
            return SocialUnlinkStoreStatus.LastAuthenticator;
        }

        dbContext.SocialCredentials.Remove(target);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return SocialUnlinkStoreStatus.Unlinked;
    }
}
