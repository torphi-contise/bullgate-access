using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Bullgate.Access.Infrastructure.EmailPassword;

/// <summary>
/// Stores e-mail/password registrations, sessions, introspection state, password
/// changes, and the associated credential invalidation operations.
/// </summary>
/// <remarks>
/// Database uniqueness is the final authority for realm-scoped identifiers. Expected
/// constraint violations are translated to stable application outcomes so concurrent
/// registrations do not leak database errors.
/// </remarks>
internal sealed class EmailPasswordAccessStore(AccessDbContext dbContext)
    : IEmailPasswordAccessStore
{
    private const string IdentifierUniqueConstraint =
        "ux_identity_identifiers_realm_scheme_value";

    public Task<PasswordIdentityCandidate?> FindByEmailAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string normalizedEmail,
        CancellationToken cancellationToken) =>
        // This read shapes normal login/registration behavior but does not reserve the
        // e-mail. The unique database constraint remains authoritative at registration.
        (
            from identifier in dbContext.IdentityIdentifiers.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on identifier.IdentityId equals identity.Id
            join password in dbContext.PasswordCredentials.AsNoTracking()
                on identifier.IdentityId equals password.IdentityId
            from phone in dbContext.IdentityIdentifiers.AsNoTracking()
                .Where(phone =>
                    phone.RealmId == realmId
                    && phone.IdentityId == identifier.IdentityId
                    && phone.Scheme == IdentifierScheme.Phone)
                .DefaultIfEmpty()
            where identifier.RealmId == realmId
                && identifier.Scheme == IdentifierScheme.Email
                && identifier.NormalizedValue == normalizedEmail
                && identity.LifecycleState == IdentityLifecycleState.Active
            select new PasswordIdentityCandidate(
                identifier.IdentityId,
                identifier.NormalizedValue,
                password.PasswordHash,
                dbContext.RegistrationContexts.Any(context =>
                    context.AppEnvironmentId == appEnvironmentId
                    && context.IdentityId == identifier.IdentityId
                    && context.Status == RegistrationContextStatus.Open),
                new AccessAuthenticatorSnapshot(
                    true,
                    dbContext.SocialCredentials.Any(credential =>
                        credential.RealmId == realmId
                        && credential.IdentityId == identifier.IdentityId
                        && credential.Provider == SocialProvider.Google),
                    dbContext.SocialCredentials
                        .Where(credential =>
                            credential.RealmId == realmId
                            && credential.IdentityId == identifier.IdentityId
                            && credential.Provider == SocialProvider.Google)
                        .Select(credential => credential.Email)
                        .FirstOrDefault(),
                    dbContext.SocialCredentials.Any(credential =>
                        credential.RealmId == realmId
                        && credential.IdentityId == identifier.IdentityId
                        && credential.Provider == SocialProvider.Apple),
                    dbContext.SocialCredentials
                        .Where(credential =>
                            credential.RealmId == realmId
                            && credential.IdentityId == identifier.IdentityId
                            && credential.Provider == SocialProvider.Apple)
                        .Select(credential => credential.Email)
                        .FirstOrDefault()),
                phone == null ? null : phone.NormalizedValue,
                phone == null ? null : phone.VerifiedAt)
        ).SingleOrDefaultAsync(cancellationToken);

    public async Task<bool> TryCreateRegistrationAsync(
        Identity identity,
        IdentityIdentifier identifier,
        PasswordCredential passwordCredential,
        RegistrationContext registrationContext,
        IdentitySession session,
        CancellationToken cancellationToken)
    {
        dbContext.Identities.Add(identity);
        dbContext.IdentityIdentifiers.Add(identifier);
        dbContext.PasswordCredentials.Add(passwordCredential);
        dbContext.RegistrationContexts.Add(registrationContext);
        dbContext.IdentitySessions.Add(session);

        try
        {
            // One SaveChanges call gives the initial identity, identifier, authenticator,
            // registration context, and session a single EF-managed transaction.
            await dbContext.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException exception)
            when (exception.InnerException is PostgresException
            {
                SqlState: PostgresErrorCodes.UniqueViolation,
                ConstraintName: IdentifierUniqueConstraint,
            })
        {
            dbContext.ChangeTracker.Clear();
            return false;
        }
    }

    public Task AddSessionAsync(
        IdentitySession session,
        CancellationToken cancellationToken)
    {
        dbContext.IdentitySessions.Add(session);
        return dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task<SessionIntrospectionCandidate?> FindSessionAsync(
        Guid appEnvironmentId,
        byte[] tokenHash,
        CancellationToken cancellationToken) =>
        // Do not filter revocation or expiry here. Returning those fields lets the
        // application collapse every inactive state into the same public contract.
        (
            from session in dbContext.IdentitySessions.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on session.IdentityId equals identity.Id
            join identifier in dbContext.IdentityIdentifiers.AsNoTracking()
                on session.IdentityId equals identifier.IdentityId
            from phone in dbContext.IdentityIdentifiers.AsNoTracking()
                .Where(phone =>
                    phone.RealmId == identity.RealmId
                    && phone.IdentityId == session.IdentityId
                    && phone.Scheme == IdentifierScheme.Phone)
                .DefaultIfEmpty()
            where session.AppEnvironmentId == appEnvironmentId
                && session.TokenHash.SequenceEqual(tokenHash)
                && identifier.Scheme == IdentifierScheme.Email
                && identity.LifecycleState == IdentityLifecycleState.Active
            select new SessionIntrospectionCandidate(
                session.Id,
                session.IdentityId,
                identifier.NormalizedValue,
                session.ExpiresAt,
                session.RevokedAt,
                session.Purpose,
                new AccessAuthenticatorSnapshot(
                    dbContext.PasswordCredentials.Any(credential =>
                        credential.IdentityId == session.IdentityId),
                    dbContext.SocialCredentials.Any(credential =>
                        credential.IdentityId == session.IdentityId
                        && credential.Provider == SocialProvider.Google),
                    dbContext.SocialCredentials
                        .Where(credential =>
                            credential.IdentityId == session.IdentityId
                            && credential.Provider == SocialProvider.Google)
                        .Select(credential => credential.Email)
                        .FirstOrDefault(),
                    dbContext.SocialCredentials.Any(credential =>
                        credential.IdentityId == session.IdentityId
                        && credential.Provider == SocialProvider.Apple),
                    dbContext.SocialCredentials
                        .Where(credential =>
                            credential.IdentityId == session.IdentityId
                            && credential.Provider == SocialProvider.Apple)
                        .Select(credential => credential.Email)
                        .FirstOrDefault()),
                dbContext.PasswordCredentials
                    .Where(credential => credential.IdentityId == session.IdentityId)
                    .Select(credential => credential.PasswordHash)
                    .FirstOrDefault(),
                phone == null ? null : phone.NormalizedValue,
                phone == null ? null : phone.VerifiedAt)
        ).SingleOrDefaultAsync(cancellationToken);

    /// <inheritdoc />
    public Task RevokeSessionAsync(
        Guid appEnvironmentId,
        byte[] tokenHash,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken) =>
        // Expiry is intentionally absent from this predicate. Explicit revocation may
        // still annotate an expired row, while the unrevoked filter makes retries safe
        // and preserves the first revocation time.
        dbContext.IdentitySessions
            .Where(session =>
                session.AppEnvironmentId == appEnvironmentId
                && session.TokenHash.SequenceEqual(tokenHash)
                && session.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    session => session.RevokedAt,
                    revokedAt),
                cancellationToken);

    public async Task<bool> TrySetPasswordAndRevokeOtherSessionsAsync(
        Guid identityId,
        Guid currentSessionId,
        string? expectedPasswordHash,
        string passwordHash,
        DateTimeOffset changedAt,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();

        // Password replacement, recovery-token invalidation, and revocation of other
        // sessions form one security operation. Committing only a subset would leave
        // an older credential path active after the password change.
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var identity = await dbContext.Identities
            .FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {identityId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        if (identity is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        var credential = await dbContext.PasswordCredentials.SingleOrDefaultAsync(
            item => item.IdentityId == identityId,
            cancellationToken);
        if (!string.Equals(
                credential?.PasswordHash,
                expectedPasswordHash,
                StringComparison.Ordinal))
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        if (credential is null)
        {
            dbContext.PasswordCredentials.Add(
                new PasswordCredential(identityId, passwordHash, changedAt));
        }
        else
        {
            credential.Replace(passwordHash, changedAt);
        }

        await dbContext.SaveChangesAsync(cancellationToken);
        await dbContext.PasswordResetTokens
            .Where(token =>
                token.IdentityId == identityId
                && token.UsedAt == null
                && token.ExpiresAt > changedAt)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    token => token.UsedAt,
                    changedAt),
                cancellationToken);
        await dbContext.IdentitySessions
            .Where(session =>
                session.IdentityId == identityId
                && session.Id != currentSessionId
                && session.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    session => session.RevokedAt,
                    changedAt),
                cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }
}
