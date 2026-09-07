using Bullgate.Access.Application.Identities;
using Bullgate.Access.Application.Sessions;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Bullgate.Access.Infrastructure.Identities;

/// <summary>
/// Applies mutations authorized by the current product session, including e-mail
/// replacement and hard deletion of all Access-owned identity data.
/// </summary>
/// <remarks>
/// Realm, environment, session purpose, and lifecycle checks are repeated inside the
/// transaction so a stale pre-check cannot authorize a mutation.
/// </remarks>
internal sealed class CurrentIdentityStore(AccessDbContext dbContext)
    : ICurrentIdentityStore
{
    private const string IdentifierUniqueConstraint =
        "ux_identity_identifiers_realm_scheme_value";

    /// <inheritdoc />
    public Task<CurrentIdentityCandidate?> FindBySessionAsync(
        Guid appEnvironmentId,
        byte[] sessionTokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        // Resolve the identity graph only through an active session in the requested
        // environment. The application layer separately checks realm and product purpose
        // before treating this snapshot as eligible for mutation.
        (
            from session in dbContext.IdentitySessions.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on session.IdentityId equals identity.Id
            join email in dbContext.IdentityIdentifiers.AsNoTracking()
                on session.IdentityId equals email.IdentityId
            from phone in dbContext.IdentityIdentifiers.AsNoTracking()
                .Where(identifier => identifier.IdentityId == session.IdentityId
                    && identifier.RealmId == identity.RealmId
                    && identifier.Scheme == IdentifierScheme.Phone)
                .DefaultIfEmpty()
            where session.AppEnvironmentId == appEnvironmentId
                && session.TokenHash.SequenceEqual(sessionTokenHash)
                && session.RevokedAt == null
                && session.ExpiresAt > now
                && identity.LifecycleState == IdentityLifecycleState.Active
                && email.RealmId == identity.RealmId
                && email.Scheme == IdentifierScheme.Email
            select new CurrentIdentityCandidate(
                identity.Id,
                session.Id,
                identity.RealmId,
                email.NormalizedValue,
                phone == null ? null : phone.NormalizedValue,
                phone == null ? null : phone.VerifiedAt,
                session.ExpiresAt,
                session.Purpose,
                new AccessAuthenticatorSnapshot(
                    dbContext.PasswordCredentials.Any(credential =>
                        credential.IdentityId == identity.Id),
                    dbContext.SocialCredentials.Any(credential =>
                        credential.IdentityId == identity.Id
                        && credential.Provider == SocialProvider.Google),
                    dbContext.SocialCredentials
                        .Where(credential => credential.IdentityId == identity.Id
                            && credential.Provider == SocialProvider.Google)
                        .Select(credential => credential.Email)
                        .FirstOrDefault(),
                    dbContext.SocialCredentials.Any(credential =>
                        credential.IdentityId == identity.Id
                        && credential.Provider == SocialProvider.Apple),
                    dbContext.SocialCredentials
                        .Where(credential => credential.IdentityId == identity.Id
                            && credential.Provider == SocialProvider.Apple)
                        .Select(credential => credential.Email)
                        .FirstOrDefault()))
        ).SingleOrDefaultAsync(cancellationToken);

    /// <inheritdoc />
    public async Task<CurrentIdentityMutationStatus> TryChangeEmailAsync(
        Guid realmId,
        Guid appEnvironmentId,
        Guid identityId,
        Guid sessionId,
        string normalizedEmail,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        try
        {
            // Serialize identity and session mutations before checking authorization.
            // A concurrent revocation or deletion must be observed before the e-mail
            // value is changed.
            await using var transaction = await dbContext.Database.BeginTransactionAsync(
                cancellationToken);
            var identity = await dbContext.Identities
                .FromSqlInterpolated(
                    $"SELECT * FROM identities WHERE id = {identityId} AND realm_id = {realmId} FOR UPDATE")
                .AsNoTracking()
                .SingleOrDefaultAsync(cancellationToken);
            var session = identity is null
                ? null
                : await dbContext.IdentitySessions
                    .FromSqlInterpolated(
                        $"SELECT * FROM identity_sessions WHERE id = {sessionId} FOR UPDATE")
                    .AsNoTracking()
                    .SingleOrDefaultAsync(cancellationToken);
            var authenticated = identity is not null
                && identity.LifecycleState == IdentityLifecycleState.Active
                && session is not null
                && session.IdentityId == identityId
                && session.AppEnvironmentId == appEnvironmentId
                && session.Purpose == IdentitySessionPurpose.Product
                && session.RevokedAt is null
                && session.ExpiresAt > now;
            if (!authenticated)
            {
                await transaction.RollbackAsync(cancellationToken);
                return CurrentIdentityMutationStatus.IdentityNotFound;
            }

            // Verification evidence belongs to the old address and cannot be inherited
            // by a replacement value, even when the environment permits unverified e-mail.
            var updated = await dbContext.IdentityIdentifiers
                .Where(identifier => identifier.RealmId == realmId
                    && identifier.IdentityId == identityId
                    && identifier.Scheme == IdentifierScheme.Email)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(
                            identifier => identifier.NormalizedValue,
                            normalizedEmail)
                        .SetProperty(
                            identifier => identifier.VerifiedAt,
                            (DateTimeOffset?)null)
                        .SetProperty(
                            identifier => identifier.VerificationMethod,
                            (string?)null),
                    cancellationToken);
            if (updated != 1)
            {
                await transaction.RollbackAsync(cancellationToken);
                return CurrentIdentityMutationStatus.IdentityNotFound;
            }

            // Invalidate every outstanding password-recovery path created from the
            // earlier identity snapshot. This includes e-mail reset tokens and phone
            // challenges; neither may change the password after the account mutation.
            await dbContext.PasswordResetTokens
                .Where(token => token.IdentityId == identityId
                    && token.UsedAt == null
                    && token.ExpiresAt > now)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(token => token.UsedAt, now),
                    cancellationToken);
            await dbContext.PhonePasswordResetChallenges
                .Where(challenge => challenge.IdentityId == identityId
                    && (challenge.Status
                            == PhonePasswordResetChallengeStatus.PendingDelivery
                        || challenge.Status
                            == PhonePasswordResetChallengeStatus.Active
                        || challenge.Status
                            == PhonePasswordResetChallengeStatus.Confirming))
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(
                            challenge => challenge.Status,
                            PhonePasswordResetChallengeStatus.Superseded)
                        .SetProperty(challenge => challenge.CompletedAt, now),
                    cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            return CurrentIdentityMutationStatus.Updated;
        }
        // The preliminary service lookup cannot prevent another identity from claiming
        // the value concurrently. PostgreSQL uniqueness is the final ownership authority.
        catch (DbUpdateException exception)
            when (exception.InnerException is PostgresException
            {
                SqlState: PostgresErrorCodes.UniqueViolation,
                ConstraintName: IdentifierUniqueConstraint,
            })
        {
            return CurrentIdentityMutationStatus.EmailTaken;
        }
        catch (PostgresException exception)
            when (exception.SqlState == PostgresErrorCodes.UniqueViolation
                && exception.ConstraintName == IdentifierUniqueConstraint)
        {
            return CurrentIdentityMutationStatus.EmailTaken;
        }
    }

    /// <inheritdoc />
    public async Task<bool> TryDeleteAsync(
        Guid realmId,
        Guid appEnvironmentId,
        byte[] sessionTokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Discard earlier tracked snapshots before locking the bearer-selected session;
        // deletion authorization must use state read inside this transaction. In
        // particular, a service-side lookup performed before this transaction would be
        // stale if another request revoked the session or changed identity lifecycle.
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var session = await dbContext.IdentitySessions
            .FromSqlInterpolated(
                $"SELECT * FROM identity_sessions WHERE app_environment_id = {appEnvironmentId} AND token_hash = {sessionTokenHash} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        // The raw session token selects only the session. Realm ownership is established
        // by locking the associated identity with the authenticated integration scope.
        var identity = session is null
            ? null
            : await dbContext.Identities
                .FromSqlInterpolated(
                    $"SELECT * FROM identities WHERE id = {session.IdentityId} AND realm_id = {realmId} FOR UPDATE")
                .AsNoTracking()
                .SingleOrDefaultAsync(cancellationToken);
        if (identity?.LifecycleState != IdentityLifecycleState.Active
            || session is null
            || session.Purpose != IdentitySessionPurpose.Product
            || session.RevokedAt is not null
            || session.ExpiresAt <= now)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        var affectedFlowIds = await dbContext.AccessFlowDataSubjects.AsNoTracking()
            .Where(subject => subject.RealmId == realmId
                && subject.IdentityId == identity.Id)
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
            .Where(item => item.Id == identity.Id && item.RealmId == realmId)
            .ExecuteDeleteAsync(cancellationToken);

        // No success is observable until both flow erasure and identity erasure share
        // this commit. An exception or cancellation before commit leaves neither half
        // intentionally applied.
        await transaction.CommitAsync(cancellationToken);
        return deleted == 1;
    }

}
