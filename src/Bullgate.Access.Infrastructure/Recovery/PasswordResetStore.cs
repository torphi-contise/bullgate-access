using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Recovery;

/// <summary>
/// Issues, invalidates, and atomically consumes e-mail password-reset tokens.
/// </summary>
/// <remarks>
/// Token state, identity eligibility, password replacement, session revocation, and
/// invalidation of sibling tokens are coordinated here to prevent replay after a
/// successful reset.
/// </remarks>
internal sealed class PasswordResetStore(AccessDbContext dbContext)
    : IPasswordResetStore
{
    /// <inheritdoc />
    public async Task<PasswordResetIssueStoreResult> TryIssueAsync(
        PasswordResetToken token,
        string? expectedNormalizedEmail,
        PasswordResetIssueConstraint? issueConstraint,
        CancellationToken cancellationToken)
    {
        // The identity lock makes the issue limit deterministic when several requests
        // arrive together; a count followed by an unlocked insert would be bypassable.
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var identity = await LockIdentityAsync(token.IdentityId, cancellationToken);
        if (identity is null
            || identity.LifecycleState != IdentityLifecycleState.Active
            || !await IsEligibleEnvironmentAsync(
                token.AppEnvironmentId,
                identity.RealmId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return PasswordResetIssueStoreResult.IdentityIneligible;
        }

        if (expectedNormalizedEmail is not null
            && !await HasExpectedEmailAsync(
                identity.RealmId,
                identity.Id,
                expectedNormalizedEmail,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return PasswordResetIssueStoreResult.IdentityIneligible;
        }

        if (issueConstraint is not null)
        {
            var recentIssues = await dbContext.PasswordResetTokens.CountAsync(
                existing =>
                    existing.IdentityId == token.IdentityId
                    && existing.CreatedAt >= issueConstraint.IssuedSince,
                cancellationToken);
            if (recentIssues >= issueConstraint.MaximumIssues)
            {
                await transaction.RollbackAsync(cancellationToken);
                return PasswordResetIssueStoreResult.RateLimited;
            }
        }

        dbContext.PasswordResetTokens.Add(token);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return PasswordResetIssueStoreResult.Issued;
    }

    /// <inheritdoc />
    public async Task<bool> TryInvalidateAsync(
        Guid tokenId,
        DateTimeOffset invalidatedAt,
        CancellationToken cancellationToken)
    {
        // UsedAt records that authority ended, not whether a reset succeeded. Restrict
        // the update to active rows so retries are no-ops and the database constraint
        // used_at < expires_at remains true; an expired token is already unusable.
        var invalidated = await dbContext.PasswordResetTokens
            .Where(token => token.Id == tokenId
                && token.UsedAt == null
                && token.ExpiresAt > invalidatedAt)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(token => token.UsedAt, invalidatedAt),
                cancellationToken);
        return invalidated == 1;
    }

    /// <inheritdoc />
    public Task<PasswordResetEmailCandidate?> FindByEmailAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string normalizedEmail,
        CancellationToken cancellationToken) =>
        QueryCandidates(realmId, appEnvironmentId, normalizedEmail: normalizedEmail)
            .SingleOrDefaultAsync(cancellationToken);

    /// <inheritdoc />
    public Task<PasswordResetEmailCandidate?> FindByIdentityAsync(
        Guid realmId,
        Guid appEnvironmentId,
        Guid identityId,
        CancellationToken cancellationToken) =>
        QueryCandidates(realmId, appEnvironmentId, identityId: identityId)
            .SingleOrDefaultAsync(cancellationToken);

    // The e-mail and identity filters must stay inside the query, before the
    // projection: EF Core cannot translate a predicate over a positional record
    // built in the select (new PasswordResetEmailCandidate(...).Email == x).
    private IQueryable<PasswordResetEmailCandidate> QueryCandidates(
        Guid realmId,
        Guid appEnvironmentId,
        Guid? identityId = null,
        string? normalizedEmail = null) =>
        from identifier in dbContext.IdentityIdentifiers.AsNoTracking()
        join identity in dbContext.Identities.AsNoTracking()
            on identifier.IdentityId equals identity.Id
        join environment in dbContext.AppEnvironments.AsNoTracking()
            on appEnvironmentId equals environment.Id
        join app in dbContext.Apps.AsNoTracking()
            on environment.AppId equals app.Id
        where identifier.RealmId == realmId
            && identifier.Scheme == IdentifierScheme.Email
            && (normalizedEmail == null || identifier.NormalizedValue == normalizedEmail)
            && identity.RealmId == realmId
            && identity.LifecycleState == IdentityLifecycleState.Active
            && (identityId == null || identity.Id == identityId)
            && environment.RealmId == realmId
            && environment.IsActive
            && environment.EmailIdentifierEnabled
            && environment.PasswordAuthenticatorEnabled
            && app.IsActive
        select new PasswordResetEmailCandidate(
            identity.Id,
            identifier.NormalizedValue,
            app.Name,
            environment.PasswordRecoveryUrl);

    /// <inheritdoc />
    public Task<bool> IsActiveAsync(
        Guid appEnvironmentId,
        byte[] tokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        (
            from token in dbContext.PasswordResetTokens.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on token.IdentityId equals identity.Id
            join environment in dbContext.AppEnvironments.AsNoTracking()
                on token.AppEnvironmentId equals environment.Id
            where token.AppEnvironmentId == appEnvironmentId
                && token.TokenHash.SequenceEqual(tokenHash)
                && token.UsedAt == null
                && token.ExpiresAt > now
                && identity.LifecycleState == IdentityLifecycleState.Active
                && environment.RealmId == identity.RealmId
                && environment.IsActive
                && environment.PasswordAuthenticatorEnabled
            select token.Id
        ).AnyAsync(cancellationToken);

    /// <inheritdoc />
    public async Task<Guid?> TryResetPasswordAsync(
        Guid appEnvironmentId,
        byte[] tokenHash,
        string passwordHash,
        DateTimeOffset resetAt,
        CancellationToken cancellationToken)
    {
        var candidate = await dbContext.PasswordResetTokens
            .AsNoTracking()
            .Where(token =>
                token.AppEnvironmentId == appEnvironmentId
                && token.TokenHash.SequenceEqual(tokenHash))
            .Select(token => new { token.Id, token.IdentityId })
            .SingleOrDefaultAsync(cancellationToken);
        if (candidate is null)
        {
            return null;
        }

        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        // Re-check the candidate under locks. The earlier hash lookup is intentionally
        // not authority because another request may consume or invalidate the token.
        var identity = await LockIdentityAsync(candidate.IdentityId, cancellationToken);
        if (identity is null
            || identity.LifecycleState != IdentityLifecycleState.Active
            || !await IsEligibleEnvironmentAsync(
                appEnvironmentId,
                identity.RealmId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var token = await dbContext.PasswordResetTokens
            .FromSqlInterpolated(
                $"SELECT * FROM password_reset_tokens WHERE id = {candidate.Id} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (token is null || !token.IsActive(resetAt))
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var credential = await dbContext.PasswordCredentials.SingleOrDefaultAsync(
            item => item.IdentityId == identity.Id,
            cancellationToken);
        if (credential is null)
        {
            dbContext.PasswordCredentials.Add(
                new PasswordCredential(identity.Id, passwordHash, resetAt));
        }
        else
        {
            credential.Replace(passwordHash, resetAt);
        }

        token.MarkUsed(resetAt);
        await dbContext.SaveChangesAsync(cancellationToken);

        await dbContext.IdentitySessions
            .Where(session =>
                session.IdentityId == identity.Id
                && session.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    session => session.RevokedAt,
                    resetAt),
                cancellationToken);
        // Consuming one reset revokes every remaining reset path for the identity so
        // possession of an older message cannot overwrite the new password.
        await dbContext.PasswordResetTokens
            .Where(other =>
                other.IdentityId == identity.Id
                && other.UsedAt == null
                && other.ExpiresAt > resetAt)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    other => other.UsedAt,
                    resetAt),
                cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return identity.Id;
    }

    private Task<Identity?> LockIdentityAsync(
        Guid identityId,
        CancellationToken cancellationToken) =>
        dbContext.Identities
            .FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {identityId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);

    private Task<bool> IsEligibleEnvironmentAsync(
        Guid appEnvironmentId,
        Guid realmId,
        CancellationToken cancellationToken) =>
        dbContext.AppEnvironments.AnyAsync(
            environment =>
                environment.Id == appEnvironmentId
                && environment.RealmId == realmId
                && environment.IsActive
                && environment.PasswordAuthenticatorEnabled,
            cancellationToken);

    private Task<bool> HasExpectedEmailAsync(
        Guid realmId,
        Guid identityId,
        string expectedNormalizedEmail,
        CancellationToken cancellationToken) =>
        dbContext.IdentityIdentifiers.AnyAsync(
            identifier => identifier.RealmId == realmId
                && identifier.IdentityId == identityId
                && identifier.Scheme == IdentifierScheme.Email
                && identifier.NormalizedValue == expectedNormalizedEmail,
            cancellationToken);
}
