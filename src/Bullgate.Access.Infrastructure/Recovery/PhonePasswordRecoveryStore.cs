using System.Security.Cryptography;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Recovery;

/// <summary>
/// Coordinates phone recovery challenge reservation, delivery state, confirmation,
/// password replacement, and invalidation of competing recovery paths.
/// </summary>
/// <remarks>
/// Provider delivery cannot participate in the database transaction. The store uses
/// explicit reservation and finalization states so retries have durable meaning and
/// an OTP cannot be consumed twice.
/// </remarks>
internal sealed class PhonePasswordRecoveryStore(AccessDbContext dbContext)
    : IPhonePasswordRecoveryStore
{
    /// <inheritdoc />
    public Task<PhonePasswordRecoveryApplicationClient?> FindApplicationClientAsync(
        Guid appEnvironmentId,
        string applicationClientKey,
        CancellationToken cancellationToken) =>
        dbContext.ApplicationClients.AsNoTracking()
            .Where(client => client.Key == applicationClientKey
                && client.AppEnvironmentId == appEnvironmentId
                && client.IsActive)
            .Select(client => new PhonePasswordRecoveryApplicationClient(
                client.Id,
                client.Key,
                client.SmsRetrieverAppHash))
            .SingleOrDefaultAsync(cancellationToken);

    /// <inheritdoc />
    public Task<PhonePasswordRecoveryCandidate?> FindCandidateAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string normalizedPhone,
        CancellationToken cancellationToken) =>
        // This query deliberately joins current topology and verified ownership rather
        // than treating a matching phone row as authority. TryReserveAsync repeats the
        // checks under the identity lock because this read can become stale.
        (
            from identifier in dbContext.IdentityIdentifiers.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on identifier.IdentityId equals identity.Id
            join environment in dbContext.AppEnvironments.AsNoTracking()
                on appEnvironmentId equals environment.Id
            join app in dbContext.Apps.AsNoTracking()
                on environment.AppId equals app.Id
            where identifier.RealmId == realmId
                && identifier.Scheme == IdentifierScheme.Phone
                && identifier.NormalizedValue == normalizedPhone
                && identifier.VerifiedAt != null
                && identity.RealmId == realmId
                && identity.LifecycleState == IdentityLifecycleState.Active
                && environment.RealmId == realmId
                && environment.IsActive
                && environment.PhoneIdentifierEnabled
                && environment.PhoneVerificationEnabled
                && environment.PasswordAuthenticatorEnabled
                && app.IsActive
            select new PhonePasswordRecoveryCandidate(identity.Id)
        ).SingleOrDefaultAsync(cancellationToken);

    /// <inheritdoc />
    public async Task<PhonePasswordRecoveryReservation> TryReserveAsync(
        Guid realmId,
        PhonePasswordResetChallenge challenge,
        DateTimeOffset rateWindowStartsAt,
        int maximumRequests,
        DateTimeOffset reservedAt,
        CancellationToken cancellationToken)
    {
        // Drop any entity snapshot left by an earlier operation before FOR UPDATE reads;
        // transaction-critical decisions must use the state protected by these locks.
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        // The identity row is the per-person concurrency coordinator. Every recovery
        // transition locks it before a challenge, keeping lock order deterministic and
        // serializing rate, cooldown, ownership, and open-challenge decisions.
        var identity = await LockIdentityAsync(
            challenge.IdentityId,
            cancellationToken);
        if (identity is null
            || identity.RealmId != realmId
            || identity.LifecycleState != IdentityLifecycleState.Active
            || !await IsEnvironmentEligibleAsync(
                challenge.AppEnvironmentId,
                realmId,
                cancellationToken)
            || !await IsVerifiedPhoneOwnerAsync(
                realmId,
                challenge.IdentityId,
                challenge.Phone,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return new PhonePasswordRecoveryReservation(
                PhonePasswordRecoveryReservationStatus.IdentityIneligible);
        }

        // Count every durable request, including terminal attempts. Provider failure or
        // challenge replacement must not let repeated requests bypass the hourly limit.
        var recent = await dbContext.PhonePasswordResetChallenges.CountAsync(
            existing => existing.IdentityId == challenge.IdentityId
                && existing.CreatedAt >= rateWindowStartsAt,
            cancellationToken);
        if (recent >= maximumRequests)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new PhonePasswordRecoveryReservation(
                PhonePasswordRecoveryReservationStatus.RateLimited);
        }

        var latestResendAvailableAt = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .Where(existing => existing.IdentityId == challenge.IdentityId)
            .OrderByDescending(existing => existing.CreatedAt)
            .Select(existing => (DateTimeOffset?)existing.ResendAvailableAt)
            .FirstOrDefaultAsync(cancellationToken);
        // Cooldown follows the latest reserved request, not merely the latest currently
        // active challenge, so superseding or failing a request cannot erase the delay.
        if (latestResendAvailableAt > reservedAt)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new PhonePasswordRecoveryReservation(
                PhonePasswordRecoveryReservationStatus.ResendTooSoon);
        }

        var open = await dbContext.PhonePasswordResetChallenges
            .Where(existing => existing.IdentityId == challenge.IdentityId
                && existing.AppEnvironmentId == challenge.AppEnvironmentId
                && (existing.Status == PhonePasswordResetChallengeStatus.PendingDelivery
                    || existing.Status == PhonePasswordResetChallengeStatus.Active
                    || existing.Status == PhonePasswordResetChallengeStatus.Confirming))
            .SingleOrDefaultAsync(cancellationToken);
        if (open is not null)
        {
            // A confirmer may already have passed the local OTP check and be awaiting a
            // provider decision. Do not replace that exclusive reservation while valid.
            if (open.Status == PhonePasswordResetChallengeStatus.Confirming
                && open.ExpiresAt > reservedAt)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new PhonePasswordRecoveryReservation(
                    PhonePasswordRecoveryReservationStatus.ResendTooSoon);
            }
        }

        PhonePasswordRecoverySupersededChallenge? superseded = null;
        if (open is not null)
        {
            // Supersede before inserting so the partial unique index continues to allow
            // only one pending, active, or confirming challenge in this scope.
            open.Supersede(reservedAt);
            superseded = new PhonePasswordRecoverySupersededChallenge(
                open.Id,
                open.ProviderReference,
                open.ProviderApprovedAt);
        }

        dbContext.PhonePasswordResetChallenges.Add(challenge);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new PhonePasswordRecoveryReservation(
            PhonePasswordRecoveryReservationStatus.Reserved,
            superseded);
    }

    /// <inheritdoc />
    public async Task<bool> TryRollbackReservationAsync(
        Guid challengeId,
        Guid? supersededChallengeId,
        DateTimeOffset rolledBackAt,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        var identityId = await FindChallengeIdentityIdAsync(
            challengeId,
            cancellationToken);
        if (identityId is null)
        {
            return false;
        }

        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await LockIdentityAsync(identityId.Value, cancellationToken) is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        var reservation = await LockChallengeAsync(challengeId, cancellationToken);
        if (reservation is null
            || reservation.Status != PhonePasswordResetChallengeStatus.PendingDelivery)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        dbContext.PhonePasswordResetChallenges.Remove(reservation);
        await dbContext.SaveChangesAsync(cancellationToken);

        if (supersededChallengeId is not null)
        {
            var previous = await LockChallengeAsync(
                supersededChallengeId.Value,
                cancellationToken);
            // Compensation is bounded to an unexpired provider-backed predecessor that
            // the caller could have canceled. Do not infer recoverability for a row with
            // no external reference or return an expired challenge to Active.
            if (previous is
                {
                    Status: PhonePasswordResetChallengeStatus.Superseded,
                    ProviderReference: not null,
                }
                && previous.ExpiresAt > rolledBackAt)
            {
                previous.RestoreActive();
                await dbContext.SaveChangesAsync(cancellationToken);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> TryActivateAsync(
        Guid challengeId,
        string? providerReference,
        DateTimeOffset activatedAt,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        var identityId = await FindChallengeIdentityIdAsync(
            challengeId,
            cancellationToken);
        if (identityId is null)
        {
            return false;
        }

        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await LockIdentityAsync(identityId.Value, cancellationToken) is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        var challenge = await LockChallengeAsync(challengeId, cancellationToken);
        if (challenge is null
            || challenge.Status != PhonePasswordResetChallengeStatus.PendingDelivery)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }
        // Delivery that finishes after expiry cannot make an already-dead OTP usable.
        // Persist the terminal failure so a retry cannot reactivate this reservation.
        if (challenge.ExpiresAt <= activatedAt)
        {
            challenge.FailDelivery(activatedAt);
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return false;
        }

        challenge.Activate(providerReference);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task FailDeliveryAsync(
        Guid challengeId,
        DateTimeOffset failedAt,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        var identityId = await FindChallengeIdentityIdAsync(
            challengeId,
            cancellationToken);
        if (identityId is null)
        {
            return;
        }

        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await LockIdentityAsync(identityId.Value, cancellationToken) is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return;
        }

        var challenge = await LockChallengeAsync(challengeId, cancellationToken);
        if (challenge?.Status != PhonePasswordResetChallengeStatus.PendingDelivery)
        {
            await transaction.RollbackAsync(cancellationToken);
            return;
        }

        challenge.FailDelivery(failedAt);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<PhonePasswordRecoveryCodeCheck> TryBeginConfirmationAsync(
        Guid realmId,
        Guid appEnvironmentId,
        string normalizedPhone,
        byte[] codeHash,
        DateTimeOffset attemptedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(codeHash);
        if (codeHash.Length != IdentityLimits.PhonePasswordResetCodeHashLength)
        {
            throw new ArgumentException("Code hash has an invalid length.", nameof(codeHash));
        }

        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        // The unlocked lookup selects a likely row only. Identity and challenge locks
        // below establish authority and every relevant field is checked again.
        var candidate = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .Where(challenge => challenge.AppEnvironmentId == appEnvironmentId
                && challenge.Phone == normalizedPhone
                && challenge.Status == PhonePasswordResetChallengeStatus.Active
                && challenge.ExpiresAt > attemptedAt)
            .OrderByDescending(challenge => challenge.CreatedAt)
            .Select(challenge => new
            {
                challenge.Id,
                challenge.IdentityId,
            })
            .FirstOrDefaultAsync(cancellationToken);
        if (candidate is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new PhonePasswordRecoveryCodeCheck(
                PhonePasswordRecoveryCodeCheckStatus.InvalidCode);
        }

        var identity = await LockIdentityAsync(
            candidate.IdentityId,
            cancellationToken);
        if (identity is null
            || identity.RealmId != realmId
            || identity.LifecycleState != IdentityLifecycleState.Active)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new PhonePasswordRecoveryCodeCheck(
                PhonePasswordRecoveryCodeCheckStatus.InvalidCode);
        }

        var challenge = await LockChallengeAsync(
            candidate.Id,
            cancellationToken);
        if (challenge is null
            || challenge.IdentityId != identity.Id
            || challenge.AppEnvironmentId != appEnvironmentId
            || challenge.Phone != normalizedPhone
            || !challenge.IsActive(attemptedAt))
        {
            await transaction.RollbackAsync(cancellationToken);
            return new PhonePasswordRecoveryCodeCheck(
                PhonePasswordRecoveryCodeCheckStatus.InvalidCode);
        }

        if (!await IsEnvironmentEligibleAsync(
                appEnvironmentId,
                realmId,
                cancellationToken)
            || !await IsVerifiedPhoneOwnerAsync(
                realmId,
                challenge.IdentityId,
                normalizedPhone,
                cancellationToken))
        {
            // Eligibility or phone ownership disappeared after delivery. Make the
            // challenge terminal and cancel only provider work that was not approved.
            challenge.Supersede(attemptedAt);
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new PhonePasswordRecoveryCodeCheck(
                PhonePasswordRecoveryCodeCheckStatus.InvalidCode,
                challenge.Id,
                ProviderReference: challenge.ProviderReference,
                CancelProvider: challenge.ProviderApprovedAt is null
                    && challenge.ProviderReference is not null);
        }

        if (!CryptographicOperations.FixedTimeEquals(challenge.CodeHash, codeHash))
        {
            // Fixed-time comparison avoids making partial hash similarity observable.
            // Provider cancellation becomes eligible only when the final attempt makes
            // the locally stored challenge terminal.
            var exhausted = challenge.RecordFailure(attemptedAt);
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new PhonePasswordRecoveryCodeCheck(
                PhonePasswordRecoveryCodeCheckStatus.InvalidCode,
                challenge.Id,
                ProviderReference: challenge.ProviderReference,
                CancelProvider: exhausted
                    && challenge.ProviderApprovedAt is null
                    && challenge.ProviderReference is not null);
        }

        // Confirming is an exclusive reservation: provider approval happens outside the
        // transaction, so another request must not consume the same local proof meanwhile.
        challenge.BeginConfirmation(attemptedAt);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new PhonePasswordRecoveryCodeCheck(
            PhonePasswordRecoveryCodeCheckStatus.Ready,
            challenge.Id,
            challenge.IdentityId,
            challenge.ProviderReference,
            challenge.ProviderApprovedAt);
    }

    /// <inheritdoc />
    public async Task<bool> TryReleaseConfirmationAsync(
        Guid challengeId,
        DateTimeOffset releasedAt,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        var identityId = await FindChallengeIdentityIdAsync(
            challengeId,
            cancellationToken);
        if (identityId is null)
        {
            return false;
        }

        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await LockIdentityAsync(identityId.Value, cancellationToken) is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        var challenge = await LockChallengeAsync(challengeId, cancellationToken);
        if (challenge?.Status != PhonePasswordResetChallengeStatus.Confirming)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        if (challenge.ExpiresAt <= releasedAt)
        {
            // A provider failure may release a still-valid confirmation for retry, but
            // expiry is terminal and must not return the challenge to Active.
            challenge.Supersede(releasedAt);
        }
        else
        {
            challenge.ReleaseConfirmation(releasedAt);
        }
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> TryFinalizeAsync(
        Guid challengeId,
        PasswordResetToken resetToken,
        DateTimeOffset providerApprovedAt,
        DateTimeOffset completedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resetToken);
        dbContext.ChangeTracker.Clear();

        var challengeIdentityId = await FindChallengeIdentityIdAsync(
            challengeId,
            cancellationToken);
        // Bind newly issued reset authority to the challenge owner before taking locks;
        // the locked checks below remain authoritative against concurrent state changes.
        if (challengeIdentityId != resetToken.IdentityId)
        {
            return false;
        }

        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var identity = await LockIdentityAsync(
            challengeIdentityId.Value,
            cancellationToken);
        if (identity is null
            || identity.LifecycleState != IdentityLifecycleState.Active)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        var challenge = await LockChallengeAsync(challengeId, cancellationToken);
        if (challenge is null
            || challenge.Status != PhonePasswordResetChallengeStatus.Confirming
            || challenge.IdentityId != resetToken.IdentityId
            || challenge.AppEnvironmentId != resetToken.AppEnvironmentId
            || !await IsEnvironmentEligibleAsync(
                challenge.AppEnvironmentId,
                identity.RealmId,
                cancellationToken)
            || !await IsVerifiedPhoneOwnerAsync(
                identity.RealmId,
                identity.Id,
                challenge.Phone,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        // Provider approval, challenge completion, and reset-token persistence form one
        // local commit. A completed challenge must never exist without its reset path.
        challenge.MarkProviderApproved(providerApprovedAt);
        challenge.Complete(completedAt);
        dbContext.PasswordResetTokens.Add(resetToken);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    private Task<Guid?> FindChallengeIdentityIdAsync(
        Guid challengeId,
        CancellationToken cancellationToken) =>
        dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .Where(challenge => challenge.Id == challengeId)
            .Select(challenge => (Guid?)challenge.IdentityId)
            .SingleOrDefaultAsync(cancellationToken);

    private Task<Identity?> LockIdentityAsync(
        Guid identityId,
        CancellationToken cancellationToken) =>
        dbContext.Identities
            .FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {identityId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);

    private Task<PhonePasswordResetChallenge?> LockChallengeAsync(
        Guid challengeId,
        CancellationToken cancellationToken) =>
        dbContext.PhonePasswordResetChallenges
            .FromSqlInterpolated(
                $"SELECT * FROM phone_password_reset_challenges WHERE id = {challengeId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);

    private Task<bool> IsVerifiedPhoneOwnerAsync(
        Guid realmId,
        Guid identityId,
        string normalizedPhone,
        CancellationToken cancellationToken) =>
        (
            from identifier in dbContext.IdentityIdentifiers
            join identity in dbContext.Identities
                on identifier.IdentityId equals identity.Id
            where identifier.RealmId == realmId
                && identifier.IdentityId == identityId
                && identifier.Scheme == IdentifierScheme.Phone
                && identifier.NormalizedValue == normalizedPhone
                && identifier.VerifiedAt != null
                && identity.RealmId == realmId
                && identity.LifecycleState == IdentityLifecycleState.Active
            select identifier.Id
        ).AnyAsync(cancellationToken);

    private Task<bool> IsEnvironmentEligibleAsync(
        Guid appEnvironmentId,
        Guid realmId,
        CancellationToken cancellationToken) =>
        (
            from environment in dbContext.AppEnvironments
            join app in dbContext.Apps on environment.AppId equals app.Id
            where environment.Id == appEnvironmentId
                && environment.RealmId == realmId
                && environment.IsActive
                && environment.PhoneIdentifierEnabled
                && environment.PhoneVerificationEnabled
                && environment.PhoneVerificationProvider == VerificationProviderKey.TwilioVerify
                && environment.PasswordAuthenticatorEnabled
                && app.IsActive
            select environment.Id
        ).AnyAsync(cancellationToken);
}
