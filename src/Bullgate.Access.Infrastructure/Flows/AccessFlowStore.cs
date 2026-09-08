using System.Security.Cryptography;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace Bullgate.Access.Infrastructure.Flows;

/// <summary>
/// Persists flow revisions, idempotent requests, proof challenges, and session
/// issuance while enforcing the transaction boundaries of the AccessFlow protocol.
/// </summary>
/// <remarks>
/// This store deliberately converts PostgreSQL locks and named uniqueness constraints
/// into protocol outcomes. Those checks are part of the concurrency contract, not
/// incidental persistence details.
/// </remarks>
internal sealed class AccessFlowStore(AccessDbContext dbContext) : IAccessFlowStore
{
    private const string RequestPrimaryKey = "pk_access_flow_requests";
    private const string ActiveSourceIntentUniqueConstraint =
        "ux_access_flows_active_source_session_intent";
    private const string PendingExternalRequestUniqueConstraint =
        "ux_access_flow_requests_pending_external_flow";
    private const string PendingDeliveryChallengeUniqueConstraint =
        "ux_proof_challenges_pending_delivery_flow_type";
    private const string ConfirmingChallengeUniqueConstraint =
        "ux_proof_challenges_confirming_flow_type";
    private const string IdentifierValueUniqueConstraint =
        "ux_identity_identifiers_realm_scheme_value";
    private const string IdentitySchemeUniqueConstraint =
        "ux_identity_identifiers_realm_identity_scheme";
    private const string SessionTokenUniqueConstraint = "ux_identity_sessions_token_hash";

    // A reservation without a proof challenge (an e-mail being sent) has nothing that
    // carries an expiry, so it stays alive for this window and is then reclaimed.
    private static readonly TimeSpan RequestOnlyReservationLifetime = TimeSpan.FromMinutes(1);

    public async Task<StoredAccessFlowRequest?> FindRequestAsync(
        Guid integrationClientId,
        Guid requestId,
        CancellationToken cancellationToken)
    {
        var stored = await (
            from request in dbContext.AccessFlowRequests.AsNoTracking()
            join flow in dbContext.AccessFlows.AsNoTracking()
                on request.FlowId equals flow.Id
            join currentRevision in dbContext.AccessFlowRevisions.AsNoTracking()
                on new { FlowId = flow.Id, Revision = flow.CurrentRevision }
                equals new
                {
                    currentRevision.FlowId,
                    Revision = currentRevision.Revision,
                }
            where request.IntegrationClientId == integrationClientId
                && request.RequestId == requestId
            select new
            {
                request.PayloadHash,
                request.Status,
                request.ResultRevision,
                request.IssuedSessionId,
                Flow = new StoredAccessFlow(
                    flow.Id,
                    flow.IdentityId,
                    flow.RegistrationContextId,
                    flow.SourceSessionId,
                    flow.ApplicationClientId,
                    flow.Status,
                    flow.ProtocolVersion,
                    flow.Intent,
                    flow.CurrentRevision,
                    flow.ExpiresAt,
                    currentRevision.SnapshotJson),
            }).SingleOrDefaultAsync(cancellationToken);

        if (stored is null)
        {
            return null;
        }

        // The flow projection carries the latest revision for current state, while an
        // already committed request must replay the immutable revision it originally
        // produced. Never substitute the newer snapshot for ResultRevision.
        string? snapshotJson = null;
        if (stored.ResultRevision is not null)
        {
            snapshotJson = await dbContext.AccessFlowRevisions.AsNoTracking()
                .Where(revision => revision.FlowId == stored.Flow.FlowId
                    && revision.Revision == stored.ResultRevision.Value)
                .Select(revision => revision.SnapshotJson)
                .SingleAsync(cancellationToken);
        }

        StoredAccessFlowIssuedSession? issuedSession = null;
        if (stored.IssuedSessionId is not null)
        {
            // Persistent replay stores only the issued session hash and scope facts.
            // Clear terminal session material is deterministically derived elsewhere.
            issuedSession = await (
                from session in dbContext.IdentitySessions.AsNoTracking()
                where session.Id == stored.IssuedSessionId.Value
                select new StoredAccessFlowIssuedSession(
                    session.IdentityId,
                    session.Id,
                    session.TokenHash,
                    session.ExpiresAt,
                    session.Purpose)
            ).SingleAsync(cancellationToken);
        }

        return new StoredAccessFlowRequest(
            stored.PayloadHash,
            stored.Status,
            stored.Flow,
            snapshotJson,
            issuedSession);
    }

    public Task<ContinueRegistrationCandidate?> FindContinueRegistrationCandidateAsync(
        AccessFlowScope scope,
        byte[] sessionTokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        // This narrows normal service behavior but does not reserve the source session.
        // TryCreateAsync repeats every eligibility check after acquiring locks.
        (
            from session in dbContext.IdentitySessions.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on session.IdentityId equals identity.Id
            join context in dbContext.RegistrationContexts.AsNoTracking()
                on new
                {
                    session.AppEnvironmentId,
                    session.IdentityId,
                }
                equals new
                {
                    context.AppEnvironmentId,
                    context.IdentityId,
                }
            where session.AppEnvironmentId == scope.AppEnvironmentId
                && session.TokenHash.SequenceEqual(sessionTokenHash)
                && session.Purpose == IdentitySessionPurpose.Registration
                && session.RevokedAt == null
                && session.ExpiresAt > now
                && identity.RealmId == scope.RealmId
                && identity.LifecycleState == IdentityLifecycleState.Active
                && context.Status == RegistrationContextStatus.Open
            select new ContinueRegistrationCandidate(
                identity.Id,
                context.Id,
                session.Id)
        ).SingleOrDefaultAsync(cancellationToken);

    public Task<ManagePhoneCandidate?> FindManagePhoneCandidateAsync(
        AccessFlowScope scope,
        byte[] sessionTokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        // Product purpose is part of candidate selection because a registration session
        // must never authorize management of an existing product identity.
        (
            from session in dbContext.IdentitySessions.AsNoTracking()
            join identity in dbContext.Identities.AsNoTracking()
                on session.IdentityId equals identity.Id
            where session.AppEnvironmentId == scope.AppEnvironmentId
                && session.TokenHash.SequenceEqual(sessionTokenHash)
                && session.Purpose == IdentitySessionPurpose.Product
                && session.RevokedAt == null
                && session.ExpiresAt > now
                && identity.RealmId == scope.RealmId
                && identity.LifecycleState == IdentityLifecycleState.Active
            select new ManagePhoneCandidate(identity.Id, session.Id)
        ).SingleOrDefaultAsync(cancellationToken);

    public Task<ApplicationClientVerificationMetadata?> FindApplicationClientAsync(
        Guid appEnvironmentId,
        string applicationClientKey,
        CancellationToken cancellationToken) =>
        dbContext.ApplicationClients.AsNoTracking()
            .Where(client => client.Key == applicationClientKey
                && client.AppEnvironmentId == appEnvironmentId
                && client.IsActive)
            .Select(client => new ApplicationClientVerificationMetadata(
                client.Id,
                client.Key,
                client.SmsRetrieverAppHash))
            .SingleOrDefaultAsync(cancellationToken);

    public Task<ApplicationClientVerificationMetadata?> FindApplicationClientAsync(
        Guid appEnvironmentId,
        Guid applicationClientId,
        CancellationToken cancellationToken) =>
        dbContext.ApplicationClients.AsNoTracking()
            .Where(client => client.Id == applicationClientId
                && client.AppEnvironmentId == appEnvironmentId
                && client.IsActive)
            .Select(client => new ApplicationClientVerificationMetadata(
                client.Id,
                client.Key,
                client.SmsRetrieverAppHash))
            .SingleOrDefaultAsync(cancellationToken);

    public async Task<PhoneJourneyState> FindPhoneJourneyAsync(
        Guid flowId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var challenges = await dbContext.ProofChallenges.AsNoTracking()
            .Where(challenge =>
                challenge.AccessFlowId == flowId
                && challenge.Status == ProofChallengeStatus.Active
                && challenge.ExpiresAt > now)
            .Select(challenge => new StoredProofChallenge(
                challenge.Id,
                challenge.Type,
                challenge.DestinationValue,
                challenge.SecretHash,
                challenge.ProviderReference,
                challenge.Attempts,
                challenge.MaxAttempts,
                challenge.ExpiresAt,
                challenge.ResendAvailableAt))
            .ToListAsync(cancellationToken);
        var conflict = await (
            from item in dbContext.PhoneRegistrationConflicts.AsNoTracking()
            join previousIdentity in dbContext.Identities.AsNoTracking()
                on item.PreviousIdentityId equals previousIdentity.Id
            join phone in dbContext.IdentityIdentifiers.AsNoTracking()
                on item.ConflictingPhoneIdentifierId equals phone.Id
            where item.AccessFlowId == flowId
                && item.ExpiresAt > now
                && previousIdentity.LifecycleState == IdentityLifecycleState.Active
                && phone.IdentityId == item.PreviousIdentityId
                && phone.Scheme == IdentifierScheme.Phone
                && phone.VerifiedAt != null
            select new StoredPhoneRegistrationConflict(
                item.PreviousIdentityId,
                item.ConflictingPhoneIdentifierId,
                dbContext.IdentityIdentifiers
                    .Where(identifier =>
                        identifier.IdentityId == item.PreviousIdentityId
                        && identifier.Scheme == IdentifierScheme.Email)
                    .OrderBy(identifier => identifier.CreatedAt)
                    .Select(identifier => (Guid?)identifier.Id)
                    .FirstOrDefault(),
                dbContext.IdentityIdentifiers
                    .Where(identifier =>
                        identifier.IdentityId == item.PreviousIdentityId
                        && identifier.Scheme == IdentifierScheme.Email)
                    .OrderBy(identifier => identifier.CreatedAt)
                    .Select(identifier => identifier.NormalizedValue)
                    .FirstOrDefault(),
                item.FailedEmailAttempts,
                item.EmailResolutionExhaustedAt,
                item.ExpiresAt)
        ).SingleOrDefaultAsync(cancellationToken);

        return new PhoneJourneyState(
            challenges.SingleOrDefault(challenge =>
                challenge.Type == ProofChallengeType.PhonePossession),
            conflict);
    }

    public Task<int> CountRecentChallengesAsync(
        Guid identityId,
        ProofChallengeType type,
        DateTimeOffset since,
        CancellationToken cancellationToken) =>
        // DeliveryFailed means no usable challenge reached the person. Excluding it keeps
        // a provider outage from consuming the AccessFlow per-identity request quota.
        dbContext.ProofChallenges.AsNoTracking().CountAsync(
            challenge => challenge.IdentityId == identityId
                && challenge.Type == type
                && challenge.Status != ProofChallengeStatus.DeliveryFailed
                && challenge.CreatedAt >= since,
            cancellationToken);

    public Task<PhoneIdentifierOwner?> FindPhoneOwnerAsync(
        Guid realmId,
        string normalizedPhone,
        CancellationToken cancellationToken) =>
        // Ownership can change immediately after this read. Transition commands carry
        // the result only as expected state and commit methods re-check it under locks.
        (from identifier in dbContext.IdentityIdentifiers.AsNoTracking()
         join identity in dbContext.Identities.AsNoTracking()
             on identifier.IdentityId equals identity.Id
         where identifier.RealmId == realmId
             && identifier.Scheme == IdentifierScheme.Phone
             && identifier.NormalizedValue == normalizedPhone
             && identity.LifecycleState == IdentityLifecycleState.Active
         select new PhoneIdentifierOwner(
             identifier.Id,
             identifier.IdentityId,
             dbContext.IdentityIdentifiers
                 .Where(email => email.IdentityId == identifier.IdentityId
                     && email.Scheme == IdentifierScheme.Email)
                 .OrderBy(email => email.CreatedAt)
                 .Select(email => email.NormalizedValue)
                 .FirstOrDefault(),
             identifier.VerifiedAt != null))
            .SingleOrDefaultAsync(cancellationToken);

    public Task<Guid?> FindIdentifierOwnerAsync(
        Guid realmId,
        string scheme,
        string normalizedValue,
        CancellationToken cancellationToken) =>
        dbContext.IdentityIdentifiers.AsNoTracking()
            .Where(identifier => identifier.RealmId == realmId
                && identifier.Scheme == scheme
                && identifier.NormalizedValue == normalizedValue)
            .Select(identifier => (Guid?)identifier.IdentityId)
            .SingleOrDefaultAsync(cancellationToken);

    public Task<StoredAccessFlow?> FindActiveFlowBySourceAsync(
        Guid sourceSessionId,
        AccessFlowIntent intent,
        CancellationToken cancellationToken) =>
        // This read supports resume/expiry planning. The partial unique index and
        // TryCreateAsync transaction remain authoritative for active-flow ownership.
        (
            from flow in dbContext.AccessFlows.AsNoTracking()
            join revision in dbContext.AccessFlowRevisions.AsNoTracking()
                on new { FlowId = flow.Id, Revision = flow.CurrentRevision }
                equals new { revision.FlowId, Revision = revision.Revision }
            where flow.SourceSessionId == sourceSessionId
                && flow.Intent == intent
                && flow.Status == AccessFlowStatus.Active
            select new StoredAccessFlow(
                flow.Id,
                flow.IdentityId,
                flow.RegistrationContextId,
                flow.SourceSessionId,
                flow.ApplicationClientId,
                flow.Status,
                flow.ProtocolVersion,
                flow.Intent,
                flow.CurrentRevision,
                flow.ExpiresAt,
                revision.SnapshotJson)
        ).SingleOrDefaultAsync(cancellationToken);

    public async Task<AccessFlowCreateResult> TryCreateAsync(
        AccessFlow flow,
        AccessFlowRevision revision,
        AccessFlowRequest request,
        ExpireActiveAccessFlowCommand? expiredFlow,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken)
    {
        // Discard snapshots accumulated by preliminary reads. Every creation decision
        // below must observe the state protected by this transaction's row locks.
        dbContext.ChangeTracker.Clear();
        // Creation locks every authority used to validate the source. Without the
        // shared transaction, revocation or a parallel flow could win between the
        // eligibility read and the insert (ACCESS-012).
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);

        var identity = await dbContext.Identities
            .FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {flow.IdentityId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        var sourceSession = await dbContext.IdentitySessions
            .FromSqlInterpolated(
                $"SELECT * FROM identity_sessions WHERE id = {flow.SourceSessionId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        var intentName = flow.Intent.ToString();
        var existing = await dbContext.AccessFlows
            .FromSqlInterpolated(
                $"SELECT * FROM access_flows WHERE source_session_id = {flow.SourceSessionId} AND intent = {intentName} AND status = 'Active' FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        var existingRequest = await dbContext.AccessFlowRequests
            .FromSqlInterpolated(
                $"SELECT * FROM access_flow_requests WHERE integration_client_id = {request.IntegrationClientId} AND request_id = {request.RequestId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        if (existingRequest is not null)
        {
            // A request id is scoped to the integration client. Payload equivalence is
            // resolved by the application layer from the previously stored request;
            // this transaction must never create a second effect (ACCESS-010).
            await transaction.RollbackAsync(cancellationToken);
            return new AccessFlowCreateResult(
                AccessFlowCreateStatus.RequestAlreadyExists);
        }

        var expectedPurpose = flow.Intent == AccessFlowIntent.ContinueRegistration
            ? IdentitySessionPurpose.Registration
            : IdentitySessionPurpose.Product;
        var sourceIsActive = identity is not null
            && identity.RealmId == flow.RealmId
            && identity.LifecycleState == IdentityLifecycleState.Active
            && sourceSession is not null
            && sourceSession.IdentityId == flow.IdentityId
            && sourceSession.AppEnvironmentId == flow.AppEnvironmentId
            && sourceSession.Purpose == expectedPurpose
            && sourceSession.RevokedAt is null
            && sourceSession.ExpiresAt > startedAt;
        if (!sourceIsActive)
        {
            // Revalidate under lock even when the caller performed a prior lookup.
            // Session purpose is authority: registration and product sessions cannot
            // be substituted for one another (ACCESS-003).
            await transaction.RollbackAsync(cancellationToken);
            return new AccessFlowCreateResult(
                flow.Intent == AccessFlowIntent.ContinueRegistration
                    ? AccessFlowCreateStatus.RegistrationNotPending
                    : AccessFlowCreateStatus.SourceSessionInactive);
        }

        RegistrationContext? registrationContext = null;
        if (flow.Intent == AccessFlowIntent.ContinueRegistration)
        {
            registrationContext = await dbContext.RegistrationContexts
                .FromSqlInterpolated(
                    $"SELECT * FROM registration_contexts WHERE id = {flow.RegistrationContextId!.Value} FOR UPDATE")
                .AsNoTracking()
                .SingleOrDefaultAsync(cancellationToken);
            if (registrationContext is null
                || registrationContext.IdentityId != flow.IdentityId
                || registrationContext.RealmId != flow.RealmId
                || registrationContext.AppEnvironmentId != flow.AppEnvironmentId
                || registrationContext.Status != RegistrationContextStatus.Open)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new AccessFlowCreateResult(
                    AccessFlowCreateStatus.RegistrationNotPending);
            }
        }

        if (existing is not null)
        {
            // The unique slot is source-session plus intent, but resume also requires
            // the complete identity, realm, environment, protocol, and registration
            // context binding to match. A slot collision never transfers a journey.
            var existingMatchesSource = existing.IdentityId == flow.IdentityId
                && existing.RealmId == flow.RealmId
                && existing.AppEnvironmentId == flow.AppEnvironmentId
                && existing.SourceSessionId == flow.SourceSessionId
                && existing.Intent == flow.Intent
                && existing.ProtocolVersion == flow.ProtocolVersion
                && existing.RegistrationContextId == flow.RegistrationContextId;
            if (!existingMatchesSource)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new AccessFlowCreateResult(
                    flow.Intent == AccessFlowIntent.ContinueRegistration
                        ? AccessFlowCreateStatus.RegistrationNotPending
                        : AccessFlowCreateStatus.SourceSessionInactive);
            }

            if (existing.ExpiresAt <= startedAt)
            {
                var storedExpired = await ToStoredFlowAsync(
                    existing,
                    cancellationToken);
                // Expiry is itself a revisioned transition. Require the caller's exact
                // observed flow and revision before closing it to create a replacement.
                if (expiredFlow is null
                    || expiredFlow.FlowId != existing.Id
                    || expiredFlow.ExpectedRevision != existing.CurrentRevision
                    || expiredFlow.ExpiredAt != startedAt)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return new AccessFlowCreateResult(
                        AccessFlowCreateStatus.ExistingFlowExpired,
                        storedExpired);
                }

                await CloseExternalArtifactsAsync(
                    existing.Id,
                    startedAt,
                    cancellationToken);
                var expiredRevision = existing.Expire(
                    expiredFlow.ExpectedRevision,
                    expiredFlow.ExpiredAt);
                dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
                    existing.Id,
                    expiredRevision,
                    expiredFlow.SnapshotJson,
                    expiredFlow.ExpiredAt));

                // Persist the terminal revision first to release the partial unique
                // active-flow index before inserting the replacement in this transaction.
                await dbContext.SaveChangesAsync(cancellationToken);
            }
            else
            {
                // A source session can resume only the same integration/application
                // ownership. Sharing the session does not transfer an active flow.
                if (existing.IntegrationClientId != flow.IntegrationClientId)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return new AccessFlowCreateResult(
                        AccessFlowCreateStatus.IntegrationClientConflict);
                }
                if (existing.ApplicationClientId != flow.ApplicationClientId)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return new AccessFlowCreateResult(
                        AccessFlowCreateStatus.ApplicationClientInvalid);
                }

                await ReconcileExternalArtifactsAsync(
                    existing.Id,
                    startedAt,
                    cancellationToken);
                // Resuming does not create a revision. The new request is anchored to
                // the existing current revision so its replay result remains exact.
                var resumed = new AccessFlowRequest(
                    request.IntegrationClientId,
                    request.RequestId,
                    existing.Id,
                    AccessFlowRequestKind.Start,
                    request.PayloadHash,
                    existing.CurrentRevision,
                    request.CreatedAt);
                dbContext.AccessFlowRequests.Add(resumed);
                var stored = await ToStoredFlowAsync(existing, cancellationToken);
                try
                {
                    await dbContext.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return new AccessFlowCreateResult(
                        AccessFlowCreateStatus.Resumed,
                        stored);
                }
                catch (DbUpdateException exception)
                    when (IsUniqueViolation(exception, RequestPrimaryKey))
                {
                    await transaction.RollbackAsync(cancellationToken);
                    dbContext.ChangeTracker.Clear();
                    return new AccessFlowCreateResult(
                        AccessFlowCreateStatus.RequestAlreadyExists);
                }
            }
        }

        dbContext.AccessFlows.Add(flow);
        // Record erasure reachability at creation; later identity ownership changes must
        // not hide historical snapshots from hard-deletion traversal.
        dbContext.AccessFlowDataSubjects.Add(new AccessFlowDataSubject(
            flow.RealmId,
            flow.Id,
            flow.IdentityId,
            startedAt));
        dbContext.AccessFlowRevisions.Add(revision);
        dbContext.AccessFlowRequests.Add(request);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new AccessFlowCreateResult(AccessFlowCreateStatus.Created);
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return new AccessFlowCreateResult(
                AccessFlowCreateStatus.RequestAlreadyExists);
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, ActiveSourceIntentUniqueConstraint))
        {
            // A parallel creator won after the advisory active-flow read. Report an
            // unsettled slot so the bounded service loop can reload and either resume
            // that winner or propose expiration for its exact revision.
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return new AccessFlowCreateResult(
                AccessFlowCreateStatus.ExistingFlowExpired);
        }
    }

    public Task<StoredAccessFlow?> FindFlowAsync(
        AccessFlowScope scope,
        Guid flowId,
        CancellationToken cancellationToken) =>
        // A flow UUID is only a selector. Integration client, environment, and realm are
        // all required so cross-scope flows are indistinguishable from absence.
        (
            from flow in dbContext.AccessFlows.AsNoTracking()
            join revision in dbContext.AccessFlowRevisions.AsNoTracking()
                on new { FlowId = flow.Id, Revision = flow.CurrentRevision }
                equals new { revision.FlowId, Revision = revision.Revision }
            where flow.Id == flowId
                && flow.IntegrationClientId == scope.IntegrationClientId
                && flow.AppEnvironmentId == scope.AppEnvironmentId
                && flow.RealmId == scope.RealmId
            select new StoredAccessFlow(
                flow.Id,
                flow.IdentityId,
                flow.RegistrationContextId,
                flow.SourceSessionId,
                flow.ApplicationClientId,
                flow.Status,
                flow.ProtocolVersion,
                flow.Intent,
                flow.CurrentRevision,
                flow.ExpiresAt,
                revision.SnapshotJson)
        ).SingleOrDefaultAsync(cancellationToken);

    public async Task<AccessFlowCommitStatus> TryAdvanceAsync(
        AdvanceAccessFlowCommand command,
        CancellationToken cancellationToken)
    {
        // Request uniqueness is checked before loading the flow, then protected again by
        // the request primary key when SaveCommitAsync persists the revision and result.
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.AdvancedAt,
            cancellationToken,
            command.RequestId);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var revisionNumber = pending.Flow!.Advance(
            command.ExpectedRevision,
            command.AdvancedAt);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            pending.Flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.AdvancedAt));
        dbContext.AccessFlowRequests.Add(new AccessFlowRequest(
            command.Scope.IntegrationClientId,
            command.RequestId,
            pending.Flow.Id,
            AccessFlowRequestKind.Action,
            command.PayloadHash,
            revisionNumber,
            command.AdvancedAt));

        return await SaveCommitAsync(transaction, cancellationToken);
    }

    public async Task<AccessFlowCommitStatus> TryAdvanceRegistrationWithIdentifierAsync(
        AdvanceRegistrationWithIdentifierFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.AdvancedAt,
            cancellationToken,
            command.RequestId);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        if (flow.Intent != AccessFlowIntent.ContinueRegistration
            || pending.Context is null
            || command.Identifier.IdentityId != flow.IdentityId
            || command.Identifier.RealmId != flow.RealmId
            || command.Identifier.Scheme is not (IdentifierScheme.Cpf or IdentifierScheme.Phone)
            || (command.Identifier.Scheme == IdentifierScheme.Cpf) != command.BirthDate.HasValue)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RegistrationNotPending;
        }

        var owner = await dbContext.IdentityIdentifiers
            .FromSqlInterpolated(
                $"SELECT * FROM identity_identifiers WHERE realm_id = {flow.RealmId} AND scheme = {command.Identifier.Scheme} AND normalized_value = {command.Identifier.NormalizedValue} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (owner is not null && owner.IdentityId != flow.IdentityId)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }

        if (command.BirthDate is { } birthDate)
        {
            var identity = await dbContext.Identities.SingleAsync(
                item => item.Id == flow.IdentityId && item.RealmId == flow.RealmId,
                cancellationToken);
            identity.RecordBirthDate(birthDate);
        }
        if (owner is null)
        {
            dbContext.IdentityIdentifiers.Add(command.Identifier);
        }

        var revisionNumber = flow.Advance(
            command.ExpectedRevision,
            command.AdvancedAt);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.AdvancedAt));
        dbContext.AccessFlowRequests.Add(new AccessFlowRequest(
            command.Scope.IntegrationClientId,
            command.RequestId,
            flow.Id,
            AccessFlowRequestKind.Action,
            command.PayloadHash,
            revisionNumber,
            command.AdvancedAt));

        return await SavePhoneCommitAsync(transaction, cancellationToken);
    }

    public async Task<AccessFlowCommitStatus> TryCreateProofChallengeAsync(
        CreateProofChallengeFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var expectedOwner = await FindPhoneOwnerAsync(
            command.Scope.RealmId,
            command.Challenge.DestinationValue,
            cancellationToken);
        // LoadActiveFlowAsync locks the source identity/session/flow plus the expected
        // phone owner in deterministic order. The earlier owner read is not authority.
        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.CreatedAt,
            cancellationToken,
            command.RequestId,
            additionalIdentityIds: expectedOwner is null
                ? []
                : [expectedOwner.IdentityId]);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }
        if (command.Challenge.AccessFlowId != pending.Flow!.Id
            || command.Challenge.IdentityId != pending.Flow.IdentityId
            || command.Challenge.Status != ProofChallengeStatus.PendingDelivery)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RegistrationNotPending;
        }

        var lockedPhone = await LockPhoneOwnerAsync(
            pending.Flow.RealmId,
            command.Challenge.DestinationValue,
            expectedOwner,
            cancellationToken);
        if (lockedPhone is { OwnerIsActive: false }
            || !SameOwner(lockedPhone?.Owner, expectedOwner))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }
        if (lockedPhone is not null)
        {
            // The owner may appear in conflict snapshots later. Record the historical
            // data-subject edge before any personal data from that identity is retained.
            await AddDataSubjectAsync(
                pending.Flow,
                lockedPhone.Owner.IdentityId,
                command.CreatedAt,
                cancellationToken);
        }

        var recentCount = await dbContext.ProofChallenges.CountAsync(
            challenge => challenge.IdentityId == pending.Flow.IdentityId
                && challenge.Type == command.Challenge.Type
                && challenge.Status != ProofChallengeStatus.DeliveryFailed
                && challenge.CreatedAt >= command.RateWindowStartsAt,
            cancellationToken);
        if (recentCount >= command.MaxRequestsInRateWindow)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ChallengeRateLimited;
        }

        var conflict = await LockPhoneConflictAsync(
            pending.Flow.Id,
            cancellationToken);
        if (conflict is not null)
        {
            // An unexpired ownership conflict is a different state-machine branch; a
            // fresh possession challenge cannot silently replace that pending decision.
            if (conflict.ExpiresAt > command.CreatedAt)
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.PhoneConflictNotPending;
            }
            dbContext.PhoneRegistrationConflicts.Remove(conflict);
        }

        var active = await dbContext.ProofChallenges
            .Where(challenge =>
                challenge.AccessFlowId == pending.Flow.Id
                && challenge.Type == command.Challenge.Type
                && challenge.Status == ProofChallengeStatus.Active)
            .ToListAsync(cancellationToken);
        if (active.Any(challenge => challenge.ResendAvailableAt > command.CreatedAt))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ChallengeResendTooSoon;
        }

        // Keep existing active challenges until the new delivery is known to work. The
        // reservation inserts only PendingDelivery state plus its pending request.
        dbContext.ProofChallenges.Add(command.Challenge);
        dbContext.AccessFlowRequests.Add(AccessFlowRequest.ReserveExternal(
            command.Scope.IntegrationClientId,
            command.RequestId,
            pending.Flow.Id,
            command.PayloadHash,
            command.CreatedAt));

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationReserved;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, PendingExternalRequestUniqueConstraint)
                || IsUniqueViolation(exception, PendingDeliveryChallengeUniqueConstraint))
        {
            // Partial unique indexes arbitrate races that passed the preliminary reads:
            // one provider effect may be pending for the flow and challenge type.
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.ExternalOperationPending;
        }
    }

    public async Task<AccessFlowCommitStatus> TryFinalizeProofChallengeDeliveryAsync(
        FinalizeProofChallengeDeliveryFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.FinalizedAt,
            cancellationToken,
            command.RequestId,
            continuePendingRequest: true);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        var request = pending.Request;
        // Finalization must continue the exact reservation. A matching request id with
        // different payload or lifecycle state cannot claim this provider effect.
        if (request is null
            || request.FlowId != flow.Id
            || request.Kind != AccessFlowRequestKind.Action
            || request.Status != AccessFlowRequestStatus.PendingExternal
            || !PayloadMatches(request.PayloadHash, command.PayloadHash))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }

        var conflict = await LockPhoneConflictAsync(flow.Id, cancellationToken);
        if (conflict is not null)
        {
            if (conflict.ExpiresAt > command.FinalizedAt)
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.PhoneConflictNotPending;
            }
            dbContext.PhoneRegistrationConflicts.Remove(conflict);
        }

        var challenge = await dbContext.ProofChallenges
            .FromSqlInterpolated(
                $"SELECT * FROM proof_challenges WHERE id = {command.ChallengeId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (challenge is null
            || challenge.AccessFlowId != flow.Id
            || challenge.IdentityId != flow.IdentityId
            || challenge.Status != ProofChallengeStatus.PendingDelivery
            || challenge.ExpiresAt <= command.FinalizedAt)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }

        var active = await dbContext.ProofChallenges
            .Where(item => item.AccessFlowId == flow.Id
                && item.Type == challenge.Type
                && item.Status == ProofChallengeStatus.Active)
            .ToListAsync(cancellationToken);
        // Supersede the prior usable challenge only after the replacement delivery has
        // succeeded and its pending row has been revalidated under lock.
        foreach (var item in active)
        {
            item.Supersede(command.FinalizedAt);
        }

        if (active.Count > 0)
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }

        challenge.Activate(command.ProviderReference);
        // Activation, snapshot revision, and request commit are one local transaction;
        // replay can never observe a delivered challenge without its matching result.
        var revisionNumber = flow.Advance(
            command.ExpectedRevision,
            command.FinalizedAt);
        request.Commit(revisionNumber);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.FinalizedAt));

        return await SaveCommitAsync(transaction, cancellationToken);
    }

    public async Task<AccessFlowCommitStatus> TryFailProofChallengeDeliveryAsync(
        FailProofChallengeDeliveryFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var reservation = await LoadExternalReservationAsync(
            command.Scope,
            command.FlowId,
            command.RequestId,
            command.ChallengeId,
            cancellationToken);
        if (reservation is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }
        if (!PayloadMatches(reservation.Request.PayloadHash, command.PayloadHash))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        if (reservation.Request.Status == AccessFlowRequestStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        if (reservation.Request.Status == AccessFlowRequestStatus.ExternalFailed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }
        if (reservation.Challenge.Status != ProofChallengeStatus.PendingDelivery)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }

        // Delivery failure closes only the new reservation. Any older Active challenge
        // was intentionally left untouched and may remain usable until its own expiry.
        reservation.Challenge.FailDelivery(command.FailedAt);
        reservation.Request.FailExternal();
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AccessFlowCommitStatus.ExternalOperationFailed;
    }

    public async Task<AccessFlowCommitStatus> TryRecordFailedProofAttemptAsync(
        RecordFailedProofAttemptFlowCommand command,
        CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.AttemptedAt,
            cancellationToken,
            command.RequestId);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var challenge = await dbContext.ProofChallenges.SingleOrDefaultAsync(
            item => item.Id == command.ChallengeId
                && item.AccessFlowId == pending.Flow!.Id
                && item.IdentityId == pending.Flow.IdentityId
                && item.Status == ProofChallengeStatus.Active
                && item.ExpiresAt > command.AttemptedAt,
            cancellationToken);
        // ExpectedChallengeAttempts is optimistic concurrency for the OTP counter. Two
        // submissions based on the same snapshot cannot both record the next attempt.
        if (challenge is null || challenge.Attempts != command.ExpectedChallengeAttempts)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ProofChallengeNotActive;
        }

        challenge.RecordFailure(command.AttemptedAt);
        // Attempt evidence, feedback snapshot, and request result advance together so
        // exact replay never loses the reason the flow moved to its next state.
        var revisionNumber = pending.Flow!.Advance(
            command.ExpectedRevision,
            command.AttemptedAt);
        dbContext.ProofAttempts.Add(command.Attempt);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            pending.Flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.AttemptedAt));
        dbContext.AccessFlowRequests.Add(new AccessFlowRequest(
            command.Scope.IntegrationClientId,
            command.RequestId,
            pending.Flow.Id,
            AccessFlowRequestKind.Action,
            command.PayloadHash,
            revisionNumber,
            command.AttemptedAt));

        return await SaveCommitAsync(transaction, cancellationToken);
    }

    public async Task<AccessFlowCommitStatus> TryBeginPhoneConfirmationAsync(
        BeginPhoneConfirmationFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.BeganAt,
            cancellationToken,
            command.RequestId,
            additionalIdentityIds: command.ExpectedOwner is null
                ? []
                : [command.ExpectedOwner.IdentityId]);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        var lockedPhone = await LockPhoneOwnerAsync(
            flow.RealmId,
            command.NormalizedPhone,
            command.ExpectedOwner,
            cancellationToken);
        if (lockedPhone is { OwnerIsActive: false }
            || !SameOwner(lockedPhone?.Owner, command.ExpectedOwner))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }

        // The service compared the local OTP hash before this call. Re-check challenge
        // identity, destination, expiry, and attempt count under lock before reserving
        // the right to finalize that proof.
        var challenge = await dbContext.ProofChallenges
            .FromSqlInterpolated(
                $"SELECT * FROM proof_challenges WHERE id = {command.ChallengeId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (challenge is null
            || challenge.AccessFlowId != flow.Id
            || challenge.IdentityId != flow.IdentityId
            || challenge.Type != ProofChallengeType.PhonePossession
            || challenge.DestinationValue != command.NormalizedPhone
            || challenge.Status != ProofChallengeStatus.Active
            || challenge.ExpiresAt <= command.BeganAt
            || challenge.Attempts != command.ExpectedChallengeAttempts)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ProofChallengeNotActive;
        }

        if (lockedPhone is not null)
        {
            // A confirmed value owned by another identity can place personal data from
            // that owner in conflict state; preserve erasure reachability before commit.
            await AddDataSubjectAsync(
                flow,
                lockedPhone.Owner.IdentityId,
                command.BeganAt,
                cancellationToken);
        }

        // Confirming prevents a second request from consuming the same locally accepted
        // OTP while final persistence is in progress. PendingExternal is the shared
        // durable request state used for this two-phase commit boundary.
        challenge.BeginConfirmation(command.BeganAt);
        dbContext.AccessFlowRequests.Add(AccessFlowRequest.ReserveExternal(
            command.Scope.IntegrationClientId,
            command.RequestId,
            flow.Id,
            command.PayloadHash,
            command.BeganAt));

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationReserved;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, PendingExternalRequestUniqueConstraint)
                || IsUniqueViolation(exception, ConfirmingChallengeUniqueConstraint))
        {
            // Database constraints are the final arbiter if parallel confirmations pass
            // preliminary request and challenge checks at the same time.
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.ExternalOperationPending;
        }
    }

    public async Task<AccessFlowCommitStatus> TryReleasePhoneConfirmationAsync(
        ReleasePhoneConfirmationFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var reservation = await LoadExternalReservationAsync(
            command.Scope,
            command.FlowId,
            command.RequestId,
            command.ChallengeId,
            cancellationToken);
        if (reservation is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }
        if (!PayloadMatches(reservation.Request.PayloadHash, command.PayloadHash))
        {
            // The same request id cannot be repurposed to release a reservation created
            // for different input.
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        if (reservation.Request.Status == AccessFlowRequestStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        if (reservation.Request.Status == AccessFlowRequestStatus.ExternalFailed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }
        if (reservation.Challenge.Status != ProofChallengeStatus.Confirming)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }

        // Return a still-valid challenge to Active so it can be retried with a new request
        // id; the domain makes an expired challenge terminal instead. The failed request
        // remains durable and cannot be replayed as success.
        reservation.Challenge.ReleaseConfirmation(command.ReleasedAt);
        reservation.Request.FailExternal();
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AccessFlowCommitStatus.ExternalOperationFailed;
    }

    public async Task<AccessFlowCommitStatus> TryConfirmPhoneAsync(
        ConfirmPhoneFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.ConfirmedAt,
            cancellationToken,
            command.RequestId,
            continuePendingRequest: true,
            additionalIdentityIds: command.ExpectedOwner is null
                ? []
                : [command.ExpectedOwner.IdentityId]);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        var request = pending.Request;
        // Finalization must consume the exact pending request created by Begin. Matching
        // flow and request ids are insufficient when payload or lifecycle state differs.
        if (request is null
            || request.FlowId != flow.Id
            || request.Kind != AccessFlowRequestKind.Action
            || request.Status != AccessFlowRequestStatus.PendingExternal
            || !PayloadMatches(request.PayloadHash, command.PayloadHash))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }

        var existingConflict = await LockPhoneConflictAsync(
            flow.Id,
            cancellationToken);
        var lockedPhone = await LockPhoneOwnerAsync(
            flow.RealmId,
            command.NormalizedPhone,
            command.ExpectedOwner,
            cancellationToken);
        var actualIdentifier = lockedPhone?.Identifier;
        var actualOwner = lockedPhone?.Owner;
        if (lockedPhone is { OwnerIsActive: false }
            || !SameOwner(actualOwner, command.ExpectedOwner))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }

        // Confirming is mandatory: local hash comparison alone did not yet create proof
        // or mutate identifier ownership, and an Active challenge can still race.
        var challenge = await dbContext.ProofChallenges
            .FromSqlInterpolated(
                $"SELECT * FROM proof_challenges WHERE id = {command.ChallengeId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (challenge is null
            || challenge.AccessFlowId != flow.Id
            || challenge.IdentityId != flow.IdentityId
            || challenge.Type != ProofChallengeType.PhonePossession
            || challenge.DestinationValue != command.NormalizedPhone
            || challenge.Status != ProofChallengeStatus.Confirming
            || challenge.ExpiresAt <= command.ConfirmedAt
            || challenge.Attempts != command.ExpectedChallengeAttempts)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ProofChallengeNotActive;
        }

        if (actualOwner is not null)
        {
            await AddDataSubjectAsync(
                flow,
                actualOwner.IdentityId,
                command.ConfirmedAt,
                cancellationToken);
        }

        if (actualOwner is null)
        {
            // No owner means the command must supply the exact new phone identifier that
            // was derived from this challenge and target identity.
            if (command.NewPhoneIdentifier is not null)
            {
                if (command.NewPhoneIdentifier.IdentityId != flow.IdentityId
                    || command.NewPhoneIdentifier.RealmId != flow.RealmId
                    || command.NewPhoneIdentifier.Scheme != IdentifierScheme.Phone
                    || command.NewPhoneIdentifier.NormalizedValue
                        != challenge.DestinationValue)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return AccessFlowCommitStatus.PhoneOwnershipChanged;
                }
                if (flow.Intent == AccessFlowIntent.ManagePhone)
                {
                    await DeleteOtherPhoneIdentifiersAsync(
                        flow.IdentityId,
                        command.NewPhoneIdentifier.Id,
                        cancellationToken);
                }
                dbContext.IdentityIdentifiers.Add(command.NewPhoneIdentifier);
            }
            else
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.PhoneOwnershipChanged;
            }
        }
        else if (command.NewPhoneIdentifier is not null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }

        var provedIdentifierId = actualIdentifier?.Id
            ?? command.NewPhoneIdentifier!.Id;
        if (command.Attempt.ChallengeId != challenge.Id
            || command.Proof.AccessFlowId != flow.Id
            || command.Proof.IdentityId != flow.IdentityId
            || command.Proof.ChallengeId != challenge.Id
            || command.Proof.Type != ProofChallengeType.PhonePossession
            || command.Proof.SubjectIdentifierId != provedIdentifierId)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ProofChallengeNotActive;
        }

        var conflict = actualOwner is
        {
            IsVerified: true,
            IdentityId: var ownerIdentityId,
        } && ownerIdentityId != flow.IdentityId;
        // Command shape must agree with locked ownership: a verified foreign owner opens
        // explicit conflict state and cannot simultaneously issue a product session.
        var shouldIssueSession = !conflict && !command.ContinueRegistration;
        if (conflict != (command.PhoneConflict is not null)
            || shouldIssueSession != (command.ProductSession is not null)
            || (command.ContinueRegistration
                && (conflict || flow.Intent != AccessFlowIntent.ContinueRegistration
                    || pending.Context is null)))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }

        challenge.Confirm(command.ConfirmedAt);
        dbContext.ProofAttempts.Add(command.Attempt);
        dbContext.IdentityProofs.Add(command.Proof);

        int revisionNumber;
        if (conflict)
        {
            var phoneConflict = command.PhoneConflict!;
            if (phoneConflict.AccessFlowId != flow.Id
                || phoneConflict.PreviousIdentityId != actualOwner!.IdentityId
                || phoneConflict.ConflictingPhoneIdentifierId != actualOwner.IdentifierId
                || command.Proof.SubjectIdentifierId != actualOwner.IdentifierId)
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.PhoneOwnershipChanged;
            }

            if (existingConflict is not null)
            {
                if (existingConflict.ExpiresAt > command.ConfirmedAt)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return AccessFlowCommitStatus.PhoneConflictNotPending;
                }
                dbContext.PhoneRegistrationConflicts.Remove(existingConflict);
                await dbContext.SaveChangesAsync(cancellationToken);
            }

            dbContext.PhoneRegistrationConflicts.Add(phoneConflict);
            revisionNumber = flow.Advance(
                command.ExpectedRevision,
                command.ConfirmedAt);
        }
        else
        {
            if (!command.ContinueRegistration && (command.ProductSession is null
                || command.ProductSession.IdentityId != flow.IdentityId
                || command.ProductSession.AppEnvironmentId != flow.AppEnvironmentId
                || command.ProductSession.Purpose != IdentitySessionPurpose.Product))
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.RegistrationNotPending;
            }

            if (actualIdentifier is not null)
            {
                if (flow.Intent == AccessFlowIntent.ManagePhone)
                {
                    await DeleteOtherPhoneIdentifiersAsync(
                        flow.IdentityId,
                        actualIdentifier.Id,
                        cancellationToken);
                }
                if (actualIdentifier.IdentityId != flow.IdentityId)
                {
                    var previousIdentityId = actualIdentifier.IdentityId;
                    // Only a non-conflicting identifier may move here. Invalidate the
                    // previous owner's recovery paths in the same ownership transaction.
                    actualIdentifier.TransferTo(flow.IdentityId);
                    await InvalidateRecoveryArtifactsAsync(
                        [previousIdentityId],
                        command.ConfirmedAt,
                        cancellationToken);
                }
                if (actualIdentifier.VerifiedAt is null)
                {
                    actualIdentifier.Verify(command.ConfirmedAt, "sms");
                }
            }

            // Any recovery authority created from the target identity's earlier contact
            // snapshot becomes stale once verified phone ownership is committed.
            await InvalidateRecoveryArtifactsAsync(
                [flow.IdentityId],
                command.ConfirmedAt,
                cancellationToken);

            if (command.ContinueRegistration)
            {
                revisionNumber = flow.Advance(
                    command.ExpectedRevision,
                    command.ConfirmedAt);
            }
            else
            {
                if (flow.Intent == AccessFlowIntent.ContinueRegistration)
                {
                    pending.Context!.Complete(command.ConfirmedAt);
                }
                revisionNumber = flow.Complete(
                    command.ExpectedRevision,
                    command.ConfirmedAt);
                dbContext.IdentitySessions.Add(command.ProductSession!);
                if (flow.Intent == AccessFlowIntent.ContinueRegistration)
                {
                    if (!await TryRevokeSourceSessionAsync(
                            flow,
                            IdentitySessionPurpose.Registration,
                            command.ConfirmedAt,
                            cancellationToken))
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return AccessFlowCommitStatus.RegistrationNotPending;
                    }
                    await RevokeOtherRegistrationSessionsAsync(
                        flow,
                        command.ConfirmedAt,
                        cancellationToken);
                }
                else
                {
                    if (!await TryRevokeSourceSessionAsync(
                            flow,
                            IdentitySessionPurpose.Product,
                            command.ConfirmedAt,
                            cancellationToken))
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return AccessFlowCommitStatus.SourceSessionInactive;
                    }
                }
            }
        }

        // Linking the issued session id to the request lets deterministic replay recover
        // the same terminal session authority without storing its clear bearer value.
        request.Commit(revisionNumber, command.ProductSession?.Id);

        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.ConfirmedAt));
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.Committed;
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RevisionConflict;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey)
                || IsUniqueViolation(exception, SessionTokenUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, IdentifierValueUniqueConstraint)
                || IsUniqueViolation(exception, IdentitySchemeUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }
    }

    public async Task<AccessFlowCommitStatus> TryRecordPhoneConflictEmailFailureAsync(
        RecordPhoneConflictEmailFailureFlowCommand command,
        CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.AttemptedAt,
            cancellationToken,
            command.RequestId);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }
        var flow = pending.Flow!;
        var conflict = await LockPhoneConflictAsync(
            flow.Id,
            cancellationToken);
        if (conflict is null || conflict.ExpiresAt <= command.AttemptedAt)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneConflictNotPending;
        }

        if (conflict.FailedEmailAttempts != command.ExpectedAttempts)
        {
            // Attempt count is optimistic concurrency within the conflict revision. A
            // second submission from the same snapshot must refresh before continuing.
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RevisionConflict;
        }
        if (conflict.EmailResolutionExhaustedAt is not null
            || conflict.FailedEmailAttempts >= command.MaxAttempts)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.TooManyAttempts;
        }

        conflict.RecordEmailMismatch(command.MaxAttempts, command.AttemptedAt);
        // Failure count, exhaustion state, feedback snapshot, and idempotency result
        // advance together; replay returns this exact attempt outcome.
        var revisionNumber = flow.Advance(
            command.ExpectedRevision,
            command.AttemptedAt);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.AttemptedAt));
        dbContext.AccessFlowRequests.Add(new AccessFlowRequest(
            command.Scope.IntegrationClientId,
            command.RequestId,
            flow.Id,
            AccessFlowRequestKind.Action,
            command.PayloadHash,
            revisionNumber,
            command.AttemptedAt));

        return await SaveCommitAsync(transaction, cancellationToken);
    }

    public async Task<AccessFlowCommitStatus> TryTransferPhoneAsync(
        TransferPhoneFlowCommand command,
        CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.CompletedAt,
            cancellationToken,
            command.RequestId,
            additionalIdentityIds: [command.ExpectedPreviousIdentityId]);
        // The previous identity joins the standard lock set so phone ownership cannot
        // move while the transfer decision is being revalidated.
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }
        var flow = pending.Flow!;
        var conflict = await LockPhoneConflictAsync(
            flow.Id,
            cancellationToken);
        if (conflict is null || conflict.ExpiresAt <= command.CompletedAt)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneConflictNotPending;
        }

        if (conflict.PreviousIdentityId != command.ExpectedPreviousIdentityId)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }

        if (conflict.FailedEmailAttempts != command.ExpectedAttempts)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RevisionConflict;
        }
        if (conflict.EmailResolutionExhaustedAt is not null
            || conflict.FailedEmailAttempts >= command.MaxAttempts)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.TooManyAttempts;
        }

        var previousEmail = await dbContext.IdentityIdentifiers.SingleOrDefaultAsync(
            identifier => identifier.IdentityId == conflict.PreviousIdentityId
                && identifier.RealmId == flow.RealmId
                && identifier.Scheme == IdentifierScheme.Email
                && identifier.NormalizedValue == command.NormalizedPreviousEmail,
            cancellationToken);
        // Re-check every fact implied by the service snapshot: exact normalized e-mail
        // knowledge, active previous owner, still-owned verified phone, durable phone
        // proof, and correctly scoped product session. The e-mail match is not proof of
        // mailbox possession.
        var previousIdentityIsActive = await dbContext.Identities.AnyAsync(
            identity => identity.Id == conflict.PreviousIdentityId
                && identity.RealmId == flow.RealmId
                && identity.LifecycleState == IdentityLifecycleState.Active,
            cancellationToken);
        var phone = await dbContext.IdentityIdentifiers
            .FromSqlInterpolated(
                $"SELECT * FROM identity_identifiers WHERE id = {conflict.ConflictingPhoneIdentifierId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        var hasPhoneProof = await dbContext.IdentityProofs.AnyAsync(
            proof => proof.AccessFlowId == flow.Id
                && proof.IdentityId == flow.IdentityId
                && proof.Type == ProofChallengeType.PhonePossession
                && proof.SubjectIdentifierId == conflict.ConflictingPhoneIdentifierId,
            cancellationToken);
        if (previousEmail is null
            || !previousIdentityIsActive
            || phone is null
            || phone.IdentityId != conflict.PreviousIdentityId
            || phone.RealmId != flow.RealmId
            || phone.Scheme != IdentifierScheme.Phone
            || phone.VerifiedAt is null
            || !hasPhoneProof
            || (command.ContinueRegistration
                ? flow.Intent != AccessFlowIntent.ContinueRegistration
                    || pending.Context is null || command.ProductSession is not null
                : command.ProductSession is null
                    || command.ProductSession.IdentityId != flow.IdentityId
                    || command.ProductSession.AppEnvironmentId != flow.AppEnvironmentId
                    || command.ProductSession.Purpose != IdentitySessionPurpose.Product))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneConflictNotPending;
        }

        if (flow.Intent == AccessFlowIntent.ManagePhone)
        {
            await DeleteOtherPhoneIdentifiersAsync(
                flow.IdentityId,
                phone.Id,
                cancellationToken);
        }
        phone.TransferTo(flow.IdentityId);
        phone.Verify(command.CompletedAt, "sms");
        // Ownership transfer makes recovery artifacts for both identity snapshots stale;
        // invalidate them atomically with the identifier move.
        await InvalidateRecoveryArtifactsAsync(
            [flow.IdentityId, conflict.PreviousIdentityId],
            command.CompletedAt,
            cancellationToken);
        if (!command.ContinueRegistration && flow.Intent == AccessFlowIntent.ContinueRegistration)
        {
            pending.Context!.Complete(command.CompletedAt);
        }
        var revisionNumber = command.ContinueRegistration
            ? flow.Advance(command.ExpectedRevision, command.CompletedAt)
            : flow.Complete(command.ExpectedRevision, command.CompletedAt);

        dbContext.PhoneRegistrationConflicts.Remove(conflict);
        if (command.ProductSession is not null)
        {
            dbContext.IdentitySessions.Add(command.ProductSession);
        }
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.CompletedAt));
        dbContext.AccessFlowRequests.Add(new AccessFlowRequest(
            command.Scope.IntegrationClientId,
            command.RequestId,
            flow.Id,
            AccessFlowRequestKind.Action,
            command.PayloadHash,
            revisionNumber,
            command.CompletedAt,
            command.ProductSession?.Id));
        if (!command.ContinueRegistration && flow.Intent == AccessFlowIntent.ContinueRegistration)
        {
            if (!await TryRevokeSourceSessionAsync(
                    flow,
                    IdentitySessionPurpose.Registration,
                    command.CompletedAt,
                    cancellationToken))
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.RegistrationNotPending;
            }
            await RevokeOtherRegistrationSessionsAsync(
                flow,
                command.CompletedAt,
                cancellationToken);
        }
        else if (!command.ContinueRegistration)
        {
            if (!await TryRevokeSourceSessionAsync(
                    flow,
                    IdentitySessionPurpose.Product,
                    command.CompletedAt,
                    cancellationToken))
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.SourceSessionInactive;
            }
        }

        return await SavePhoneCommitAsync(transaction, cancellationToken);
    }

    public async Task<AccessFlowCommitStatus> TryChangePhoneAsync(
        ChangePhoneFlowCommand command,
        CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.ChangedAt,
            cancellationToken,
            command.RequestId);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        var conflict = await LockPhoneConflictAsync(
            flow.Id,
            cancellationToken);
        var challenges = await dbContext.ProofChallenges
            .Where(challenge =>
                challenge.AccessFlowId == flow.Id
                && challenge.IdentityId == flow.IdentityId
                && challenge.Type == ProofChallengeType.PhonePossession
                && challenge.Status == ProofChallengeStatus.Active)
            .ToListAsync(cancellationToken);
        foreach (var challenge in challenges)
        {
            // Codes issued for the abandoned destination must not remain usable after
            // the flow returns to phone collection.
            challenge.Supersede(command.ChangedAt);
        }
        if (conflict is not null)
        {
            // This action abandons the conflict decision only. It does not transfer or
            // delete the phone currently owned by either identity.
            dbContext.PhoneRegistrationConflicts.Remove(conflict);
        }

        var revisionNumber = flow.Advance(
            command.ExpectedRevision,
            command.ChangedAt);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.ChangedAt));
        dbContext.AccessFlowRequests.Add(new AccessFlowRequest(
            command.Scope.IntegrationClientId,
            command.RequestId,
            flow.Id,
            AccessFlowRequestKind.Action,
            command.PayloadHash,
            revisionNumber,
            command.ChangedAt));

        return await SaveCommitAsync(transaction, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<AccessFlowCommitStatus> TryReservePreviousIdentityRecoveryAsync(
        ReservePreviousIdentityRecoveryFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.ReservedAt,
            cancellationToken,
            command.RequestId,
            additionalIdentityIds: [command.ExpectedPreviousIdentityId]);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        // Reservation and finalization use the same locked validation routine. Do not
        // send recovery e-mail based only on the earlier, unlocked service snapshot.
        var recovery = await LockPreviousIdentityRecoveryAsync(
            flow,
            command.ExpectedPreviousIdentityId,
            command.ExpectedPhoneIdentifierId,
            command.ReservedAt,
            cancellationToken);
        if (recovery.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return recovery.Status;
        }

        // Persist only the idempotency reservation here; the flow revision advances
        // after the provider accepts delivery. The unique pending-request constraint
        // grants at most one caller ownership of this external effect.
        dbContext.AccessFlowRequests.Add(AccessFlowRequest.ReserveExternal(
            command.Scope.IntegrationClientId,
            command.RequestId,
            flow.Id,
            command.PayloadHash,
            command.ReservedAt));
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationReserved;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, PendingExternalRequestUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.ExternalOperationPending;
        }
    }

    /// <inheritdoc />
    public async Task<AccessFlowCommitStatus> TryFailPreviousIdentityRecoveryAsync(
        FailPreviousIdentityRecoveryFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var request = await LockPendingRequestAsync(
            command.Scope,
            command.FlowId,
            command.RequestId,
            cancellationToken);
        if (request is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }
        if (!PayloadMatches(request.PayloadHash, command.PayloadHash)
            || request.Status == AccessFlowRequestStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        if (request.Status == AccessFlowRequestStatus.ExternalFailed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }

        // Failure closes only this matching reservation. Any issued reset token is a
        // separate recovery aggregate and is compensated through its opaque token id.
        request.FailExternal();
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AccessFlowCommitStatus.ExternalOperationFailed;
    }

    /// <inheritdoc />
    public async Task<AccessFlowCommitStatus> TryFinalizePreviousIdentityRecoveryAsync(
        RecoverPreviousIdentityFlowCommand command,
        CancellationToken cancellationToken)
    {
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.CompletedAt,
            cancellationToken,
            command.RequestId,
            continuePendingRequest: true,
            additionalIdentityIds: [command.ExpectedPreviousIdentityId]);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        var request = pending.Request;
        if (request is null
            || request.FlowId != flow.Id
            || request.Kind != AccessFlowRequestKind.Action
            || request.Status != AccessFlowRequestStatus.PendingExternal
            || !PayloadMatches(request.PayloadHash, command.PayloadHash))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.ExternalOperationFailed;
        }

        // E-mail acceptance is not enough to authorize completion. Re-check the same
        // conflict, identity lifecycle, phone ownership, and durable phone proof that
        // made the reservation eligible.
        var recovery = await LockPreviousIdentityRecoveryAsync(
            flow,
            command.ExpectedPreviousIdentityId,
            command.ExpectedPhoneIdentifierId,
            command.CompletedAt,
            cancellationToken);
        if (recovery.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return recovery.Status;
        }

        // Recovery keeps the previous identity and its phone. The identity created for
        // the interrupted registration is the one abandoned, and its registration
        // context, conflict, source session, and flow close in this transaction.
        recovery.CurrentIdentity!.Abandon();
        pending.Context!.Abandon(command.CompletedAt);
        var revisionNumber = flow.Complete(
            command.ExpectedRevision,
            command.CompletedAt);
        dbContext.PhoneRegistrationConflicts.Remove(recovery.Conflict!);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            revisionNumber,
            command.SnapshotJson,
            command.CompletedAt));
        request.Commit(revisionNumber);

        // Remove every authentication and proof path owned by the abandoned provisional
        // identity. The identity row remains as lifecycle history but cannot authenticate.
        if (!await TryRevokeSourceSessionAsync(
                flow,
                IdentitySessionPurpose.Registration,
                command.CompletedAt,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RegistrationNotPending;
        }
        await dbContext.IdentitySessions
            .Where(session =>
                session.IdentityId == flow.IdentityId
                && session.Id != flow.SourceSessionId
                && session.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    session => session.RevokedAt,
                    command.CompletedAt),
                cancellationToken);
        await dbContext.PasswordResetTokens
            .Where(token => token.IdentityId == flow.IdentityId)
            .ExecuteDeleteAsync(cancellationToken);
        await dbContext.PasswordCredentials
            .Where(credential => credential.IdentityId == flow.IdentityId)
            .ExecuteDeleteAsync(cancellationToken);
        await dbContext.SocialCredentials
            .Where(credential => credential.IdentityId == flow.IdentityId)
            .ExecuteDeleteAsync(cancellationToken);
        await dbContext.IdentityProofs
            .Where(proof => proof.AccessFlowId == flow.Id)
            .ExecuteDeleteAsync(cancellationToken);
        await dbContext.ProofAttempts
            .Where(attempt => dbContext.ProofChallenges.Any(challenge =>
                challenge.Id == attempt.ChallengeId
                && challenge.AccessFlowId == flow.Id))
            .ExecuteDeleteAsync(cancellationToken);
        await dbContext.ProofChallenges
            .Where(challenge =>
                challenge.AccessFlowId == flow.Id)
            .ExecuteDeleteAsync(cancellationToken);
        await dbContext.PhonePasswordResetChallenges
            .Where(challenge => challenge.IdentityId == flow.IdentityId)
            .ExecuteDeleteAsync(cancellationToken);
        await dbContext.IdentityIdentifiers
            .Where(identifier => identifier.IdentityId == flow.IdentityId)
            .ExecuteDeleteAsync(cancellationToken);

        return await SaveCommitAsync(transaction, cancellationToken);
    }

    public async Task<AccessFlowCommitStatus> TryCompletePhoneManagementAsync(
        CompletePhoneManagementFlowCommand command,
        CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.CompletedAt,
            cancellationToken,
            command.RequestId);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        // The supplied session is server-created, but validate its identity, environment,
        // and purpose inside the transaction before allowing it to replace source authority.
        if (flow.Intent != AccessFlowIntent.ManagePhone
            || command.ProductSession.IdentityId != flow.IdentityId
            || command.ProductSession.AppEnvironmentId != flow.AppEnvironmentId
            || command.ProductSession.Purpose != IdentitySessionPurpose.Product)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }

        // The earlier service lookup was advisory. Lock the natural phone key again so
        // ownership cannot change between availability checking and final commit.
        var target = await dbContext.IdentityIdentifiers
            .FromSqlInterpolated(
                $"SELECT * FROM identity_identifiers WHERE realm_id = {flow.RealmId} AND scheme = {IdentifierScheme.Phone} AND normalized_value = {command.NormalizedPhone} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (target is not null && target.IdentityId != flow.IdentityId)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }

        if (target is null)
        {
            var identifier = new IdentityIdentifier(
                Guid.CreateVersion7(command.CompletedAt),
                flow.IdentityId,
                flow.RealmId,
                IdentifierScheme.Phone,
                command.NormalizedPhone,
                command.CompletedAt);
            // managePhone models one selected phone per identity. Remove older phone
            // identifiers while retaining non-phone identifiers and credentials.
            await DeleteOtherPhoneIdentifiersAsync(
                flow.IdentityId,
                identifier.Id,
                cancellationToken);
            dbContext.IdentityIdentifiers.Add(identifier);
        }
        else
        {
            await DeleteOtherPhoneIdentifiersAsync(
                flow.IdentityId,
                target.Id,
                cancellationToken);
        }

        // Reset links and phone-recovery challenges were authorized from the previous
        // contact snapshot and become stale when the selected phone changes.
        await InvalidateRecoveryArtifactsAsync(
            [flow.IdentityId],
            command.CompletedAt,
            cancellationToken);

        var resultRevision = flow.Complete(
            command.ExpectedRevision,
            command.CompletedAt);
        dbContext.IdentitySessions.Add(command.ProductSession);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            resultRevision,
            command.SnapshotJson,
            command.CompletedAt));
        dbContext.AccessFlowRequests.Add(new AccessFlowRequest(
            command.Scope.IntegrationClientId,
            command.RequestId,
            flow.Id,
            AccessFlowRequestKind.Action,
            command.PayloadHash,
            resultRevision,
            command.CompletedAt,
            command.ProductSession.Id));
        // Rotation succeeds only if the exact active product session that authorized
        // this flow is revoked in the same transaction. Other product sessions remain.
        if (!await TryRevokeSourceSessionAsync(
                flow,
                IdentitySessionPurpose.Product,
                command.CompletedAt,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.SourceSessionInactive;
        }

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.Committed;
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RevisionConflict;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey)
                || IsUniqueViolation(exception, SessionTokenUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, IdentifierValueUniqueConstraint)
                || IsUniqueViolation(exception, IdentitySchemeUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }
    }

    public async Task<AccessFlowCommitStatus> TryCompleteRegistrationAsync(
        CompleteRegistrationFlowCommand command,
        CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);

        if (await RequestExistsAsync(
                command.Scope.IntegrationClientId,
                command.RequestId,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }

        var pending = await LoadActiveFlowAsync(
            command.Scope,
            command.FlowId,
            command.ExpectedRevision,
            command.CompletedAt,
            cancellationToken,
            command.RequestId);
        if (pending.Status != AccessFlowCommitStatus.Committed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return pending.Status;
        }

        var flow = pending.Flow!;
        var context = pending.Context;
        if (flow.Intent != AccessFlowIntent.ContinueRegistration
            || context is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RegistrationNotPending;
        }

        // A terminal registration action, including an offered skip, closes any conflict
        // branch and active challenges so no proof can mutate the completed journey.
        var phoneConflict = await LockPhoneConflictAsync(
            flow.Id,
            cancellationToken);

        if (command.Identifier is not null)
        {
            if (command.Identifier.IdentityId != flow.IdentityId
                || command.Identifier.RealmId != flow.RealmId
                || command.Identifier.Scheme is not (
                    IdentifierScheme.Phone or IdentifierScheme.Cpf))
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.PhoneOwnershipChanged;
            }

            if ((command.Identifier.Scheme == IdentifierScheme.Cpf)
                != (command.BirthDate is not null))
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.RegistrationNotPending;
            }

            // Re-check the natural identifier key under lock. A conflict created after the
            // service's preliminary lookup must defeat this completion.
            var owner = await dbContext.IdentityIdentifiers
                .FromSqlInterpolated(
                    $"SELECT * FROM identity_identifiers WHERE realm_id = {flow.RealmId} AND scheme = {command.Identifier.Scheme} AND normalized_value = {command.Identifier.NormalizedValue} FOR UPDATE")
                .SingleOrDefaultAsync(cancellationToken);
            if (owner is not null && owner.IdentityId != flow.IdentityId)
            {
                await transaction.RollbackAsync(cancellationToken);
                return AccessFlowCommitStatus.PhoneOwnershipChanged;
            }
            if (owner is null)
            {
                dbContext.IdentityIdentifiers.Add(command.Identifier);
            }

            if (command.BirthDate is not null)
            {
                var identity = await dbContext.Identities.SingleAsync(
                    item => item.Id == flow.IdentityId && item.RealmId == flow.RealmId,
                    cancellationToken);
                identity.RecordBirthDate(command.BirthDate.Value);
            }
        }

        if (phoneConflict is not null)
        {
            dbContext.PhoneRegistrationConflicts.Remove(phoneConflict);
        }
        var activePhoneChallenges = await dbContext.ProofChallenges
            .Where(challenge =>
                challenge.AccessFlowId == flow.Id
                && challenge.Type == ProofChallengeType.PhonePossession
                && challenge.Status == ProofChallengeStatus.Active)
            .ToListAsync(cancellationToken);
        foreach (var challenge in activePhoneChallenges)
        {
            challenge.Supersede(command.CompletedAt);
        }

        context.Complete(command.CompletedAt);
        var resultRevision = flow.Complete(
            command.ExpectedRevision,
            command.CompletedAt);
        var revision = new AccessFlowRevision(
            flow.Id,
            resultRevision,
            command.SnapshotJson,
            command.CompletedAt);
        var request = new AccessFlowRequest(
            command.Scope.IntegrationClientId,
            command.RequestId,
            flow.Id,
            AccessFlowRequestKind.Action,
            command.PayloadHash,
            resultRevision,
            command.CompletedAt,
            command.ProductSession.Id);

        dbContext.IdentitySessions.Add(command.ProductSession);
        dbContext.AccessFlowRevisions.Add(revision);
        dbContext.AccessFlowRequests.Add(request);

        // Product-session issuance, terminal state, and removal of registration authority
        // are one commit. A source session that expired or was revoked loses the race.
        if (!await TryRevokeSourceSessionAsync(
                flow,
                IdentitySessionPurpose.Registration,
                command.CompletedAt,
                cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RegistrationNotPending;
        }
        await RevokeOtherRegistrationSessionsAsync(
            flow,
            command.CompletedAt,
            cancellationToken);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.Committed;
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RevisionConflict;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey)
                || IsUniqueViolation(exception, SessionTokenUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, IdentifierValueUniqueConstraint)
                || IsUniqueViolation(exception, IdentitySchemeUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }
    }

    public async Task<AccessFlowCommitStatus> TryExpireAsync(
        ExpireAccessFlowCommand command,
        CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            cancellationToken);
        var discovered = await dbContext.AccessFlows.AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.Id == command.FlowId
                    && item.IntegrationClientId == command.Scope.IntegrationClientId
                    && item.AppEnvironmentId == command.Scope.AppEnvironmentId
                    && item.RealmId == command.Scope.RealmId,
                cancellationToken);
        if (discovered is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.FlowNotFound;
        }

        // Match the normal transition lock order before locking the flow. Expiration
        // must not deadlock a concurrent action that holds identity/session authority.
        await dbContext.Identities
            .FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {discovered.IdentityId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        await dbContext.IdentitySessions
            .FromSqlInterpolated(
                $"SELECT * FROM identity_sessions WHERE id = {discovered.SourceSessionId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        var flow = await dbContext.AccessFlows
            .FromSqlInterpolated(
                $"SELECT * FROM access_flows WHERE id = {command.FlowId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (flow is null
            || flow.IdentityId != discovered.IdentityId
            || flow.SourceSessionId != discovered.SourceSessionId
            || flow.IntegrationClientId != command.Scope.IntegrationClientId
            || flow.AppEnvironmentId != command.Scope.AppEnvironmentId
            || flow.RealmId != command.Scope.RealmId)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.FlowNotFound;
        }
        if (flow.Status != AccessFlowStatus.Active
            || flow.CurrentRevision != command.ExpectedRevision)
        {
            // Time passing is not permission to overwrite the transition that already
            // won this revision. The caller must return the durable current snapshot.
            await transaction.RollbackAsync(cancellationToken);
            return AccessFlowCommitStatus.RevisionConflict;
        }

        // Resolve in-flight reservations in the same transaction as the terminal flow
        // revision: pending requests fail, undelivered challenges fail, and an exclusive
        // confirmation reservation is released according to its own lifecycle. These
        // are local states; no already accepted provider effect is rolled back.
        var pendingRequests = await dbContext.AccessFlowRequests
            .Where(request => request.FlowId == flow.Id
                && request.Status == AccessFlowRequestStatus.PendingExternal)
            .ToListAsync(cancellationToken);
        var externalChallenges = await dbContext.ProofChallenges
            .Where(challenge => challenge.AccessFlowId == flow.Id
                && (challenge.Status == ProofChallengeStatus.PendingDelivery
                    || challenge.Status == ProofChallengeStatus.Confirming))
            .ToListAsync(cancellationToken);
        foreach (var request in pendingRequests)
        {
            request.FailExternal();
        }
        foreach (var challenge in externalChallenges)
        {
            if (challenge.Status == ProofChallengeStatus.PendingDelivery)
            {
                challenge.FailDelivery(command.ExpiredAt);
            }
            else
            {
                challenge.ReleaseConfirmation(command.ExpiredAt);
            }
        }

        var resultRevision = flow.Expire(command.ExpectedRevision, command.ExpiredAt);
        dbContext.AccessFlowRevisions.Add(new AccessFlowRevision(
            flow.Id,
            resultRevision,
            command.SnapshotJson,
            command.ExpiredAt));
        // Keep the source identity session intact. If it remains active, it may authorize
        // a new flow after this terminal revision releases the active-flow slot.

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.Committed;
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RevisionConflict;
        }
    }

    private async Task<StoredAccessFlow> ToStoredFlowAsync(
        AccessFlow flow,
        CancellationToken cancellationToken)
    {
        var snapshotJson = await dbContext.AccessFlowRevisions.AsNoTracking()
            .Where(revision => revision.FlowId == flow.Id
                && revision.Revision == flow.CurrentRevision)
            .Select(revision => revision.SnapshotJson)
            .SingleAsync(cancellationToken);
        return new StoredAccessFlow(
            flow.Id,
            flow.IdentityId,
            flow.RegistrationContextId,
            flow.SourceSessionId,
            flow.ApplicationClientId,
            flow.Status,
            flow.ProtocolVersion,
            flow.Intent,
            flow.CurrentRevision,
            flow.ExpiresAt,
            snapshotJson);
    }

    private async Task ReconcileExternalArtifactsAsync(
        Guid flowId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var pendingRequests = await dbContext.AccessFlowRequests
            .Where(request => request.FlowId == flowId
                && request.Status == AccessFlowRequestStatus.PendingExternal)
            .ToListAsync(cancellationToken);
        var conflict = await LockPhoneConflictAsync(flowId, cancellationToken);
        var changed = false;
        if (conflict is not null && conflict.ExpiresAt <= now)
        {
            dbContext.PhoneRegistrationConflicts.Remove(conflict);
            changed = true;
        }

        var externalChallenges = await dbContext.ProofChallenges
            .Where(challenge => challenge.AccessFlowId == flowId
                && (challenge.Status == ProofChallengeStatus.PendingDelivery
                    || challenge.Status == ProofChallengeStatus.Confirming))
            .ToListAsync(cancellationToken);
        // Resuming a flow must not steal a provider effect still owned by another caller.
        // Reclaim only reservations whose challenge, or request-only grace window, ended.
        if (!HasLiveReservation(pendingRequests, externalChallenges, now))
        {
            foreach (var request in pendingRequests)
            {
                request.FailExternal();
                changed = true;
            }
            foreach (var challenge in externalChallenges)
            {
                if (challenge.Status == ProofChallengeStatus.PendingDelivery)
                {
                    challenge.FailDelivery(now);
                }
                else
                {
                    challenge.ReleaseConfirmation(now);
                }
                changed = true;
            }
        }

        if (changed)
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    private async Task CloseExternalArtifactsAsync(
        Guid flowId,
        DateTimeOffset closedAt,
        CancellationToken cancellationToken)
    {
        // This closes local coordination state when the owning flow becomes terminal.
        // It cannot retract a message or request already accepted by a provider.
        var pendingRequests = await dbContext.AccessFlowRequests
            .Where(request => request.FlowId == flowId
                && request.Status == AccessFlowRequestStatus.PendingExternal)
            .ToListAsync(cancellationToken);
        var externalChallenges = await dbContext.ProofChallenges
            .Where(challenge => challenge.AccessFlowId == flowId
                && (challenge.Status == ProofChallengeStatus.PendingDelivery
                    || challenge.Status == ProofChallengeStatus.Confirming))
            .ToListAsync(cancellationToken);
        foreach (var request in pendingRequests)
        {
            request.FailExternal();
        }
        foreach (var challenge in externalChallenges)
        {
            if (challenge.Status == ProofChallengeStatus.PendingDelivery)
            {
                challenge.FailDelivery(closedAt);
            }
            else
            {
                challenge.ReleaseConfirmation(closedAt);
            }
        }
    }

    private async Task<ActiveFlowLoad> LoadActiveFlowAsync(
        AccessFlowScope scope,
        Guid flowId,
        int expectedRevision,
        DateTimeOffset now,
        CancellationToken cancellationToken,
        Guid? currentRequestId = null,
        bool continuePendingRequest = false,
        params Guid[] additionalIdentityIds)
    {
        // Preliminary discovery supplies stable lock keys only. The method then locks
        // all involved identities in deterministic order, the source session, and the
        // flow before treating any revision or authority fact as current.
        var discovered = await dbContext.AccessFlows.AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.Id == flowId
                    && item.IntegrationClientId == scope.IntegrationClientId
                    && item.AppEnvironmentId == scope.AppEnvironmentId
                    && item.RealmId == scope.RealmId,
                cancellationToken);
        if (discovered is null)
        {
            return new ActiveFlowLoad(
                AccessFlowCommitStatus.FlowNotFound,
                null,
                null,
                null);
        }

        var identityIds = additionalIdentityIds
            .Append(discovered.IdentityId)
            .Where(identityId => identityId != Guid.Empty)
            .Distinct()
            .OrderBy(identityId => identityId)
            .ToArray();
        var lockedIdentity = false;
        foreach (var identityId in identityIds)
        {
            var identity = await dbContext.Identities
                .FromSqlInterpolated(
                    $"SELECT * FROM identities WHERE id = {identityId} FOR UPDATE")
                .AsNoTracking()
                .SingleOrDefaultAsync(cancellationToken);
            if (identityId == discovered.IdentityId)
            {
                lockedIdentity = identity is not null
                    && identity.RealmId == discovered.RealmId
                    && identity.LifecycleState == IdentityLifecycleState.Active;
            }
        }

        var sourceSession = await dbContext.IdentitySessions
            .FromSqlInterpolated(
                $"SELECT * FROM identity_sessions WHERE id = {discovered.SourceSessionId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        var flow = await dbContext.AccessFlows
            .FromSqlInterpolated(
                $"SELECT * FROM access_flows WHERE id = {flowId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (flow is null
            || flow.IntegrationClientId != scope.IntegrationClientId
            || flow.AppEnvironmentId != scope.AppEnvironmentId
            || flow.RealmId != scope.RealmId
            || flow.IdentityId != discovered.IdentityId
            || flow.SourceSessionId != discovered.SourceSessionId)
        {
            return new ActiveFlowLoad(
                AccessFlowCommitStatus.FlowNotFound,
                null,
                null,
                null);
        }

        AccessFlowRequest? currentRequest = null;
        if (currentRequestId is not null)
        {
            currentRequest = await dbContext.AccessFlowRequests
                .FromSqlInterpolated(
                    $"SELECT * FROM access_flow_requests WHERE integration_client_id = {scope.IntegrationClientId} AND request_id = {currentRequestId.Value} FOR UPDATE")
                .SingleOrDefaultAsync(cancellationToken);
            if (currentRequest is not null
                && continuePendingRequest
                && currentRequest.FlowId == flow.Id
                && currentRequest.Status == AccessFlowRequestStatus.ExternalFailed)
            {
                // A failed reservation is terminal for this request id. The caller must
                // use a new id rather than repeat an external effect ambiguously.
                return new ActiveFlowLoad(
                    AccessFlowCommitStatus.ExternalOperationFailed,
                    null,
                    null,
                    null);
            }
            if (currentRequest is not null
                && (!continuePendingRequest
                    || currentRequest.FlowId != flow.Id
                    || currentRequest.Status != AccessFlowRequestStatus.PendingExternal))
            {
                // Only a finalizer may continue its own exact pending reservation. Every
                // other existing request id is handled by durable replay semantics.
                return new ActiveFlowLoad(
                    AccessFlowCommitStatus.RequestAlreadyExists,
                    null,
                    null,
                    null);
            }
        }

        if (flow.Status != AccessFlowStatus.Active
            || flow.CurrentRevision != expectedRevision
            || flow.ExpiresAt <= now)
        {
            return new ActiveFlowLoad(
                AccessFlowCommitStatus.RevisionConflict,
                null,
                null,
                null);
        }

        var expectedPurpose = flow.Intent == AccessFlowIntent.ContinueRegistration
            ? IdentitySessionPurpose.Registration
            : IdentitySessionPurpose.Product;
        var sourceSessionIsActive = sourceSession is not null
            && sourceSession.IdentityId == flow.IdentityId
            && sourceSession.AppEnvironmentId == flow.AppEnvironmentId
            && sourceSession.Purpose == expectedPurpose
            && sourceSession.RevokedAt is null
            && sourceSession.ExpiresAt > now;
        if (!lockedIdentity || !sourceSessionIsActive)
        {
            return new ActiveFlowLoad(
                flow.Intent == AccessFlowIntent.ContinueRegistration
                    ? AccessFlowCommitStatus.RegistrationNotPending
                    : AccessFlowCommitStatus.SourceSessionInactive,
                null,
                null,
                null);
        }

        var pendingRequests = await dbContext.AccessFlowRequests
            .Where(request => request.FlowId == flow.Id
                && request.Status == AccessFlowRequestStatus.PendingExternal
                && (currentRequestId == null
                    || request.RequestId != currentRequestId.Value))
            .ToListAsync(cancellationToken);
        if (pendingRequests.Count > 0)
        {
            var externalChallenges = await dbContext.ProofChallenges
                .Where(challenge => challenge.AccessFlowId == flow.Id
                    && (challenge.Status == ProofChallengeStatus.PendingDelivery
                        || challenge.Status == ProofChallengeStatus.Confirming))
                .ToListAsync(cancellationToken);
            if (HasLiveReservation(pendingRequests, externalChallenges, now))
            {
                // A different request still owns an effect that may be executing or
                // awaiting finalization. Do not allow a new action to duplicate it.
                return new ActiveFlowLoad(
                    AccessFlowCommitStatus.ExternalOperationPending,
                    null,
                    null,
                    null);
            }

            // The owner disappeared beyond its recoverable lifetime. Close the orphaned
            // local state before allowing this new transition to proceed.
            foreach (var challenge in externalChallenges)
            {
                if (challenge.Status == ProofChallengeStatus.PendingDelivery)
                {
                    challenge.FailDelivery(now);
                }
                else
                {
                    challenge.ReleaseConfirmation(now);
                }
            }
            foreach (var request in pendingRequests)
            {
                request.FailExternal();
            }

            await dbContext.SaveChangesAsync(cancellationToken);
        }

        if (flow.Intent == AccessFlowIntent.ManagePhone)
        {
            return new ActiveFlowLoad(
                AccessFlowCommitStatus.Committed,
                flow,
                null,
                currentRequest);
        }

        if (flow.RegistrationContextId is null)
        {
            return new ActiveFlowLoad(
                AccessFlowCommitStatus.RegistrationNotPending,
                null,
                null,
                null);
        }

        var context = await dbContext.RegistrationContexts.SingleOrDefaultAsync(
            item => item.Id == flow.RegistrationContextId.Value
                && item.IdentityId == flow.IdentityId
                && item.AppEnvironmentId == flow.AppEnvironmentId
                && item.Status == RegistrationContextStatus.Open,
            cancellationToken);
        return context is null
            ? new ActiveFlowLoad(
                AccessFlowCommitStatus.RegistrationNotPending,
                null,
                null,
                null)
            : new ActiveFlowLoad(
                AccessFlowCommitStatus.Committed,
                flow,
                context,
                currentRequest);
    }

    // Locks identity, source session and flow in the shared order so compensation
    // never runs against a flow that another transaction is finalizing.
    private async Task<AccessFlow?> LockReservedFlowAsync(
        AccessFlowScope scope,
        Guid flowId,
        CancellationToken cancellationToken)
    {
        var discovered = await dbContext.AccessFlows.AsNoTracking()
            .SingleOrDefaultAsync(
                flow => flow.Id == flowId
                    && flow.IntegrationClientId == scope.IntegrationClientId
                    && flow.AppEnvironmentId == scope.AppEnvironmentId
                    && flow.RealmId == scope.RealmId,
                cancellationToken);
        if (discovered is null)
        {
            return null;
        }

        await dbContext.Identities
            .FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {discovered.IdentityId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        await dbContext.IdentitySessions
            .FromSqlInterpolated(
                $"SELECT * FROM identity_sessions WHERE id = {discovered.SourceSessionId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        var flow = await dbContext.AccessFlows
            .FromSqlInterpolated(
                $"SELECT * FROM access_flows WHERE id = {flowId} FOR UPDATE")
            .AsNoTracking()
            .SingleOrDefaultAsync(cancellationToken);
        return flow is null
            || flow.IdentityId != discovered.IdentityId
            || flow.SourceSessionId != discovered.SourceSessionId
            || flow.IntegrationClientId != scope.IntegrationClientId
            || flow.AppEnvironmentId != scope.AppEnvironmentId
            || flow.RealmId != scope.RealmId
                ? null
                : flow;
    }

    private Task<AccessFlowRequest?> LockRequestAsync(
        AccessFlowScope scope,
        Guid requestId,
        CancellationToken cancellationToken) =>
        dbContext.AccessFlowRequests
            .FromSqlInterpolated(
                $"SELECT * FROM access_flow_requests WHERE integration_client_id = {scope.IntegrationClientId} AND request_id = {requestId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);

    private async Task<AccessFlowRequest?> LockPendingRequestAsync(
        AccessFlowScope scope,
        Guid flowId,
        Guid requestId,
        CancellationToken cancellationToken)
    {
        var flow = await LockReservedFlowAsync(scope, flowId, cancellationToken);
        if (flow is null)
        {
            return null;
        }

        var request = await LockRequestAsync(scope, requestId, cancellationToken);
        return request is null || request.FlowId != flow.Id ? null : request;
    }

    private async Task<ExternalReservationLoad?> LoadExternalReservationAsync(
        AccessFlowScope scope,
        Guid flowId,
        Guid requestId,
        Guid challengeId,
        CancellationToken cancellationToken)
    {
        var flow = await LockReservedFlowAsync(scope, flowId, cancellationToken);
        if (flow is null)
        {
            return null;
        }

        var request = await LockRequestAsync(scope, requestId, cancellationToken);
        var challenge = await dbContext.ProofChallenges
            .FromSqlInterpolated(
                $"SELECT * FROM proof_challenges WHERE id = {challengeId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        return request is null
            || request.FlowId != flow.Id
            || challenge is null
            || challenge.AccessFlowId != flow.Id
            || challenge.IdentityId != flow.IdentityId
                ? null
                : new ExternalReservationLoad(request, challenge);
    }

    // Locks and validates everything recoverPreviousIdentity depends on. Reserve
    // and finalize share it so the e-mail is only sent for a request that could
    // have committed at reservation time. The proof belongs to the provisional flow
    // identity while its subject is the exact phone still owned by the previous identity;
    // that cross-reference proves possession without merging the two histories.
    private async Task<PreviousIdentityRecoveryLoad> LockPreviousIdentityRecoveryAsync(
        AccessFlow flow,
        Guid expectedPreviousIdentityId,
        Guid expectedPhoneIdentifierId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (flow.Intent != AccessFlowIntent.ContinueRegistration)
        {
            return new PreviousIdentityRecoveryLoad(
                AccessFlowCommitStatus.RegistrationNotPending);
        }

        var conflict = await LockPhoneConflictAsync(flow.Id, cancellationToken);
        // Failed e-mail guesses are relevant only to explicit phone transfer. Recovery
        // never trusts caller-supplied e-mail: the locked previous identity selects its
        // own canonical recovery address, and the mailbox remains the final proof.
        if (conflict is null
            || conflict.ExpiresAt <= now
            || conflict.PreviousIdentityId != expectedPreviousIdentityId
            || conflict.ConflictingPhoneIdentifierId != expectedPhoneIdentifierId)
        {
            return new PreviousIdentityRecoveryLoad(
                AccessFlowCommitStatus.PhoneConflictNotPending);
        }

        var currentIdentity = await dbContext.Identities
            .FromSqlInterpolated(
                $"SELECT * FROM identities WHERE id = {flow.IdentityId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        var previousIdentityIsActive = await dbContext.Identities.AnyAsync(
            identity => identity.Id == conflict.PreviousIdentityId
                && identity.RealmId == flow.RealmId
                && identity.LifecycleState == IdentityLifecycleState.Active,
            cancellationToken);
        var phone = await dbContext.IdentityIdentifiers
            .FromSqlInterpolated(
                $"SELECT * FROM identity_identifiers WHERE id = {conflict.ConflictingPhoneIdentifierId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        var hasPhoneProof = await dbContext.IdentityProofs.AnyAsync(
            proof => proof.AccessFlowId == flow.Id
                && proof.IdentityId == flow.IdentityId
                && proof.Type == ProofChallengeType.PhonePossession
                && proof.SubjectIdentifierId == conflict.ConflictingPhoneIdentifierId,
            cancellationToken);
        if (currentIdentity is null
            || currentIdentity.LifecycleState != IdentityLifecycleState.Active
            || !previousIdentityIsActive
            || phone is null
            || phone.IdentityId != conflict.PreviousIdentityId
            || phone.RealmId != flow.RealmId
            || phone.Scheme != IdentifierScheme.Phone
            || phone.VerifiedAt is null
            || !hasPhoneProof)
        {
            return new PreviousIdentityRecoveryLoad(
                AccessFlowCommitStatus.PhoneConflictNotPending);
        }

        return new PreviousIdentityRecoveryLoad(
            AccessFlowCommitStatus.Committed,
            conflict,
            currentIdentity);
    }

    // A reservation stays alive while its proof challenge can still be finalized.
    // E-mail recovery has no challenge row, so its request-only reservation uses the
    // short grace window above to balance duplicate prevention with crash recovery.
    private static bool HasLiveReservation(
        IReadOnlyCollection<AccessFlowRequest> pendingRequests,
        IReadOnlyCollection<ProofChallenge> externalChallenges,
        DateTimeOffset now) =>
        pendingRequests.Count > 0
        && (externalChallenges.Count > 0
            ? externalChallenges.Any(challenge => challenge.ExpiresAt > now)
            : pendingRequests.Any(request =>
                request.CreatedAt.Add(RequestOnlyReservationLifetime) > now));

    private async Task<AccessFlowCommitStatus> SaveCommitAsync(
        IDbContextTransaction transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.Committed;
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RevisionConflict;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
    }

    private async Task<AccessFlowCommitStatus> SavePhoneCommitAsync(
        IDbContextTransaction transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AccessFlowCommitStatus.Committed;
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RevisionConflict;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, RequestPrimaryKey)
                || IsUniqueViolation(exception, SessionTokenUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.RequestAlreadyExists;
        }
        catch (DbUpdateException exception)
            when (IsUniqueViolation(exception, IdentifierValueUniqueConstraint)
                || IsUniqueViolation(exception, IdentitySchemeUniqueConstraint))
        {
            await transaction.RollbackAsync(cancellationToken);
            dbContext.ChangeTracker.Clear();
            return AccessFlowCommitStatus.PhoneOwnershipChanged;
        }
    }

    private async Task<bool> TryRevokeSourceSessionAsync(
        AccessFlow flow,
        IdentitySessionPurpose expectedPurpose,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken)
    {
        var revoked = await dbContext.IdentitySessions
            .Where(session => session.Id == flow.SourceSessionId
                && session.IdentityId == flow.IdentityId
                && session.AppEnvironmentId == flow.AppEnvironmentId
                && session.Purpose == expectedPurpose
                && session.RevokedAt == null
                && session.ExpiresAt > revokedAt)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    session => session.RevokedAt,
                    revokedAt),
                cancellationToken);
        return revoked == 1;
    }

    // Registration completion closes every other registration-purpose path for this
    // identity and environment; it does not revoke unrelated product sessions.
    private Task RevokeOtherRegistrationSessionsAsync(
        AccessFlow flow,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken) =>
        dbContext.IdentitySessions
            .Where(session => session.Id != flow.SourceSessionId
                && session.IdentityId == flow.IdentityId
                && session.AppEnvironmentId == flow.AppEnvironmentId
                && session.Purpose == IdentitySessionPurpose.Registration
                && session.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    session => session.RevokedAt,
                    revokedAt),
                cancellationToken);

    // Deleting a replaced phone first removes conflict dependents and detaches historical
    // proof subjects. The proof event remains, but no longer points at a deleted identifier.
    private async Task DeleteOtherPhoneIdentifiersAsync(
        Guid identityId,
        Guid retainedIdentifierId,
        CancellationToken cancellationToken)
    {
        var identifiers = await dbContext.IdentityIdentifiers
            .Where(identifier => identifier.IdentityId == identityId
                && identifier.Scheme == IdentifierScheme.Phone
                && identifier.Id != retainedIdentifierId)
            .Select(identifier => identifier.Id)
            .ToListAsync(cancellationToken);
        if (identifiers.Count == 0)
        {
            return;
        }

        await dbContext.PhoneRegistrationConflicts
            .Where(conflict => identifiers.Contains(
                conflict.ConflictingPhoneIdentifierId))
            .ExecuteDeleteAsync(cancellationToken);
        await dbContext.IdentityProofs
            .Where(proof => proof.SubjectIdentifierId != null
                && identifiers.Contains(proof.SubjectIdentifierId.Value))
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    proof => proof.SubjectIdentifierId,
                    (Guid?)null),
                cancellationToken);
        await dbContext.IdentityIdentifiers
            .Where(identifier => identifiers.Contains(identifier.Id))
            .ExecuteDeleteAsync(cancellationToken);
    }

    // Contact ownership changes invalidate recovery authority derived from the earlier
    // identity snapshot. Invalidation is committed with the ownership-changing action.
    private async Task InvalidateRecoveryArtifactsAsync(
        IEnumerable<Guid> identityIds,
        DateTimeOffset invalidatedAt,
        CancellationToken cancellationToken)
    {
        var ids = identityIds
            .Where(identityId => identityId != Guid.Empty)
            .Distinct()
            .ToArray();
        if (ids.Length == 0)
        {
            return;
        }

        await dbContext.PasswordResetTokens
            .Where(token => ids.Contains(token.IdentityId)
                && token.UsedAt == null
                && token.ExpiresAt > invalidatedAt)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(token => token.UsedAt, invalidatedAt),
                cancellationToken);
        await dbContext.PhonePasswordResetChallenges
            .Where(challenge => ids.Contains(challenge.IdentityId)
                && (challenge.Status
                        == PhonePasswordResetChallengeStatus.PendingDelivery
                    || challenge.Status == PhonePasswordResetChallengeStatus.Active
                    || challenge.Status
                        == PhonePasswordResetChallengeStatus.Confirming))
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(
                        challenge => challenge.Status,
                        PhonePasswordResetChallengeStatus.Superseded)
                    .SetProperty(challenge => challenge.CompletedAt, invalidatedAt),
                cancellationToken);
    }

    private Task<PhoneRegistrationConflict?> LockPhoneConflictAsync(
        Guid flowId,
        CancellationToken cancellationToken) =>
        dbContext.PhoneRegistrationConflicts
            .FromSqlInterpolated(
                $"SELECT * FROM phone_registration_conflicts WHERE access_flow_id = {flowId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);

    private async Task<LockedPhoneIdentifier?> LockPhoneOwnerAsync(
        Guid realmId,
        string normalizedPhone,
        PhoneIdentifierOwner? expectedOwner,
        CancellationToken cancellationToken)
    {
        var identifier = await dbContext.IdentityIdentifiers
            .FromSqlInterpolated(
                $"SELECT * FROM identity_identifiers WHERE realm_id = {realmId} AND scheme = {IdentifierScheme.Phone} AND normalized_value = {normalizedPhone} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        if (identifier is null)
        {
            return null;
        }

        var ownerIsActive = true;
        string? email = null;
        if (expectedOwner is not null
            && expectedOwner.IdentityId == identifier.IdentityId)
        {
            ownerIsActive = await dbContext.Identities.AsNoTracking().AnyAsync(
                identity => identity.Id == identifier.IdentityId
                    && identity.RealmId == realmId
                    && identity.LifecycleState == IdentityLifecycleState.Active,
                cancellationToken);
            if (ownerIsActive)
            {
                email = await dbContext.IdentityIdentifiers.AsNoTracking()
                    .Where(item => item.IdentityId == identifier.IdentityId
                        && item.RealmId == realmId
                        && item.Scheme == IdentifierScheme.Email)
                    .Select(item => item.NormalizedValue)
                    .SingleOrDefaultAsync(cancellationToken);
            }
        }

        return new LockedPhoneIdentifier(
            identifier,
            new PhoneIdentifierOwner(
                identifier.Id,
                identifier.IdentityId,
                email,
                identifier.VerifiedAt is not null),
            ownerIsActive);
    }

    private async Task AddDataSubjectAsync(
        AccessFlow flow,
        Guid identityId,
        DateTimeOffset createdAt,
        CancellationToken cancellationToken)
    {
        var tracked = dbContext.ChangeTracker.Entries<AccessFlowDataSubject>()
            .Any(entry => entry.Entity.FlowId == flow.Id
                && entry.Entity.IdentityId == identityId);
        if (tracked || await dbContext.AccessFlowDataSubjects.AsNoTracking().AnyAsync(
                subject => subject.FlowId == flow.Id
                    && subject.IdentityId == identityId,
                cancellationToken))
        {
            return;
        }

        dbContext.AccessFlowDataSubjects.Add(new AccessFlowDataSubject(
            flow.RealmId,
            flow.Id,
            identityId,
            createdAt));
    }

    private static bool SameOwner(
        PhoneIdentifierOwner? actual,
        PhoneIdentifierOwner? expected) =>
        actual is null && expected is null
        || actual is not null
        && expected is not null
        && actual.IdentifierId == expected.IdentifierId
        && actual.IdentityId == expected.IdentityId
        && string.Equals(actual.Email, expected.Email, StringComparison.Ordinal)
        && actual.IsVerified == expected.IsVerified;

    private static bool PayloadMatches(byte[] stored, byte[] presented) =>
        stored.Length == presented.Length
        && CryptographicOperations.FixedTimeEquals(stored, presented);

    private Task<bool> RequestExistsAsync(
        Guid integrationClientId,
        Guid requestId,
        CancellationToken cancellationToken) =>
        dbContext.AccessFlowRequests.AsNoTracking().AnyAsync(
            request => request.IntegrationClientId == integrationClientId
                && request.RequestId == requestId,
            cancellationToken);

    private static bool IsUniqueViolation(DbUpdateException exception, string constraint) =>
        exception.InnerException is PostgresException
        {
            SqlState: PostgresErrorCodes.UniqueViolation,
            ConstraintName: var constraintName,
        }
        && string.Equals(constraintName, constraint, StringComparison.Ordinal);

    private sealed record ActiveFlowLoad(
        AccessFlowCommitStatus Status,
        AccessFlow? Flow,
        RegistrationContext? Context,
        AccessFlowRequest? Request);

    private sealed record ExternalReservationLoad(
        AccessFlowRequest Request,
        ProofChallenge Challenge);

    private sealed record PreviousIdentityRecoveryLoad(
        AccessFlowCommitStatus Status,
        PhoneRegistrationConflict? Conflict = null,
        Identity? CurrentIdentity = null);

    private sealed record LockedPhoneIdentifier(
        IdentityIdentifier Identifier,
        PhoneIdentifierOwner Owner,
        bool OwnerIsActive);
}
