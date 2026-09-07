using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Bullgate.Access.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps the current AccessFlow state and its fixed tenancy, client, identity, source-
/// session, intent, revision, and lifetime boundaries.
/// </summary>
internal sealed class AccessFlowConfiguration : IEntityTypeConfiguration<AccessFlow>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<AccessFlow> builder)
    {
        builder.ToTable(
            "access_flows",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_access_flows_protocol_version",
                    "protocol_version > 0");
                table.HasCheckConstraint(
                    "ck_access_flows_current_revision",
                    "current_revision > 0");
                table.HasCheckConstraint(
                    "ck_access_flows_expiration",
                    "expires_at > created_at");
                table.HasCheckConstraint(
                    "ck_access_flows_updated_at",
                    "updated_at >= created_at");
                table.HasCheckConstraint(
                    "ck_access_flows_completion",
                    "(status = 'Active' AND completed_at IS NULL) "
                    + "OR (status IN ('Completed', 'Expired', 'Cancelled') "
                    + "AND completed_at IS NOT NULL)");
                table.HasCheckConstraint(
                    "ck_access_flows_intent",
                    "intent IN ('ContinueRegistration', 'ManagePhone')");
                table.HasCheckConstraint(
                    "ck_access_flows_intent_context",
                    "(intent = 'ContinueRegistration' AND registration_context_id IS NOT NULL) "
                    + "OR (intent = 'ManagePhone' AND registration_context_id IS NULL)");
                table.HasCheckConstraint(
                    "ck_access_flows_status",
                    "status IN ('Active', 'Completed', 'Expired', 'Cancelled')");
            });
        builder.HasKey(flow => flow.Id).HasName("pk_access_flows");
        builder.Property(flow => flow.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(flow => flow.RealmId).HasColumnName("realm_id");
        builder.Property(flow => flow.AppEnvironmentId)
            .HasColumnName("app_environment_id");
        builder.Property(flow => flow.IntegrationClientId)
            .HasColumnName("integration_client_id");
        builder.Property(flow => flow.ApplicationClientId)
            .HasColumnName("application_client_id");
        builder.Property(flow => flow.IdentityId).HasColumnName("identity_id");
        builder.Property(flow => flow.RegistrationContextId)
            .HasColumnName("registration_context_id");
        builder.Property(flow => flow.SourceSessionId).HasColumnName("source_session_id");
        builder.Property(flow => flow.ProtocolVersion).HasColumnName("protocol_version");
        builder.Property(flow => flow.Intent)
            .HasColumnName("intent")
            .HasConversion<string>()
            .HasMaxLength(32)
            .IsRequired();
        builder.Property(flow => flow.Status)
            .HasColumnName("status")
            .HasConversion<string>()
            .HasMaxLength(16)
            .IsRequired();
        builder.Property(flow => flow.CurrentRevision)
            .HasColumnName("current_revision")
            .IsConcurrencyToken();
        // EF optimistic concurrency complements the service's expectedRevision check;
        // a write based on stale tracked state must not overwrite a newer transition.
        builder.Property(flow => flow.CreatedAt).HasColumnName("created_at");
        builder.Property(flow => flow.UpdatedAt).HasColumnName("updated_at");
        builder.Property(flow => flow.ExpiresAt).HasColumnName("expires_at");
        builder.Property(flow => flow.CompletedAt).HasColumnName("completed_at");
        builder.HasIndex(flow => new { flow.AppEnvironmentId, flow.Status })
            .HasDatabaseName("ix_access_flows_environment_status");
        builder.HasIndex(flow => new { flow.IdentityId, flow.AppEnvironmentId })
            .HasDatabaseName("ix_access_flows_identity_environment");
        builder.HasIndex(flow => flow.IntegrationClientId)
            .HasDatabaseName("ix_access_flows_integration_client");
        builder.HasIndex(flow => flow.ApplicationClientId)
            .HasDatabaseName("ix_access_flows_application_client");
        builder.HasIndex(flow => new { flow.RealmId, flow.IdentityId })
            .HasDatabaseName("ix_access_flows_realm_identity");
        builder.HasIndex(flow => flow.RegistrationContextId)
            .HasDatabaseName("ix_access_flows_registration_context");
        builder.HasIndex(flow => flow.SourceSessionId)
            .HasDatabaseName("ix_access_flows_source_session");
        builder.HasIndex(flow => new { flow.SourceSessionId, flow.Intent })
            .IsUnique()
            .HasFilter("status = 'Active'")
            .HasDatabaseName("ux_access_flows_active_source_session_intent");
        // Terminal history remains available, but one source session cannot drive two
        // simultaneous active journeys with the same intent.
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(flow => new { flow.RealmId, flow.IdentityId })
            .HasPrincipalKey(identity => new { identity.RealmId, identity.Id })
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flows_identities");
        builder.HasOne<AppEnvironment>()
            .WithMany()
            .HasForeignKey(flow => flow.AppEnvironmentId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flows_app_environments");
        builder.HasOne<IntegrationClient>()
            .WithMany()
            .HasForeignKey(flow => flow.IntegrationClientId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flows_integration_clients");
        builder.HasOne<ApplicationClient>()
            .WithMany()
            .HasForeignKey(flow => flow.ApplicationClientId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flows_application_clients");
        builder.HasOne<RegistrationContext>()
            .WithMany()
            .HasForeignKey(flow => flow.RegistrationContextId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flows_registration_contexts");
        builder.HasOne<IdentitySession>()
            .WithMany()
            .HasForeignKey(flow => flow.SourceSessionId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flows_source_sessions");
    }
}

/// <summary>
/// Maps immutable, versioned response snapshots used for exact replay and stale-client
/// conflict recovery.
/// </summary>
internal sealed class AccessFlowRevisionConfiguration
    : IEntityTypeConfiguration<AccessFlowRevision>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<AccessFlowRevision> builder)
    {
        builder.ToTable(
            "access_flow_revisions",
            table => table.HasCheckConstraint(
                "ck_access_flow_revisions_revision",
                "revision > 0"));
        builder.HasKey(revision => new { revision.FlowId, revision.Revision })
            .HasName("pk_access_flow_revisions");
        builder.Property(revision => revision.FlowId).HasColumnName("flow_id");
        builder.Property(revision => revision.Revision).HasColumnName("revision");
        builder.Property(revision => revision.SnapshotJson)
            .HasColumnName("snapshot")
            .HasColumnType("jsonb")
            .IsRequired();
        builder.Property(revision => revision.CreatedAt).HasColumnName("created_at");
        builder.HasOne<AccessFlow>()
            .WithMany()
            .HasForeignKey(revision => revision.FlowId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_access_flow_revisions_flows");
    }
}

/// <summary>
/// Maps an integration-client-scoped idempotency request to its payload hash, external-
/// effect state, exact result revision, and optional issued session.
/// </summary>
internal sealed class AccessFlowRequestConfiguration
    : IEntityTypeConfiguration<AccessFlowRequest>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<AccessFlowRequest> builder)
    {
        builder.ToTable(
            "access_flow_requests",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_access_flow_requests_payload_hash_length",
                    $"octet_length(payload_hash) = {AccessFlowLimits.PayloadHashLength}");
                table.HasCheckConstraint(
                    "ck_access_flow_requests_result_revision",
                    "result_revision IS NULL OR result_revision > 0");
                table.HasCheckConstraint(
                    "ck_access_flow_requests_kind",
                    "kind IN ('Start', 'Action')");
                table.HasCheckConstraint(
                    "ck_access_flow_requests_status",
                    "status IN ('PendingExternal', 'Committed', 'ExternalFailed')");
                table.HasCheckConstraint(
                    "ck_access_flow_requests_completion",
                    "(status = 'Committed' AND result_revision IS NOT NULL) "
                    + "OR (status IN ('PendingExternal', 'ExternalFailed') "
                    + "AND result_revision IS NULL AND issued_session_id IS NULL)");
            });
        builder.HasKey(request => new
        {
            request.IntegrationClientId,
            request.RequestId,
        })
            .HasName("pk_access_flow_requests");
        // Request ids are intentionally reusable by another integration client. The
        // authenticated client id is part of both idempotency identity and ownership.
        builder.Property(request => request.IntegrationClientId)
            .HasColumnName("integration_client_id");
        builder.Property(request => request.RequestId).HasColumnName("request_id");
        builder.Property(request => request.FlowId).HasColumnName("flow_id");
        builder.Property(request => request.Kind)
            .HasColumnName("kind")
            .HasConversion<string>()
            .HasMaxLength(16)
            .IsRequired();
        builder.Property(request => request.Status)
            .HasColumnName("status")
            .HasConversion<string>()
            .HasMaxLength(24)
            .IsRequired();
        builder.Property(request => request.PayloadHash)
            .HasColumnName("payload_hash")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(request => request.ResultRevision)
            .HasColumnName("result_revision");
        builder.Property(request => request.CreatedAt).HasColumnName("created_at");
        builder.Property(request => request.IssuedSessionId)
            .HasColumnName("issued_session_id");
        builder.HasIndex(request => new { request.FlowId, request.ResultRevision })
            .HasDatabaseName("ix_access_flow_requests_flow_revision");
        builder.HasIndex(request => request.FlowId)
            .IsUnique()
            .HasFilter("status = 'PendingExternal'")
            .HasDatabaseName("ux_access_flow_requests_pending_external_flow");
        // Only one external effect may be reserved for a flow at a time; otherwise two
        // deliveries could both be valid while neither request can replay deterministically.
        builder.HasIndex(request => request.IssuedSessionId)
            .HasDatabaseName("ix_access_flow_requests_issued_session");
        builder.HasOne<IntegrationClient>()
            .WithMany()
            .HasForeignKey(request => request.IntegrationClientId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flow_requests_integration_clients");
        builder.HasOne<AccessFlow>()
            .WithMany()
            .HasForeignKey(request => request.FlowId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_access_flow_requests_flows");
        builder.HasOne<AccessFlowRevision>()
            .WithMany()
            .HasForeignKey(request => new
            {
                request.FlowId,
                request.ResultRevision,
            })
            .HasPrincipalKey(revision => new
            {
                revision.FlowId,
                revision.Revision,
            })
            // A committed request references the exact stored snapshot it returned,
            // not whichever revision happens to be current during a later retry.
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flow_requests_revisions");
        builder.HasOne<IdentitySession>()
            .WithMany()
            .HasForeignKey(request => request.IssuedSessionId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flow_requests_issued_sessions");
    }
}

/// <summary>
/// Maps append-only erasure reachability from a flow to every identity whose personal
/// data may occur in its historical snapshots.
/// </summary>
/// <remarks>
/// The flow side cascades because erasing a flow must remove its reachability metadata.
/// The identity side restricts direct deletion so application code must first follow
/// every link and delete the complete flow graph. This asymmetric relationship prevents
/// a database cascade from either leaving flow history behind or deleting another
/// identity that happens to share the flow.
/// </remarks>
internal sealed class AccessFlowDataSubjectConfiguration
    : IEntityTypeConfiguration<AccessFlowDataSubject>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<AccessFlowDataSubject> builder)
    {
        builder.ToTable("access_flow_data_subjects");
        builder.HasKey(subject => new { subject.FlowId, subject.IdentityId })
            .HasName("pk_access_flow_data_subjects");
        builder.Property(subject => subject.RealmId).HasColumnName("realm_id");
        builder.Property(subject => subject.FlowId).HasColumnName("flow_id");
        builder.Property(subject => subject.IdentityId).HasColumnName("identity_id");
        builder.Property(subject => subject.CreatedAt).HasColumnName("created_at");
        builder.HasIndex(subject => new
        {
            subject.RealmId,
            subject.IdentityId,
            subject.FlowId,
        })
            .HasDatabaseName("ix_access_flow_data_subjects_realm_identity_flow");
        builder.HasOne<AccessFlow>()
            .WithMany()
            .HasForeignKey(subject => subject.FlowId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_access_flow_data_subjects_flows");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(subject => new { subject.RealmId, subject.IdentityId })
            .HasPrincipalKey(identity => new { identity.RealmId, identity.Id })
            // Restrict identity deletion until the deletion service follows this link
            // and removes the complete flow graph (ACCESS-016).
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_access_flow_data_subjects_identities");
    }
}
