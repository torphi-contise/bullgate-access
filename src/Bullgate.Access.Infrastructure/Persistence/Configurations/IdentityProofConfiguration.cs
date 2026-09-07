using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Bullgate.Access.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps proof challenges and enforces attempt, lifetime, completion, and single-open-
/// challenge invariants in PostgreSQL.
/// </summary>
internal sealed class ProofChallengeConfiguration
    : IEntityTypeConfiguration<ProofChallenge>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<ProofChallenge> builder)
    {
        builder.ToTable(
            "proof_challenges",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_proof_challenges_attempts",
                    "attempts >= 0 AND attempts <= max_attempts AND max_attempts > 0");
                table.HasCheckConstraint(
                    "ck_proof_challenges_expiration",
                    "expires_at > created_at AND resend_available_at >= created_at");
                table.HasCheckConstraint(
                    "ck_proof_challenges_completion",
                    "(status IN ('PendingDelivery', 'Active', 'Confirming') "
                    + "AND completed_at IS NULL) "
                    + "OR (status IN ('DeliveryFailed', 'Verified', 'Superseded', 'Exhausted') "
                    + "AND completed_at IS NOT NULL)");
                table.HasCheckConstraint(
                    "ck_proof_challenges_secret_hash_length",
                    $"octet_length(secret_hash) = {IdentityLimits.SessionTokenHashLength}");
            });
        builder.HasKey(challenge => challenge.Id).HasName("pk_proof_challenges");
        builder.Property(challenge => challenge.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();
        builder.Property(challenge => challenge.AccessFlowId)
            .HasColumnName("access_flow_id");
        builder.Property(challenge => challenge.IdentityId)
            .HasColumnName("identity_id");
        builder.Property(challenge => challenge.Type)
            .HasColumnName("type")
            .HasConversion<string>()
            .HasMaxLength(32)
            .IsRequired();
        builder.Property(challenge => challenge.Channel)
            .HasColumnName("channel")
            .HasConversion<string>()
            .HasMaxLength(16)
            .IsRequired();
        builder.Property(challenge => challenge.DestinationScheme)
            .HasColumnName("destination_scheme")
            .HasMaxLength(IdentityLimits.IdentifierSchemeMaxLength)
            .IsRequired();
        builder.Property(challenge => challenge.DestinationValue)
            .HasColumnName("destination_value")
            .HasMaxLength(IdentityLimits.IdentifierValueMaxLength)
            .IsRequired();
        builder.Property(challenge => challenge.SecretHash)
            .HasColumnName("secret_hash")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(challenge => challenge.ProviderReference)
            .HasColumnName("provider_reference")
            .HasMaxLength(IdentityLimits.ProviderReferenceMaxLength);
        builder.Property(challenge => challenge.Status)
            .HasColumnName("status")
            .HasConversion<string>()
            .HasMaxLength(16)
            .IsRequired();
        builder.Property(challenge => challenge.Attempts).HasColumnName("attempts");
        builder.Property(challenge => challenge.MaxAttempts).HasColumnName("max_attempts");
        builder.Property(challenge => challenge.CreatedAt).HasColumnName("created_at");
        builder.Property(challenge => challenge.ExpiresAt).HasColumnName("expires_at");
        builder.Property(challenge => challenge.ResendAvailableAt)
            .HasColumnName("resend_available_at");
        builder.Property(challenge => challenge.CompletedAt).HasColumnName("completed_at");
        builder.HasIndex(challenge => new
        {
            challenge.AccessFlowId,
            challenge.Type,
        }, "IX_ProofChallenges_AccessFlowId_Type_Active")
            .IsUnique()
            .HasFilter("status = 'Active'")
            .HasDatabaseName("ux_proof_challenges_active_flow_type");
        // Separate partial indexes reserve each externally meaningful transition.
        // They allow historical terminal rows while preventing two workers from
        // concurrently owning the same flow/type delivery or confirmation state.
        builder.HasIndex(challenge => new
        {
            challenge.AccessFlowId,
            challenge.Type,
        }, "IX_ProofChallenges_AccessFlowId_Type_PendingDelivery")
            .IsUnique()
            .HasFilter("status = 'PendingDelivery'")
            .HasDatabaseName("ux_proof_challenges_pending_delivery_flow_type");
        builder.HasIndex(challenge => new
        {
            challenge.AccessFlowId,
            challenge.Type,
        }, "IX_ProofChallenges_AccessFlowId_Type_Confirming")
            .IsUnique()
            .HasFilter("status = 'Confirming'")
            .HasDatabaseName("ux_proof_challenges_confirming_flow_type");
        builder.HasIndex(challenge => new
        {
            challenge.IdentityId,
            challenge.Type,
            challenge.CreatedAt,
        })
            .HasDatabaseName("ix_proof_challenges_identity_type_created");
        builder.HasOne<AccessFlow>()
            .WithMany()
            .HasForeignKey(challenge => challenge.AccessFlowId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_proof_challenges_access_flows");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(challenge => challenge.IdentityId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_proof_challenges_identities");
    }
}

/// <summary>
/// Maps the append-only audit trail of attempts made against a proof challenge.
/// </summary>
internal sealed class ProofAttemptConfiguration : IEntityTypeConfiguration<ProofAttempt>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<ProofAttempt> builder)
    {
        builder.ToTable("proof_attempts");
        builder.HasKey(attempt => attempt.Id).HasName("pk_proof_attempts");
        builder.Property(attempt => attempt.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();
        builder.Property(attempt => attempt.ChallengeId).HasColumnName("challenge_id");
        builder.Property(attempt => attempt.Outcome)
            .HasColumnName("outcome")
            .HasConversion<string>()
            .HasMaxLength(16)
            .IsRequired();
        builder.Property(attempt => attempt.AttemptedAt).HasColumnName("attempted_at");
        builder.HasIndex(attempt => new { attempt.ChallengeId, attempt.AttemptedAt })
            .HasDatabaseName("ix_proof_attempts_challenge_attempted");
        builder.HasOne<ProofChallenge>()
            .WithMany()
            .HasForeignKey(attempt => attempt.ChallengeId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_proof_attempts_challenges");
    }
}

/// <summary>
/// Maps a completed identity proof to the flow, challenge, identity, and optional
/// identifier whose possession was established.
/// </summary>
internal sealed class IdentityProofConfiguration : IEntityTypeConfiguration<IdentityProof>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<IdentityProof> builder)
    {
        builder.ToTable("identity_proofs");
        builder.HasKey(proof => proof.Id).HasName("pk_identity_proofs");
        builder.Property(proof => proof.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(proof => proof.AccessFlowId)
            .HasColumnName("access_flow_id");
        builder.Property(proof => proof.IdentityId).HasColumnName("identity_id");
        builder.Property(proof => proof.ChallengeId).HasColumnName("challenge_id");
        builder.Property(proof => proof.Type)
            .HasColumnName("type")
            .HasConversion<string>()
            .HasMaxLength(32)
            .IsRequired();
        builder.Property(proof => proof.SubjectIdentifierId)
            .HasColumnName("subject_identifier_id");
        builder.Property(proof => proof.CreatedAt).HasColumnName("created_at");
        builder.HasIndex(proof => proof.ChallengeId)
            .IsUnique()
            .HasDatabaseName("ux_identity_proofs_challenge");
        // One challenge can materialize at most one proof. Attempt history is retained,
        // but replaying confirmation cannot mint a second proof from the same evidence.
        builder.HasIndex(proof => new
        {
            proof.AccessFlowId,
            proof.Type,
        })
            .HasDatabaseName("ix_identity_proofs_flow_type");
        builder.HasIndex(proof => proof.IdentityId)
            .HasDatabaseName("ix_identity_proofs_identity");
        builder.HasIndex(proof => proof.SubjectIdentifierId)
            .HasDatabaseName("ix_identity_proofs_subject_identifier");
        builder.HasOne<AccessFlow>()
            .WithMany()
            .HasForeignKey(proof => proof.AccessFlowId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_identity_proofs_access_flows");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(proof => proof.IdentityId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_identity_proofs_identities");
        builder.HasOne<ProofChallenge>()
            .WithMany()
            .HasForeignKey(proof => proof.ChallengeId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_identity_proofs_challenges");
        builder.HasOne<IdentityIdentifier>()
            .WithMany()
            .HasForeignKey(proof => proof.SubjectIdentifierId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_identity_proofs_subject_identifiers");
    }
}
