using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Bullgate.Access.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps the temporary evidence required to resolve a proven phone that is already
/// owned by another active identity without silently merging identities.
/// </summary>
internal sealed class PhoneRegistrationConflictConfiguration
    : IEntityTypeConfiguration<PhoneRegistrationConflict>
{
    public void Configure(EntityTypeBuilder<PhoneRegistrationConflict> builder)
    {
        builder.ToTable(
            "phone_registration_conflicts",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_phone_registration_conflicts_attempts",
                    "failed_email_attempts >= 0");
                table.HasCheckConstraint(
                    "ck_phone_registration_conflicts_expiration",
                    "expires_at > created_at");
                table.HasCheckConstraint(
                    "ck_phone_registration_conflicts_email_exhaustion",
                    "email_resolution_exhausted_at IS NULL OR (email_resolution_exhausted_at >= created_at AND email_resolution_exhausted_at < expires_at AND failed_email_attempts > 0)");
            });
        builder.HasKey(conflict => conflict.AccessFlowId)
            .HasName("pk_phone_registration_conflicts");
        // Using the flow id as the primary key permits only one unresolved phone
        // ownership conflict per flow and makes cascade deletion deterministic.
        builder.Property(conflict => conflict.AccessFlowId)
            .HasColumnName("access_flow_id")
            .ValueGeneratedNever();
        builder.Property(conflict => conflict.PreviousIdentityId)
            .HasColumnName("previous_identity_id");
        builder.Property(conflict => conflict.ConflictingPhoneIdentifierId)
            .HasColumnName("conflicting_phone_identifier_id");
        builder.Property(conflict => conflict.FailedEmailAttempts)
            .HasColumnName("failed_email_attempts");
        builder.Property(conflict => conflict.EmailResolutionExhaustedAt)
            .HasColumnName("email_resolution_exhausted_at");
        builder.Property(conflict => conflict.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(conflict => conflict.ExpiresAt)
            .HasColumnName("expires_at");
        builder.HasIndex(conflict => conflict.PreviousIdentityId)
            .HasDatabaseName("ix_phone_registration_conflicts_previous_identity");
        builder.HasIndex(conflict => conflict.ConflictingPhoneIdentifierId)
            .HasDatabaseName("ix_phone_registration_conflicts_phone_identifier");
        builder.HasOne<AccessFlow>()
            .WithOne()
            .HasForeignKey<PhoneRegistrationConflict>(
                conflict => conflict.AccessFlowId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_phone_registration_conflicts_access_flows");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(conflict => conflict.PreviousIdentityId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_phone_registration_conflicts_previous_identity");
        builder.HasOne<IdentityIdentifier>()
            .WithMany()
            .HasForeignKey(conflict => conflict.ConflictingPhoneIdentifierId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_phone_registration_conflicts_phone_identifier");
    }
}
