using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Bullgate.Access.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps the durable reservation and confirmation states of phone password recovery.
/// </summary>
/// <remarks>
/// Database checks keep local state consistent with the provider-effect protocol: an
/// open challenge has no completion time, and a completed reset requires recorded
/// provider approval.
/// </remarks>
internal sealed class PhonePasswordResetChallengeConfiguration
    : IEntityTypeConfiguration<PhonePasswordResetChallenge>
{
    public void Configure(EntityTypeBuilder<PhonePasswordResetChallenge> builder)
    {
        builder.ToTable(
            "phone_password_reset_challenges",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_phone_password_reset_challenges_attempts",
                    "attempts >= 0 AND attempts <= max_attempts AND max_attempts > 0");
                table.HasCheckConstraint(
                    "ck_phone_password_reset_challenges_code_hash_length",
                    $"octet_length(code_hash) = "
                    + $"{IdentityLimits.PhonePasswordResetCodeHashLength}");
                table.HasCheckConstraint(
                    "ck_phone_password_reset_challenges_expiration",
                    "expires_at > created_at AND resend_available_at >= created_at");
                table.HasCheckConstraint(
                    "ck_phone_password_reset_challenges_completion",
                    "(status IN ('PendingDelivery', 'Active', 'Confirming') "
                    + "AND completed_at IS NULL) OR "
                    + "(status IN ('Completed', 'Superseded', 'Exhausted', "
                    + "'DeliveryFailed') AND completed_at IS NOT NULL)");
                table.HasCheckConstraint(
                    "ck_phone_password_reset_challenges_provider_approval",
                    "provider_approved_at IS NULL "
                    + "OR (provider_approved_at >= created_at "
                    + "AND (completed_at IS NULL "
                    + "OR provider_approved_at <= completed_at))");
                table.HasCheckConstraint(
                    "ck_phone_password_reset_challenges_completed_approval",
                    "status <> 'Completed' OR provider_approved_at IS NOT NULL");
            });
        builder.HasKey(challenge => challenge.Id)
            .HasName("pk_phone_password_reset_challenges");
        builder.Property(challenge => challenge.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();
        builder.Property(challenge => challenge.IdentityId)
            .HasColumnName("identity_id");
        builder.Property(challenge => challenge.AppEnvironmentId)
            .HasColumnName("app_environment_id");
        builder.Property(challenge => challenge.Phone)
            .HasColumnName("phone")
            .HasMaxLength(IdentityLimits.PhoneValueMaxLength)
            .IsRequired();
        builder.Property(challenge => challenge.CodeHash)
            .HasColumnName("code_hash")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(challenge => challenge.ProviderReference)
            .HasColumnName("provider_reference")
            .HasMaxLength(IdentityLimits.ProviderReferenceMaxLength);
        builder.Property(challenge => challenge.ProviderApprovedAt)
            .HasColumnName("provider_approved_at");
        builder.Property(challenge => challenge.Status)
            .HasColumnName("status")
            .HasConversion<string>()
            .HasMaxLength(16)
            .IsRequired();
        builder.Property(challenge => challenge.Attempts)
            .HasColumnName("attempts");
        builder.Property(challenge => challenge.MaxAttempts)
            .HasColumnName("max_attempts");
        builder.Property(challenge => challenge.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(challenge => challenge.ExpiresAt)
            .HasColumnName("expires_at");
        builder.Property(challenge => challenge.ResendAvailableAt)
            .HasColumnName("resend_available_at");
        builder.Property(challenge => challenge.CompletedAt)
            .HasColumnName("completed_at");
        builder.HasIndex(challenge => new
        {
            challenge.IdentityId,
            challenge.AppEnvironmentId,
        })
            .IsUnique()
            .HasFilter("status IN ('PendingDelivery', 'Active', 'Confirming')")
            .HasDatabaseName(
                "ux_phone_password_reset_challenges_open_identity_environment");
        // Exactly one open recovery per identity/environment prevents parallel sends
        // and confirmations from creating competing password-reset authority.
        builder.HasIndex(challenge => new
        {
            challenge.IdentityId,
            challenge.CreatedAt,
        })
            .HasDatabaseName(
                "ix_phone_password_reset_challenges_identity_created");
        builder.HasIndex(challenge => new
        {
            challenge.AppEnvironmentId,
            challenge.Phone,
        })
            .HasDatabaseName(
                "ix_phone_password_reset_challenges_environment_phone");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(challenge => challenge.IdentityId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName(
                "fk_phone_password_reset_challenges_identities");
        builder.HasOne<AppEnvironment>()
            .WithMany()
            .HasForeignKey(challenge => challenge.AppEnvironmentId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName(
                "fk_phone_password_reset_challenges_app_environments");
    }
}
