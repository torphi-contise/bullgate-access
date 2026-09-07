using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Bullgate.Access.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps single-use password-reset authority as a unique token hash with bounded
/// lifetime and consumption time.
/// </summary>
internal sealed class PasswordResetTokenConfiguration
    : IEntityTypeConfiguration<PasswordResetToken>
{
    public void Configure(EntityTypeBuilder<PasswordResetToken> builder)
    {
        builder.ToTable(
            "password_reset_tokens",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_password_reset_tokens_hash_length",
                    $"octet_length(token_hash) = {IdentityLimits.PasswordResetTokenHashLength}");
                table.HasCheckConstraint(
                    "ck_password_reset_tokens_expiration",
                    "expires_at > created_at");
                table.HasCheckConstraint(
                    "ck_password_reset_tokens_used",
                    "used_at IS NULL OR (used_at >= created_at AND used_at < expires_at)");
            });
        builder.HasKey(token => token.Id).HasName("pk_password_reset_tokens");
        builder.Property(token => token.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();
        builder.Property(token => token.IdentityId).HasColumnName("identity_id");
        builder.Property(token => token.AppEnvironmentId)
            .HasColumnName("app_environment_id");
        builder.Property(token => token.TokenHash)
            .HasColumnName("token_hash")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(token => token.CreatedAt).HasColumnName("created_at");
        builder.Property(token => token.ExpiresAt).HasColumnName("expires_at");
        builder.Property(token => token.UsedAt).HasColumnName("used_at");
        builder.HasIndex(token => token.TokenHash)
            .IsUnique()
            .HasDatabaseName("ux_password_reset_tokens_token_hash");
        // Hash uniqueness is the final replay boundary even if an accidental random
        // collision or concurrent issuer bypasses an application-layer precheck.
        builder.HasIndex(token => new { token.IdentityId, token.CreatedAt })
            .HasDatabaseName("ix_password_reset_tokens_identity_created_at");
        builder.HasIndex(token => token.AppEnvironmentId)
            .HasDatabaseName("ix_password_reset_tokens_environment");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(token => token.IdentityId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_password_reset_tokens_identities");
        builder.HasOne<AppEnvironment>()
            .WithMany()
            .HasForeignKey(token => token.AppEnvironmentId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_password_reset_tokens_app_environments");
    }
}
