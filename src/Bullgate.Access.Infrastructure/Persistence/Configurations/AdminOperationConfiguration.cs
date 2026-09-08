using Bullgate.Access.Domain.Administration;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Bullgate.Access.Infrastructure.Persistence.Configurations;

internal sealed class AdminOperationConfiguration : IEntityTypeConfiguration<AdminOperation>
{
    public void Configure(EntityTypeBuilder<AdminOperation> builder)
    {
        builder.ToTable("admin_operations", table =>
        {
            table.HasCheckConstraint("ck_admin_operations_fingerprint", "octet_length(request_fingerprint) = 32");
            table.HasCheckConstraint("ck_admin_operations_result", "jsonb_typeof(result_json) = 'object'");
        });
        builder.HasKey(item => new { item.CallerId, item.OperationId });
        builder.Property(item => item.CallerId).HasColumnName("caller_id").HasMaxLength(64);
        builder.Property(item => item.OperationId).HasColumnName("operation_id").ValueGeneratedNever();
        builder.Property(item => item.OperatorId).HasColumnName("operator_id").HasMaxLength(128).IsRequired();
        builder.Property(item => item.SessionId).HasColumnName("session_id").HasMaxLength(128).IsRequired();
        builder.Property(item => item.ScopeId).HasColumnName("scope_id").HasMaxLength(128).IsRequired();
        builder.Property(item => item.Permission).HasColumnName("permission").HasMaxLength(255).IsRequired();
        builder.Property(item => item.TargetId).HasColumnName("target_id");
        builder.Property(item => item.RealmId).HasColumnName("realm_id");
        builder.Property(item => item.CommittedAt).HasColumnName("committed_at");
        builder.Property(item => item.RequestFingerprint).HasColumnName("request_fingerprint").IsRequired();
        builder.Property(item => item.ResultJson).HasColumnName("result_json").HasColumnType("jsonb").IsRequired();
        // No identity FK: an erasure receipt must survive its target without retaining contact data.
    }
}
