using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Bullgate.Access.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps the realm-scoped identity aggregate and its active or abandoned lifecycle.
/// </summary>
internal sealed class IdentityConfiguration : IEntityTypeConfiguration<Identity>
{
    public void Configure(EntityTypeBuilder<Identity> builder)
    {
        builder.ToTable(
            "identities",
            table => table.HasCheckConstraint(
                "ck_identities_lifecycle",
                "lifecycle_state IN ('Active', 'Abandoned')"));
        builder.HasKey(identity => identity.Id).HasName("pk_identities");
        builder.Property(identity => identity.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(identity => identity.RealmId).HasColumnName("realm_id");
        builder.Property(identity => identity.LifecycleState)
            .HasColumnName("lifecycle_state")
            .HasConversion<string>()
            .HasMaxLength(32)
            .HasDefaultValue(IdentityLifecycleState.Active)
            .IsRequired();
        builder.Property(identity => identity.CreatedAt).HasColumnName("created_at");
        builder.HasAlternateKey(identity => new { identity.RealmId, identity.Id })
            .HasName("ak_identities_realm_id");
        // Composite dependent keys use this alternate key so a foreign key cannot pair
        // an identity id with a caller- or row-supplied realm that it does not own.
        builder.HasOne<Realm>()
            .WithMany()
            .HasForeignKey(identity => identity.RealmId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_identities_realms");
    }
}

/// <summary>
/// Maps normalized e-mail and phone identifiers with realm ownership and optional
/// possession-verification evidence.
/// </summary>
internal sealed class IdentityIdentifierConfiguration
    : IEntityTypeConfiguration<IdentityIdentifier>
{
    public void Configure(EntityTypeBuilder<IdentityIdentifier> builder)
    {
        builder.ToTable(
            "identity_identifiers",
            table => table.HasCheckConstraint(
                "ck_identity_identifiers_verification",
                "(verified_at IS NULL AND verification_method IS NULL) "
                + "OR (verified_at IS NOT NULL AND verification_method IS NOT NULL)"));
        builder.HasKey(identifier => identifier.Id).HasName("pk_identity_identifiers");
        builder.Property(identifier => identifier.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();
        builder.Property(identifier => identifier.IdentityId).HasColumnName("identity_id");
        builder.Property(identifier => identifier.RealmId).HasColumnName("realm_id");
        builder.Property(identifier => identifier.Scheme)
            .HasColumnName("scheme")
            .HasMaxLength(IdentityLimits.IdentifierSchemeMaxLength)
            .IsRequired();
        builder.Property(identifier => identifier.NormalizedValue)
            .HasColumnName("normalized_value")
            .HasMaxLength(IdentityLimits.IdentifierValueMaxLength)
            .IsRequired();
        builder.Property(identifier => identifier.CreatedAt).HasColumnName("created_at");
        builder.Property(identifier => identifier.VerifiedAt).HasColumnName("verified_at");
        builder.Property(identifier => identifier.VerificationMethod)
            .HasColumnName("verification_method")
            .HasMaxLength(IdentityLimits.VerificationMethodMaxLength);
        builder.HasIndex(identifier => new
        {
            identifier.RealmId,
            identifier.Scheme,
            identifier.NormalizedValue,
        })
            .IsUnique()
            .HasDatabaseName("ux_identity_identifiers_realm_scheme_value");
        // These two constraints protect different invariants: a normalized value has
        // one owner in a realm, and one identity has at most one value per scheme.
        builder.HasIndex(identifier => new
        {
            identifier.RealmId,
            identifier.IdentityId,
            identifier.Scheme,
        })
            .IsUnique()
            .HasDatabaseName("ux_identity_identifiers_realm_identity_scheme");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(identifier => new
            {
                identifier.RealmId,
                identifier.IdentityId,
            })
            .HasPrincipalKey(identity => new { identity.RealmId, identity.Id })
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_identity_identifiers_identities");
    }
}

/// <summary>Maps the optional one-to-one password authenticator of an identity.</summary>
internal sealed class PasswordCredentialConfiguration
    : IEntityTypeConfiguration<PasswordCredential>
{
    public void Configure(EntityTypeBuilder<PasswordCredential> builder)
    {
        builder.ToTable("password_credentials");
        builder.HasKey(credential => credential.IdentityId)
            .HasName("pk_password_credentials");
        builder.Property(credential => credential.IdentityId).HasColumnName("identity_id");
        builder.Property(credential => credential.PasswordHash)
            .HasColumnName("password_hash")
            .HasMaxLength(IdentityLimits.PasswordHashMaxLength)
            .IsRequired();
        builder.Property(credential => credential.CreatedAt).HasColumnName("created_at");
        builder.Property(credential => credential.UpdatedAt).HasColumnName("updated_at");
        builder.HasOne<Identity>()
            .WithOne()
            .HasForeignKey<PasswordCredential>(credential => credential.IdentityId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_password_credentials_identities");
    }
}

/// <summary>
/// Maps validated provider subjects and enforces one realm owner for each
/// provider/subject pair.
/// </summary>
internal sealed class SocialCredentialConfiguration
    : IEntityTypeConfiguration<SocialCredential>
{
    public void Configure(EntityTypeBuilder<SocialCredential> builder)
    {
        builder.ToTable("social_credentials");
        builder.HasKey(credential => credential.Id)
            .HasName("pk_social_credentials");
        builder.Property(credential => credential.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();
        builder.Property(credential => credential.IdentityId).HasColumnName("identity_id");
        builder.Property(credential => credential.RealmId).HasColumnName("realm_id");
        builder.Property(credential => credential.Provider)
            .HasColumnName("provider")
            .HasMaxLength(IdentityLimits.SocialProviderMaxLength)
            .IsRequired();
        builder.Property(credential => credential.Subject)
            .HasColumnName("subject")
            .HasMaxLength(IdentityLimits.SocialSubjectMaxLength)
            .IsRequired();
        builder.Property(credential => credential.Email)
            .HasColumnName("email")
            .HasMaxLength(IdentityLimits.IdentifierValueMaxLength)
            .IsRequired();
        builder.Property(credential => credential.CreatedAt).HasColumnName("created_at");
        builder.Property(credential => credential.UpdatedAt).HasColumnName("updated_at");
        builder.HasIndex(credential => new
        {
            credential.RealmId,
            credential.Provider,
            credential.Subject,
        })
            .IsUnique()
            .HasDatabaseName("ux_social_credentials_realm_provider_subject");
        // Provider e-mail is mutable metadata. Stable subject, provider, and realm—not
        // matching e-mail text—decide whether a social credential is already owned.
        builder.HasIndex(credential => new
        {
            credential.RealmId,
            credential.IdentityId,
        })
            .HasDatabaseName("ix_social_credentials_realm_identity");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(credential => new
            {
                credential.RealmId,
                credential.IdentityId,
            })
            .HasPrincipalKey(identity => new { identity.RealmId, identity.Id })
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_social_credentials_identities");
    }
}

/// <summary>
/// Maps opaque identity sessions, including their fixed environment and distinct
/// registration or product purpose.
/// </summary>
internal sealed class IdentitySessionConfiguration
    : IEntityTypeConfiguration<IdentitySession>
{
    public void Configure(EntityTypeBuilder<IdentitySession> builder)
    {
        builder.ToTable(
            "identity_sessions",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_identity_sessions_expiration",
                    "expires_at > created_at");
                table.HasCheckConstraint(
                    "ck_identity_sessions_revocation",
                    "revoked_at IS NULL OR revoked_at >= created_at");
                table.HasCheckConstraint(
                    "ck_identity_sessions_token_hash_length",
                    $"octet_length(token_hash) = {IdentityLimits.SessionTokenHashLength}");
                table.HasCheckConstraint(
                    "ck_identity_sessions_purpose",
                    "purpose IN ('Product', 'Registration')");
            });
        builder.HasKey(session => session.Id).HasName("pk_identity_sessions");
        builder.Property(session => session.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(session => session.IdentityId).HasColumnName("identity_id");
        builder.Property(session => session.AppEnvironmentId)
            .HasColumnName("app_environment_id");
        builder.Property(session => session.Purpose)
            .HasColumnName("purpose")
            .HasConversion<string>()
            .HasMaxLength(16)
            .HasDefaultValue(IdentitySessionPurpose.Product)
            .IsRequired();
        builder.Property(session => session.TokenHash)
            .HasColumnName("token_hash")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(session => session.CreatedAt).HasColumnName("created_at");
        builder.Property(session => session.ExpiresAt).HasColumnName("expires_at");
        builder.Property(session => session.RevokedAt).HasColumnName("revoked_at");
        builder.HasIndex(session => session.TokenHash)
            .IsUnique()
            .HasDatabaseName("ux_identity_sessions_token_hash");
        // Token-hash uniqueness is global because the bearer token itself carries no
        // realm or environment selector that could disambiguate a collision.
        builder.HasIndex(session => new { session.IdentityId, session.AppEnvironmentId })
            .HasDatabaseName("ix_identity_sessions_identity_environment");
        builder.HasIndex(session => session.AppEnvironmentId)
            .HasDatabaseName("ix_identity_sessions_environment");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(session => session.IdentityId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_identity_sessions_identities");
        builder.HasOne<AppEnvironment>()
            .WithMany()
            .HasForeignKey(session => session.AppEnvironmentId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_identity_sessions_app_environments");
    }
}

/// <summary>
/// Maps the per-environment registration lifecycle that gates promotion from a
/// registration session to a product session.
/// </summary>
internal sealed class RegistrationContextConfiguration
    : IEntityTypeConfiguration<RegistrationContext>
{
    public void Configure(EntityTypeBuilder<RegistrationContext> builder)
    {
        builder.ToTable(
            "registration_contexts",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_registration_contexts_status",
                    "(status = 'Open' AND closed_at IS NULL) "
                    + "OR (status IN ('Completed', 'Abandoned') AND closed_at IS NOT NULL)");
                table.HasCheckConstraint(
                    "ck_registration_contexts_closure",
                    "closed_at IS NULL OR closed_at >= created_at");
            });
        builder.HasKey(context => context.Id).HasName("pk_registration_contexts");
        builder.Property(context => context.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(context => context.RealmId).HasColumnName("realm_id");
        builder.Property(context => context.AppEnvironmentId)
            .HasColumnName("app_environment_id");
        builder.Property(context => context.IdentityId).HasColumnName("identity_id");
        builder.Property(context => context.Status)
            .HasColumnName("status")
            .HasConversion<string>()
            .HasMaxLength(16)
            .IsRequired();
        builder.Property(context => context.CreatedAt).HasColumnName("created_at");
        builder.Property(context => context.ClosedAt).HasColumnName("closed_at");
        builder.HasIndex(context => new
        {
            context.AppEnvironmentId,
            context.IdentityId,
        })
            .IsUnique()
            .HasDatabaseName("ux_registration_contexts_environment_identity");
        // Preserve one canonical registration state for an identity in an environment;
        // retries resume it instead of creating parallel promotion paths.
        builder.HasIndex(context => new { context.RealmId, context.IdentityId })
            .HasDatabaseName("ix_registration_contexts_realm_identity");
        builder.HasOne<Identity>()
            .WithMany()
            .HasForeignKey(context => new { context.RealmId, context.IdentityId })
            .HasPrincipalKey(identity => new { identity.RealmId, identity.Id })
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_registration_contexts_identities");
        builder.HasOne<AppEnvironment>()
            .WithMany()
            .HasForeignKey(context => context.AppEnvironmentId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_registration_contexts_app_environments");
    }
}
