using Bullgate.Access.Domain.Topology;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Bullgate.Access.Infrastructure.Persistence.Configurations;

/// <summary>Maps the installation-level workspace isolation boundary.</summary>
internal sealed class WorkspaceConfiguration : IEntityTypeConfiguration<Workspace>
{
    public void Configure(EntityTypeBuilder<Workspace> builder)
    {
        builder.ToTable("workspaces");
        ConfigureId(builder);
        builder.Property(workspace => workspace.Key)
            .HasColumnName("key")
            .HasMaxLength(TopologyValue.KeyMaxLength)
            .IsRequired();
        builder.Property(workspace => workspace.Name)
            .HasColumnName("name")
            .HasMaxLength(TopologyValue.NameMaxLength)
            .IsRequired();
        builder.Property(workspace => workspace.IsActive).HasColumnName("is_active");
        builder.Property(workspace => workspace.CreatedAt).HasColumnName("created_at");
        builder.HasIndex(workspace => workspace.Key)
            .IsUnique()
            .HasDatabaseName("ux_workspaces_key");
    }

    private static void ConfigureId(EntityTypeBuilder<Workspace> builder)
    {
        builder.HasKey(workspace => workspace.Id).HasName("pk_workspaces");
        builder.Property(workspace => workspace.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();
    }
}

/// <summary>Maps an application whose natural key is unique inside a workspace.</summary>
internal sealed class AppConfiguration : IEntityTypeConfiguration<App>
{
    public void Configure(EntityTypeBuilder<App> builder)
    {
        builder.ToTable("apps");
        builder.HasKey(app => app.Id).HasName("pk_apps");
        builder.Property(app => app.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(app => app.WorkspaceId).HasColumnName("workspace_id");
        builder.Property(app => app.Key)
            .HasColumnName("key")
            .HasMaxLength(TopologyValue.KeyMaxLength)
            .IsRequired();
        builder.Property(app => app.Name)
            .HasColumnName("name")
            .HasMaxLength(TopologyValue.NameMaxLength)
            .IsRequired();
        builder.Property(app => app.IsActive).HasColumnName("is_active");
        builder.Property(app => app.CreatedAt).HasColumnName("created_at");
        builder.HasIndex(app => new { app.WorkspaceId, app.Key })
            .IsUnique()
            .HasDatabaseName("ux_apps_workspace_key");
        builder.HasAlternateKey(app => new { app.WorkspaceId, app.Id })
            .HasName("ak_apps_workspace_id");
        // Environment foreign keys target the composite key so an app id cannot be
        // attached to a different workspace even if both ids are otherwise valid.
        builder.HasOne<Workspace>()
            .WithMany()
            .HasForeignKey(app => app.WorkspaceId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_apps_workspaces");
    }
}

/// <summary>
/// Maps the identity and identifier uniqueness boundary shared by app environments.
/// </summary>
internal sealed class RealmConfiguration : IEntityTypeConfiguration<Realm>
{
    public void Configure(EntityTypeBuilder<Realm> builder)
    {
        builder.ToTable("realms");
        builder.HasKey(realm => realm.Id).HasName("pk_realms");
        builder.Property(realm => realm.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(realm => realm.WorkspaceId).HasColumnName("workspace_id");
        builder.Property(realm => realm.Key)
            .HasColumnName("key")
            .HasMaxLength(TopologyValue.KeyMaxLength)
            .IsRequired();
        builder.Property(realm => realm.Name)
            .HasColumnName("name")
            .HasMaxLength(TopologyValue.NameMaxLength)
            .IsRequired();
        builder.Property(realm => realm.IsActive).HasColumnName("is_active");
        builder.Property(realm => realm.CreatedAt).HasColumnName("created_at");
        builder.HasIndex(realm => new { realm.WorkspaceId, realm.Key })
            .IsUnique()
            .HasDatabaseName("ux_realms_workspace_key");
        builder.HasAlternateKey(realm => new { realm.WorkspaceId, realm.Id })
            .HasName("ak_realms_workspace_id");
        builder.HasOne<Workspace>()
            .WithMany()
            .HasForeignKey(realm => realm.WorkspaceId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_realms_workspaces");
    }
}

/// <summary>
/// Maps an app environment, its queryable policy projection, and its authenticated-
/// encryption envelope for the complete provider configuration.
/// </summary>
internal sealed class AppEnvironmentEntityConfiguration : IEntityTypeConfiguration<AppEnvironment>
{
    public void Configure(EntityTypeBuilder<AppEnvironment> builder)
    {
        builder.ToTable(
            "app_environments",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_app_environments_configuration_format",
                    "configuration_format_version = 2");
                table.HasCheckConstraint(
                    "ck_app_environments_configuration_nonce_length",
                    "octet_length(configuration_nonce) = 12");
                table.HasCheckConstraint(
                    "ck_app_environments_configuration_ciphertext_length",
                    "octet_length(configuration_ciphertext) > 0");
                table.HasCheckConstraint(
                    "ck_app_environments_configuration_tag_length",
                    "octet_length(configuration_tag) = 16");
            });
        builder.HasKey(environment => environment.Id).HasName("pk_app_environments");
        builder.Property(environment => environment.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();
        builder.Property(environment => environment.WorkspaceId).HasColumnName("workspace_id");
        builder.Property(environment => environment.AppId).HasColumnName("app_id");
        builder.Property(environment => environment.RealmId).HasColumnName("realm_id");
        builder.Property(environment => environment.Key)
            .HasColumnName("key")
            .HasMaxLength(TopologyValue.KeyMaxLength)
            .IsRequired();
        builder.Property(environment => environment.Name)
            .HasColumnName("name")
            .HasMaxLength(TopologyValue.NameMaxLength)
            .IsRequired();
        builder.Property(environment => environment.EmailIdentifierEnabled)
            .HasColumnName("email_identifier_enabled");
        builder.Property(environment => environment.EmailIdentifierRequired)
            .HasColumnName("email_identifier_required");
        builder.Property(environment => environment.EmailVerificationEnabled)
            .HasColumnName("email_verification_enabled");
        builder.Property(environment => environment.EmailVerificationProvider)
            .HasColumnName("email_verification_provider")
            .HasMaxLength(TopologyValue.KeyMaxLength);
        builder.Property(environment => environment.PhoneIdentifierEnabled)
            .HasColumnName("phone_identifier_enabled");
        builder.Property(environment => environment.PhoneIdentifierRequired)
            .HasColumnName("phone_identifier_required");
        builder.Property(environment => environment.PhoneVerificationEnabled)
            .HasColumnName("phone_verification_enabled");
        builder.Property(environment => environment.PhoneVerificationProvider)
            .HasColumnName("phone_verification_provider")
            .HasMaxLength(TopologyValue.KeyMaxLength);
        builder.Property(environment => environment.PasswordAuthenticatorEnabled)
            .HasColumnName("password_authenticator_enabled");
        builder.Property(environment => environment.GoogleAuthenticatorEnabled)
            .HasColumnName("google_authenticator_enabled");
        builder.Property(environment => environment.AppleAuthenticatorEnabled)
            .HasColumnName("apple_authenticator_enabled");
        builder.Property(environment => environment.PasswordRecoveryUrl)
            .HasColumnName("password_recovery_url")
            .HasMaxLength(TopologyValue.PasswordRecoveryUrlMaxLength);
        builder.Property(environment => environment.ConfigurationFormatVersion)
            .HasColumnName("configuration_format_version");
        builder.Property(environment => environment.ConfigurationNonce)
            .HasColumnName("configuration_nonce")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(environment => environment.ConfigurationCiphertext)
            .HasColumnName("configuration_ciphertext")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(environment => environment.ConfigurationTag)
            .HasColumnName("configuration_tag")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(environment => environment.ConfigurationUpdatedAt)
            .HasColumnName("configuration_updated_at");
        builder.Ignore(environment => environment.AccessPolicy);
        // AccessPolicy is reconstructed from the typed projections above. Persisting
        // the aggregate object as well would create two competing policy authorities.
        builder.Property(environment => environment.IsActive).HasColumnName("is_active");
        builder.Property(environment => environment.CreatedAt).HasColumnName("created_at");
        builder.HasIndex(environment => new { environment.AppId, environment.Key })
            .IsUnique()
            .HasDatabaseName("ux_app_environments_app_key");
        builder.HasIndex(environment => new { environment.WorkspaceId, environment.AppId })
            .HasDatabaseName("ix_app_environments_workspace_app");
        builder.HasIndex(environment => new { environment.WorkspaceId, environment.RealmId })
            .HasDatabaseName("ix_app_environments_workspace_realm");
        builder.HasOne<App>()
            .WithMany()
            .HasForeignKey(environment => new
            {
                environment.WorkspaceId,
                environment.AppId,
            })
            .HasPrincipalKey(app => new { app.WorkspaceId, app.Id })
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_app_environments_apps");
        builder.HasOne<Realm>()
            .WithMany()
            .HasForeignKey(environment => new
            {
                environment.WorkspaceId,
                environment.RealmId,
            })
            .HasPrincipalKey(realm => new { realm.WorkspaceId, realm.Id })
            // Both composite foreign keys require the environment's app and realm to
            // belong to the same recorded workspace (ACCESS-031).
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_app_environments_realms");
    }
}

/// <summary>Maps a trusted backend client inside one app environment.</summary>
internal sealed class IntegrationClientConfiguration : IEntityTypeConfiguration<IntegrationClient>
{
    public void Configure(EntityTypeBuilder<IntegrationClient> builder)
    {
        builder.ToTable("integration_clients");
        builder.HasKey(client => client.Id).HasName("pk_integration_clients");
        builder.Property(client => client.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(client => client.AppEnvironmentId).HasColumnName("app_environment_id");
        builder.Property(client => client.Key)
            .HasColumnName("key")
            .HasMaxLength(TopologyValue.KeyMaxLength)
            .IsRequired();
        builder.Property(client => client.Name)
            .HasColumnName("name")
            .HasMaxLength(TopologyValue.NameMaxLength)
            .IsRequired();
        builder.Property(client => client.IsActive).HasColumnName("is_active");
        builder.Property(client => client.CreatedAt).HasColumnName("created_at");
        builder.HasIndex(client => new { client.AppEnvironmentId, client.Key })
            .IsUnique()
            .HasDatabaseName("ux_integration_clients_environment_key");
        builder.HasOne<AppEnvironment>()
            .WithMany()
            .HasForeignKey(client => client.AppEnvironmentId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_integration_clients_app_environments");
    }
}

/// <summary>Maps the closed permission set granted to an integration client.</summary>
internal sealed class IntegrationClientPermissionConfiguration
    : IEntityTypeConfiguration<IntegrationClientPermission>
{
    public void Configure(EntityTypeBuilder<IntegrationClientPermission> builder)
    {
        builder.ToTable("integration_client_permissions");
        builder.HasKey(permission => new { permission.IntegrationClientId, permission.Value })
            .HasName("pk_integration_client_permissions");
        builder.Property(permission => permission.IntegrationClientId)
            .HasColumnName("integration_client_id");
        builder.Property(permission => permission.Value)
            .HasColumnName("permission")
            .HasMaxLength(TopologyValue.PermissionMaxLength)
            .IsRequired();
        builder.HasOne<IntegrationClient>()
            .WithMany()
            .HasForeignKey(permission => permission.IntegrationClientId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_integration_client_permissions_clients");
    }
}

/// <summary>
/// Maps hashed integration credentials and their independent expiration and revocation
/// lifecycle.
/// </summary>
internal sealed class IntegrationClientSecretConfiguration
    : IEntityTypeConfiguration<IntegrationClientSecret>
{
    public void Configure(EntityTypeBuilder<IntegrationClientSecret> builder)
    {
        builder.ToTable(
            "integration_client_secrets",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_integration_client_secrets_expiration",
                    "expires_at IS NULL OR expires_at > created_at");
                table.HasCheckConstraint(
                    "ck_integration_client_secrets_revocation",
                    "revoked_at IS NULL OR revoked_at >= created_at");
                table.HasCheckConstraint(
                    "ck_integration_client_secrets_sha256_length",
                    "hash_algorithm <> 'sha256-v1' OR octet_length(secret_hash) = 32");
            });
        builder.HasKey(secret => secret.Id).HasName("pk_integration_client_secrets");
        builder.Property(secret => secret.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(secret => secret.IntegrationClientId)
            .HasColumnName("integration_client_id");
        builder.Property(secret => secret.SecretHash)
            .HasColumnName("secret_hash")
            .HasColumnType("bytea")
            .IsRequired();
        builder.Property(secret => secret.HashAlgorithm)
            .HasColumnName("hash_algorithm")
            .HasMaxLength(TopologyValue.HashAlgorithmMaxLength)
            .IsRequired();
        builder.Property(secret => secret.CreatedAt).HasColumnName("created_at");
        builder.Property(secret => secret.ExpiresAt).HasColumnName("expires_at");
        builder.Property(secret => secret.RevokedAt).HasColumnName("revoked_at");
        builder.HasIndex(secret => secret.IntegrationClientId)
            .HasDatabaseName("ix_integration_client_secrets_client");
        builder.HasOne<IntegrationClient>()
            .WithMany()
            .HasForeignKey(secret => secret.IntegrationClientId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_integration_client_secrets_clients");
        // Restrict deletion so credential audit state is not removed accidentally with
        // topology. Lifecycle changes use explicit activation and revocation fields.
    }
}

/// <summary>
/// Maps a public application build identity and Android-specific SMS Retriever
/// metadata inside one app environment.
/// </summary>
internal sealed class ApplicationClientConfiguration
    : IEntityTypeConfiguration<ApplicationClient>
{
    public void Configure(EntityTypeBuilder<ApplicationClient> builder)
    {
        builder.ToTable(
            "application_clients",
            table =>
            {
                table.HasCheckConstraint(
                    "ck_application_clients_sms_retriever_app_hash_length",
                    "sms_retriever_app_hash IS NULL OR char_length(sms_retriever_app_hash) = 11");
                table.HasCheckConstraint(
                    "ck_application_clients_sms_retriever_app_hash_platform",
                    "sms_retriever_app_hash IS NULL OR platform = 'Android'");
            });
        builder.HasKey(client => client.Id).HasName("pk_application_clients");
        builder.Property(client => client.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(client => client.AppEnvironmentId).HasColumnName("app_environment_id");
        builder.Property(client => client.Key)
            .HasColumnName("key")
            .HasMaxLength(TopologyValue.KeyMaxLength)
            .IsRequired();
        builder.Property(client => client.Name)
            .HasColumnName("name")
            .HasMaxLength(TopologyValue.NameMaxLength)
            .IsRequired();
        builder.Property(client => client.Platform)
            .HasColumnName("platform")
            .HasConversion<string>()
            .HasMaxLength(16)
            .IsRequired();
        builder.Property(client => client.ApplicationId)
            .HasColumnName("application_id")
            .HasMaxLength(TopologyValue.ApplicationIdMaxLength);
        builder.Property(client => client.SigningIdentity)
            .HasColumnName("signing_identity")
            .HasMaxLength(TopologyValue.SigningIdentityMaxLength);
        builder.Property(client => client.SmsRetrieverAppHash)
            .HasColumnName("sms_retriever_app_hash")
            .HasMaxLength(TopologyValue.SmsRetrieverAppHashLength);
        builder.Property(client => client.IsActive).HasColumnName("is_active");
        builder.Property(client => client.CreatedAt).HasColumnName("created_at");
        builder.HasIndex(client => new { client.AppEnvironmentId, client.Key })
            .IsUnique()
            .HasDatabaseName("ux_application_clients_environment_key");
        builder.HasIndex(client => new
        {
            client.AppEnvironmentId,
            client.Platform,
            client.ApplicationId,
            client.SigningIdentity,
        })
            .IsUnique()
            .HasFilter("application_id IS NOT NULL")
            .HasDatabaseName("ux_application_clients_artifact_identity");
        // Web clients may omit an application id. Native artifact identity becomes
        // unique only when the identifying metadata exists.
        builder.HasOne<AppEnvironment>()
            .WithMany()
            .HasForeignKey(client => client.AppEnvironmentId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_application_clients_app_environments");
    }
}
