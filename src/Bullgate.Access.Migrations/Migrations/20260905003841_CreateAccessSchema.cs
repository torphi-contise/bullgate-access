using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Bullgate.Access.Migrations.Migrations
{
    /// <inheritdoc />
    public partial class CreateAccessSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "workspaces",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    key = table.Column<string>(type: "character varying(63)", maxLength: 63, nullable: false),
                    name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_workspaces", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "apps",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    workspace_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key = table.Column<string>(type: "character varying(63)", maxLength: 63, nullable: false),
                    name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_apps", x => x.id);
                    table.UniqueConstraint("ak_apps_workspace_id", x => new { x.workspace_id, x.id });
                    table.ForeignKey(
                        name: "fk_apps_workspaces",
                        column: x => x.workspace_id,
                        principalTable: "workspaces",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "realms",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    workspace_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key = table.Column<string>(type: "character varying(63)", maxLength: 63, nullable: false),
                    name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_realms", x => x.id);
                    table.UniqueConstraint("ak_realms_workspace_id", x => new { x.workspace_id, x.id });
                    table.ForeignKey(
                        name: "fk_realms_workspaces",
                        column: x => x.workspace_id,
                        principalTable: "workspaces",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "app_environments",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    workspace_id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_id = table.Column<Guid>(type: "uuid", nullable: false),
                    realm_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key = table.Column<string>(type: "character varying(63)", maxLength: 63, nullable: false),
                    name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    email_identifier_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    email_identifier_required = table.Column<bool>(type: "boolean", nullable: false),
                    email_verification_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    email_verification_provider = table.Column<string>(type: "character varying(63)", maxLength: 63, nullable: true),
                    phone_identifier_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    phone_identifier_required = table.Column<bool>(type: "boolean", nullable: false),
                    phone_verification_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    phone_verification_provider = table.Column<string>(type: "character varying(63)", maxLength: 63, nullable: true),
                    password_authenticator_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    google_authenticator_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    apple_authenticator_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    password_recovery_url = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    configuration_format_version = table.Column<int>(type: "integer", nullable: false),
                    configuration_nonce = table.Column<byte[]>(type: "bytea", nullable: false),
                    configuration_ciphertext = table.Column<byte[]>(type: "bytea", nullable: false),
                    configuration_tag = table.Column<byte[]>(type: "bytea", nullable: false),
                    configuration_updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_app_environments", x => x.id);
                    table.CheckConstraint("ck_app_environments_configuration_ciphertext_length", "octet_length(configuration_ciphertext) > 0");
                    table.CheckConstraint("ck_app_environments_configuration_format", "configuration_format_version = 2");
                    table.CheckConstraint("ck_app_environments_configuration_nonce_length", "octet_length(configuration_nonce) = 12");
                    table.CheckConstraint("ck_app_environments_configuration_tag_length", "octet_length(configuration_tag) = 16");
                    table.ForeignKey(
                        name: "fk_app_environments_apps",
                        columns: x => new { x.workspace_id, x.app_id },
                        principalTable: "apps",
                        principalColumns: new[] { "workspace_id", "id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_app_environments_realms",
                        columns: x => new { x.workspace_id, x.realm_id },
                        principalTable: "realms",
                        principalColumns: new[] { "workspace_id", "id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "identities",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    realm_id = table.Column<Guid>(type: "uuid", nullable: false),
                    lifecycle_state = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false, defaultValue: "Active"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identities", x => x.id);
                    table.UniqueConstraint("ak_identities_realm_id", x => new { x.realm_id, x.id });
                    table.CheckConstraint("ck_identities_lifecycle", "lifecycle_state IN ('Active', 'Abandoned')");
                    table.ForeignKey(
                        name: "fk_identities_realms",
                        column: x => x.realm_id,
                        principalTable: "realms",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "application_clients",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_environment_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key = table.Column<string>(type: "character varying(63)", maxLength: 63, nullable: false),
                    name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    platform = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    application_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    signing_identity = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    sms_retriever_app_hash = table.Column<string>(type: "character varying(11)", maxLength: 11, nullable: true),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_application_clients", x => x.id);
                    table.CheckConstraint("ck_application_clients_sms_retriever_app_hash_length", "sms_retriever_app_hash IS NULL OR char_length(sms_retriever_app_hash) = 11");
                    table.CheckConstraint("ck_application_clients_sms_retriever_app_hash_platform", "sms_retriever_app_hash IS NULL OR platform = 'Android'");
                    table.ForeignKey(
                        name: "fk_application_clients_app_environments",
                        column: x => x.app_environment_id,
                        principalTable: "app_environments",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "integration_clients",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_environment_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key = table.Column<string>(type: "character varying(63)", maxLength: 63, nullable: false),
                    name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_integration_clients", x => x.id);
                    table.ForeignKey(
                        name: "fk_integration_clients_app_environments",
                        column: x => x.app_environment_id,
                        principalTable: "app_environments",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "identity_identifiers",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    realm_id = table.Column<Guid>(type: "uuid", nullable: false),
                    scheme = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    normalized_value = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    verified_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    verification_method = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_identifiers", x => x.id);
                    table.CheckConstraint("ck_identity_identifiers_verification", "(verified_at IS NULL AND verification_method IS NULL) OR (verified_at IS NOT NULL AND verification_method IS NOT NULL)");
                    table.ForeignKey(
                        name: "fk_identity_identifiers_identities",
                        columns: x => new { x.realm_id, x.identity_id },
                        principalTable: "identities",
                        principalColumns: new[] { "realm_id", "id" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "identity_sessions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_environment_id = table.Column<Guid>(type: "uuid", nullable: false),
                    purpose = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false, defaultValue: "Product"),
                    token_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_sessions", x => x.id);
                    table.CheckConstraint("ck_identity_sessions_expiration", "expires_at > created_at");
                    table.CheckConstraint("ck_identity_sessions_purpose", "purpose IN ('Product', 'Registration')");
                    table.CheckConstraint("ck_identity_sessions_revocation", "revoked_at IS NULL OR revoked_at >= created_at");
                    table.CheckConstraint("ck_identity_sessions_token_hash_length", "octet_length(token_hash) = 32");
                    table.ForeignKey(
                        name: "fk_identity_sessions_app_environments",
                        column: x => x.app_environment_id,
                        principalTable: "app_environments",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_identity_sessions_identities",
                        column: x => x.identity_id,
                        principalTable: "identities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "password_credentials",
                columns: table => new
                {
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    password_hash = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_password_credentials", x => x.identity_id);
                    table.ForeignKey(
                        name: "fk_password_credentials_identities",
                        column: x => x.identity_id,
                        principalTable: "identities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "password_reset_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_environment_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_password_reset_tokens", x => x.id);
                    table.CheckConstraint("ck_password_reset_tokens_expiration", "expires_at > created_at");
                    table.CheckConstraint("ck_password_reset_tokens_hash_length", "octet_length(token_hash) = 32");
                    table.CheckConstraint("ck_password_reset_tokens_used", "used_at IS NULL OR (used_at >= created_at AND used_at < expires_at)");
                    table.ForeignKey(
                        name: "fk_password_reset_tokens_app_environments",
                        column: x => x.app_environment_id,
                        principalTable: "app_environments",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_password_reset_tokens_identities",
                        column: x => x.identity_id,
                        principalTable: "identities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "phone_password_reset_challenges",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_environment_id = table.Column<Guid>(type: "uuid", nullable: false),
                    phone = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    code_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    provider_reference = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    provider_approved_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    attempts = table.Column<int>(type: "integer", nullable: false),
                    max_attempts = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    resend_available_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_phone_password_reset_challenges", x => x.id);
                    table.CheckConstraint("ck_phone_password_reset_challenges_attempts", "attempts >= 0 AND attempts <= max_attempts AND max_attempts > 0");
                    table.CheckConstraint("ck_phone_password_reset_challenges_code_hash_length", "octet_length(code_hash) = 32");
                    table.CheckConstraint("ck_phone_password_reset_challenges_completed_approval", "status <> 'Completed' OR provider_approved_at IS NOT NULL");
                    table.CheckConstraint("ck_phone_password_reset_challenges_completion", "(status IN ('PendingDelivery', 'Active', 'Confirming') AND completed_at IS NULL) OR (status IN ('Completed', 'Superseded', 'Exhausted', 'DeliveryFailed') AND completed_at IS NOT NULL)");
                    table.CheckConstraint("ck_phone_password_reset_challenges_expiration", "expires_at > created_at AND resend_available_at >= created_at");
                    table.CheckConstraint("ck_phone_password_reset_challenges_provider_approval", "provider_approved_at IS NULL OR (provider_approved_at >= created_at AND (completed_at IS NULL OR provider_approved_at <= completed_at))");
                    table.ForeignKey(
                        name: "fk_phone_password_reset_challenges_app_environments",
                        column: x => x.app_environment_id,
                        principalTable: "app_environments",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_phone_password_reset_challenges_identities",
                        column: x => x.identity_id,
                        principalTable: "identities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "registration_contexts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    realm_id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_environment_id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    closed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_registration_contexts", x => x.id);
                    table.CheckConstraint("ck_registration_contexts_closure", "closed_at IS NULL OR closed_at >= created_at");
                    table.CheckConstraint("ck_registration_contexts_status", "(status = 'Open' AND closed_at IS NULL) OR (status IN ('Completed', 'Abandoned') AND closed_at IS NOT NULL)");
                    table.ForeignKey(
                        name: "fk_registration_contexts_app_environments",
                        column: x => x.app_environment_id,
                        principalTable: "app_environments",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_registration_contexts_identities",
                        columns: x => new { x.realm_id, x.identity_id },
                        principalTable: "identities",
                        principalColumns: new[] { "realm_id", "id" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "social_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    realm_id = table.Column<Guid>(type: "uuid", nullable: false),
                    provider = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    subject = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    email = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_social_credentials", x => x.id);
                    table.ForeignKey(
                        name: "fk_social_credentials_identities",
                        columns: x => new { x.realm_id, x.identity_id },
                        principalTable: "identities",
                        principalColumns: new[] { "realm_id", "id" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "integration_client_permissions",
                columns: table => new
                {
                    integration_client_id = table.Column<Guid>(type: "uuid", nullable: false),
                    permission = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_integration_client_permissions", x => new { x.integration_client_id, x.permission });
                    table.ForeignKey(
                        name: "fk_integration_client_permissions_clients",
                        column: x => x.integration_client_id,
                        principalTable: "integration_clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "integration_client_secrets",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    integration_client_id = table.Column<Guid>(type: "uuid", nullable: false),
                    secret_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    hash_algorithm = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_integration_client_secrets", x => x.id);
                    table.CheckConstraint("ck_integration_client_secrets_expiration", "expires_at IS NULL OR expires_at > created_at");
                    table.CheckConstraint("ck_integration_client_secrets_revocation", "revoked_at IS NULL OR revoked_at >= created_at");
                    table.CheckConstraint("ck_integration_client_secrets_sha256_length", "hash_algorithm <> 'sha256-v1' OR octet_length(secret_hash) = 32");
                    table.ForeignKey(
                        name: "fk_integration_client_secrets_clients",
                        column: x => x.integration_client_id,
                        principalTable: "integration_clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "access_flows",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    realm_id = table.Column<Guid>(type: "uuid", nullable: false),
                    app_environment_id = table.Column<Guid>(type: "uuid", nullable: false),
                    integration_client_id = table.Column<Guid>(type: "uuid", nullable: false),
                    application_client_id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    registration_context_id = table.Column<Guid>(type: "uuid", nullable: true),
                    source_session_id = table.Column<Guid>(type: "uuid", nullable: false),
                    protocol_version = table.Column<int>(type: "integer", nullable: false),
                    intent = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    current_revision = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_access_flows", x => x.id);
                    table.CheckConstraint("ck_access_flows_completion", "(status = 'Active' AND completed_at IS NULL) OR (status IN ('Completed', 'Expired', 'Cancelled') AND completed_at IS NOT NULL)");
                    table.CheckConstraint("ck_access_flows_current_revision", "current_revision > 0");
                    table.CheckConstraint("ck_access_flows_expiration", "expires_at > created_at");
                    table.CheckConstraint("ck_access_flows_intent", "intent IN ('ContinueRegistration', 'ManagePhone')");
                    table.CheckConstraint("ck_access_flows_intent_context", "(intent = 'ContinueRegistration' AND registration_context_id IS NOT NULL) OR (intent = 'ManagePhone' AND registration_context_id IS NULL)");
                    table.CheckConstraint("ck_access_flows_protocol_version", "protocol_version > 0");
                    table.CheckConstraint("ck_access_flows_status", "status IN ('Active', 'Completed', 'Expired', 'Cancelled')");
                    table.CheckConstraint("ck_access_flows_updated_at", "updated_at >= created_at");
                    table.ForeignKey(
                        name: "fk_access_flows_app_environments",
                        column: x => x.app_environment_id,
                        principalTable: "app_environments",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_access_flows_application_clients",
                        column: x => x.application_client_id,
                        principalTable: "application_clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_access_flows_identities",
                        columns: x => new { x.realm_id, x.identity_id },
                        principalTable: "identities",
                        principalColumns: new[] { "realm_id", "id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_access_flows_integration_clients",
                        column: x => x.integration_client_id,
                        principalTable: "integration_clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_access_flows_registration_contexts",
                        column: x => x.registration_context_id,
                        principalTable: "registration_contexts",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_access_flows_source_sessions",
                        column: x => x.source_session_id,
                        principalTable: "identity_sessions",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "access_flow_data_subjects",
                columns: table => new
                {
                    flow_id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    realm_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_access_flow_data_subjects", x => new { x.flow_id, x.identity_id });
                    table.ForeignKey(
                        name: "fk_access_flow_data_subjects_flows",
                        column: x => x.flow_id,
                        principalTable: "access_flows",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_access_flow_data_subjects_identities",
                        columns: x => new { x.realm_id, x.identity_id },
                        principalTable: "identities",
                        principalColumns: new[] { "realm_id", "id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "access_flow_revisions",
                columns: table => new
                {
                    flow_id = table.Column<Guid>(type: "uuid", nullable: false),
                    revision = table.Column<int>(type: "integer", nullable: false),
                    snapshot = table.Column<string>(type: "jsonb", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_access_flow_revisions", x => new { x.flow_id, x.revision });
                    table.CheckConstraint("ck_access_flow_revisions_revision", "revision > 0");
                    table.ForeignKey(
                        name: "fk_access_flow_revisions_flows",
                        column: x => x.flow_id,
                        principalTable: "access_flows",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "phone_registration_conflicts",
                columns: table => new
                {
                    access_flow_id = table.Column<Guid>(type: "uuid", nullable: false),
                    previous_identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    conflicting_phone_identifier_id = table.Column<Guid>(type: "uuid", nullable: false),
                    failed_email_attempts = table.Column<int>(type: "integer", nullable: false),
                    email_resolution_exhausted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_phone_registration_conflicts", x => x.access_flow_id);
                    table.CheckConstraint("ck_phone_registration_conflicts_attempts", "failed_email_attempts >= 0");
                    table.CheckConstraint("ck_phone_registration_conflicts_email_exhaustion", "email_resolution_exhausted_at IS NULL OR (email_resolution_exhausted_at >= created_at AND email_resolution_exhausted_at < expires_at AND failed_email_attempts > 0)");
                    table.CheckConstraint("ck_phone_registration_conflicts_expiration", "expires_at > created_at");
                    table.ForeignKey(
                        name: "fk_phone_registration_conflicts_access_flows",
                        column: x => x.access_flow_id,
                        principalTable: "access_flows",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_phone_registration_conflicts_phone_identifier",
                        column: x => x.conflicting_phone_identifier_id,
                        principalTable: "identity_identifiers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_phone_registration_conflicts_previous_identity",
                        column: x => x.previous_identity_id,
                        principalTable: "identities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "proof_challenges",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    access_flow_id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    channel = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    destination_scheme = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    destination_value = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    secret_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    provider_reference = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    attempts = table.Column<int>(type: "integer", nullable: false),
                    max_attempts = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    resend_available_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_proof_challenges", x => x.id);
                    table.CheckConstraint("ck_proof_challenges_attempts", "attempts >= 0 AND attempts <= max_attempts AND max_attempts > 0");
                    table.CheckConstraint("ck_proof_challenges_completion", "(status IN ('PendingDelivery', 'Active', 'Confirming') AND completed_at IS NULL) OR (status IN ('DeliveryFailed', 'Verified', 'Superseded', 'Exhausted') AND completed_at IS NOT NULL)");
                    table.CheckConstraint("ck_proof_challenges_expiration", "expires_at > created_at AND resend_available_at >= created_at");
                    table.CheckConstraint("ck_proof_challenges_secret_hash_length", "octet_length(secret_hash) = 32");
                    table.ForeignKey(
                        name: "fk_proof_challenges_access_flows",
                        column: x => x.access_flow_id,
                        principalTable: "access_flows",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_proof_challenges_identities",
                        column: x => x.identity_id,
                        principalTable: "identities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "access_flow_requests",
                columns: table => new
                {
                    integration_client_id = table.Column<Guid>(type: "uuid", nullable: false),
                    request_id = table.Column<Guid>(type: "uuid", nullable: false),
                    flow_id = table.Column<Guid>(type: "uuid", nullable: false),
                    kind = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    status = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                    payload_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    result_revision = table.Column<int>(type: "integer", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    issued_session_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_access_flow_requests", x => new { x.integration_client_id, x.request_id });
                    table.CheckConstraint("ck_access_flow_requests_completion", "(status = 'Committed' AND result_revision IS NOT NULL) OR (status IN ('PendingExternal', 'ExternalFailed') AND result_revision IS NULL AND issued_session_id IS NULL)");
                    table.CheckConstraint("ck_access_flow_requests_kind", "kind IN ('Start', 'Action')");
                    table.CheckConstraint("ck_access_flow_requests_payload_hash_length", "octet_length(payload_hash) = 32");
                    table.CheckConstraint("ck_access_flow_requests_result_revision", "result_revision IS NULL OR result_revision > 0");
                    table.CheckConstraint("ck_access_flow_requests_status", "status IN ('PendingExternal', 'Committed', 'ExternalFailed')");
                    table.ForeignKey(
                        name: "fk_access_flow_requests_flows",
                        column: x => x.flow_id,
                        principalTable: "access_flows",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_access_flow_requests_integration_clients",
                        column: x => x.integration_client_id,
                        principalTable: "integration_clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_access_flow_requests_issued_sessions",
                        column: x => x.issued_session_id,
                        principalTable: "identity_sessions",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_access_flow_requests_revisions",
                        columns: x => new { x.flow_id, x.result_revision },
                        principalTable: "access_flow_revisions",
                        principalColumns: new[] { "flow_id", "revision" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "identity_proofs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    access_flow_id = table.Column<Guid>(type: "uuid", nullable: false),
                    identity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    challenge_id = table.Column<Guid>(type: "uuid", nullable: false),
                    type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    subject_identifier_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_identity_proofs", x => x.id);
                    table.ForeignKey(
                        name: "fk_identity_proofs_access_flows",
                        column: x => x.access_flow_id,
                        principalTable: "access_flows",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_identity_proofs_challenges",
                        column: x => x.challenge_id,
                        principalTable: "proof_challenges",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_identity_proofs_identities",
                        column: x => x.identity_id,
                        principalTable: "identities",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_identity_proofs_subject_identifiers",
                        column: x => x.subject_identifier_id,
                        principalTable: "identity_identifiers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "proof_attempts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    challenge_id = table.Column<Guid>(type: "uuid", nullable: false),
                    outcome = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    attempted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_proof_attempts", x => x.id);
                    table.ForeignKey(
                        name: "fk_proof_attempts_challenges",
                        column: x => x.challenge_id,
                        principalTable: "proof_challenges",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_access_flow_data_subjects_realm_identity_flow",
                table: "access_flow_data_subjects",
                columns: new[] { "realm_id", "identity_id", "flow_id" });

            migrationBuilder.CreateIndex(
                name: "ix_access_flow_requests_flow_revision",
                table: "access_flow_requests",
                columns: new[] { "flow_id", "result_revision" });

            migrationBuilder.CreateIndex(
                name: "ix_access_flow_requests_issued_session",
                table: "access_flow_requests",
                column: "issued_session_id");

            migrationBuilder.CreateIndex(
                name: "ux_access_flow_requests_pending_external_flow",
                table: "access_flow_requests",
                column: "flow_id",
                unique: true,
                filter: "status = 'PendingExternal'");

            migrationBuilder.CreateIndex(
                name: "ix_access_flows_application_client",
                table: "access_flows",
                column: "application_client_id");

            migrationBuilder.CreateIndex(
                name: "ix_access_flows_environment_status",
                table: "access_flows",
                columns: new[] { "app_environment_id", "status" });

            migrationBuilder.CreateIndex(
                name: "ix_access_flows_identity_environment",
                table: "access_flows",
                columns: new[] { "identity_id", "app_environment_id" });

            migrationBuilder.CreateIndex(
                name: "ix_access_flows_integration_client",
                table: "access_flows",
                column: "integration_client_id");

            migrationBuilder.CreateIndex(
                name: "ix_access_flows_realm_identity",
                table: "access_flows",
                columns: new[] { "realm_id", "identity_id" });

            migrationBuilder.CreateIndex(
                name: "ix_access_flows_registration_context",
                table: "access_flows",
                column: "registration_context_id");

            migrationBuilder.CreateIndex(
                name: "ix_access_flows_source_session",
                table: "access_flows",
                column: "source_session_id");

            migrationBuilder.CreateIndex(
                name: "ux_access_flows_active_source_session_intent",
                table: "access_flows",
                columns: new[] { "source_session_id", "intent" },
                unique: true,
                filter: "status = 'Active'");

            migrationBuilder.CreateIndex(
                name: "ix_app_environments_workspace_app",
                table: "app_environments",
                columns: new[] { "workspace_id", "app_id" });

            migrationBuilder.CreateIndex(
                name: "ix_app_environments_workspace_realm",
                table: "app_environments",
                columns: new[] { "workspace_id", "realm_id" });

            migrationBuilder.CreateIndex(
                name: "ux_app_environments_app_key",
                table: "app_environments",
                columns: new[] { "app_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_application_clients_artifact_identity",
                table: "application_clients",
                columns: new[] { "app_environment_id", "platform", "application_id", "signing_identity" },
                unique: true,
                filter: "application_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ux_application_clients_environment_key",
                table: "application_clients",
                columns: new[] { "app_environment_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_apps_workspace_key",
                table: "apps",
                columns: new[] { "workspace_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_identity_identifiers_realm_identity_scheme",
                table: "identity_identifiers",
                columns: new[] { "realm_id", "identity_id", "scheme" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_identity_identifiers_realm_scheme_value",
                table: "identity_identifiers",
                columns: new[] { "realm_id", "scheme", "normalized_value" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_identity_proofs_flow_type",
                table: "identity_proofs",
                columns: new[] { "access_flow_id", "type" });

            migrationBuilder.CreateIndex(
                name: "ix_identity_proofs_identity",
                table: "identity_proofs",
                column: "identity_id");

            migrationBuilder.CreateIndex(
                name: "ix_identity_proofs_subject_identifier",
                table: "identity_proofs",
                column: "subject_identifier_id");

            migrationBuilder.CreateIndex(
                name: "ux_identity_proofs_challenge",
                table: "identity_proofs",
                column: "challenge_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_identity_sessions_environment",
                table: "identity_sessions",
                column: "app_environment_id");

            migrationBuilder.CreateIndex(
                name: "ix_identity_sessions_identity_environment",
                table: "identity_sessions",
                columns: new[] { "identity_id", "app_environment_id" });

            migrationBuilder.CreateIndex(
                name: "ux_identity_sessions_token_hash",
                table: "identity_sessions",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_integration_client_secrets_client",
                table: "integration_client_secrets",
                column: "integration_client_id");

            migrationBuilder.CreateIndex(
                name: "ux_integration_clients_environment_key",
                table: "integration_clients",
                columns: new[] { "app_environment_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_password_reset_tokens_environment",
                table: "password_reset_tokens",
                column: "app_environment_id");

            migrationBuilder.CreateIndex(
                name: "ix_password_reset_tokens_identity_created_at",
                table: "password_reset_tokens",
                columns: new[] { "identity_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "ux_password_reset_tokens_token_hash",
                table: "password_reset_tokens",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_phone_password_reset_challenges_environment_phone",
                table: "phone_password_reset_challenges",
                columns: new[] { "app_environment_id", "phone" });

            migrationBuilder.CreateIndex(
                name: "ix_phone_password_reset_challenges_identity_created",
                table: "phone_password_reset_challenges",
                columns: new[] { "identity_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "ux_phone_password_reset_challenges_open_identity_environment",
                table: "phone_password_reset_challenges",
                columns: new[] { "identity_id", "app_environment_id" },
                unique: true,
                filter: "status IN ('PendingDelivery', 'Active', 'Confirming')");

            migrationBuilder.CreateIndex(
                name: "ix_phone_registration_conflicts_phone_identifier",
                table: "phone_registration_conflicts",
                column: "conflicting_phone_identifier_id");

            migrationBuilder.CreateIndex(
                name: "ix_phone_registration_conflicts_previous_identity",
                table: "phone_registration_conflicts",
                column: "previous_identity_id");

            migrationBuilder.CreateIndex(
                name: "ix_proof_attempts_challenge_attempted",
                table: "proof_attempts",
                columns: new[] { "challenge_id", "attempted_at" });

            migrationBuilder.CreateIndex(
                name: "ix_proof_challenges_identity_type_created",
                table: "proof_challenges",
                columns: new[] { "identity_id", "type", "created_at" });

            migrationBuilder.CreateIndex(
                name: "ux_proof_challenges_active_flow_type",
                table: "proof_challenges",
                columns: new[] { "access_flow_id", "type" },
                unique: true,
                filter: "status = 'Active'");

            migrationBuilder.CreateIndex(
                name: "ux_proof_challenges_confirming_flow_type",
                table: "proof_challenges",
                columns: new[] { "access_flow_id", "type" },
                unique: true,
                filter: "status = 'Confirming'");

            migrationBuilder.CreateIndex(
                name: "ux_proof_challenges_pending_delivery_flow_type",
                table: "proof_challenges",
                columns: new[] { "access_flow_id", "type" },
                unique: true,
                filter: "status = 'PendingDelivery'");

            migrationBuilder.CreateIndex(
                name: "ux_realms_workspace_key",
                table: "realms",
                columns: new[] { "workspace_id", "key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_registration_contexts_realm_identity",
                table: "registration_contexts",
                columns: new[] { "realm_id", "identity_id" });

            migrationBuilder.CreateIndex(
                name: "ux_registration_contexts_environment_identity",
                table: "registration_contexts",
                columns: new[] { "app_environment_id", "identity_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_social_credentials_realm_identity",
                table: "social_credentials",
                columns: new[] { "realm_id", "identity_id" });

            migrationBuilder.CreateIndex(
                name: "ux_social_credentials_realm_provider_subject",
                table: "social_credentials",
                columns: new[] { "realm_id", "provider", "subject" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_workspaces_key",
                table: "workspaces",
                column: "key",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "access_flow_data_subjects");

            migrationBuilder.DropTable(
                name: "access_flow_requests");

            migrationBuilder.DropTable(
                name: "identity_proofs");

            migrationBuilder.DropTable(
                name: "integration_client_permissions");

            migrationBuilder.DropTable(
                name: "integration_client_secrets");

            migrationBuilder.DropTable(
                name: "password_credentials");

            migrationBuilder.DropTable(
                name: "password_reset_tokens");

            migrationBuilder.DropTable(
                name: "phone_password_reset_challenges");

            migrationBuilder.DropTable(
                name: "phone_registration_conflicts");

            migrationBuilder.DropTable(
                name: "proof_attempts");

            migrationBuilder.DropTable(
                name: "social_credentials");

            migrationBuilder.DropTable(
                name: "access_flow_revisions");

            migrationBuilder.DropTable(
                name: "identity_identifiers");

            migrationBuilder.DropTable(
                name: "proof_challenges");

            migrationBuilder.DropTable(
                name: "access_flows");

            migrationBuilder.DropTable(
                name: "application_clients");

            migrationBuilder.DropTable(
                name: "integration_clients");

            migrationBuilder.DropTable(
                name: "registration_contexts");

            migrationBuilder.DropTable(
                name: "identity_sessions");

            migrationBuilder.DropTable(
                name: "app_environments");

            migrationBuilder.DropTable(
                name: "identities");

            migrationBuilder.DropTable(
                name: "apps");

            migrationBuilder.DropTable(
                name: "realms");

            migrationBuilder.DropTable(
                name: "workspaces");
        }
    }
}
