using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Bullgate.Access.Migrations.Migrations
{
    /// <inheritdoc />
    public partial class AddAccessAdminOperations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "admin_operations",
                columns: table => new
                {
                    operation_id = table.Column<Guid>(type: "uuid", nullable: false),
                    caller_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    operator_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    session_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    scope_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    permission = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    target_id = table.Column<Guid>(type: "uuid", nullable: false),
                    realm_id = table.Column<Guid>(type: "uuid", nullable: true),
                    committed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    request_fingerprint = table.Column<byte[]>(type: "bytea", nullable: false),
                    result_json = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_admin_operations", x => new { x.caller_id, x.operation_id });
                    table.CheckConstraint("ck_admin_operations_fingerprint", "octet_length(request_fingerprint) = 32");
                    table.CheckConstraint("ck_admin_operations_result", "jsonb_typeof(result_json) = 'object'");
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "admin_operations");
        }
    }
}
