using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Bullgate.Access.Migrations.Migrations
{
    /// <inheritdoc />
    public partial class ConfigureCpfCollectionPosition : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "cpf_collection_position",
                table: "app_environments",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_app_environments_cpf_after_required_phone",
                table: "app_environments",
                sql: "cpf_collection_position IS DISTINCT FROM 'AfterPhone' OR (phone_identifier_enabled AND phone_identifier_required)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_app_environments_cpf_after_required_phone",
                table: "app_environments");

            migrationBuilder.DropColumn(
                name: "cpf_collection_position",
                table: "app_environments");
        }
    }
}
