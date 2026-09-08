using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Bullgate.Access.Migrations.Migrations
{
    /// <inheritdoc />
    public partial class AddCpfAndBirthDatePolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateOnly>(
                name: "birth_date",
                table: "identities",
                type: "date",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "cpf_identifier_enabled",
                table: "app_environments",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "cpf_identifier_required",
                table: "app_environments",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "birth_date",
                table: "identities");

            migrationBuilder.DropColumn(
                name: "cpf_identifier_enabled",
                table: "app_environments");

            migrationBuilder.DropColumn(
                name: "cpf_identifier_required",
                table: "app_environments");
        }
    }
}
