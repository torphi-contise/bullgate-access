using Npgsql;

namespace Bullgate.Access.IntegrationTests;

/// <summary>Rejects a scoped insert after the target row reaches PostgreSQL.</summary>
internal sealed class PostgreSqlInsertFault : IAsyncDisposable
{
    private readonly string connectionString;
    private readonly string table;
    private readonly string name;

    private PostgreSqlInsertFault(string connectionString, string table, string name)
    {
        this.connectionString = connectionString;
        this.table = table;
        this.name = name;
    }

    public static async Task<PostgreSqlInsertFault> CreateAsync(
        string connectionString,
        string table,
        Guid environmentId,
        string sqlState = PostgresErrorCodes.CheckViolation)
    {
        if (table is not (
            "registration_contexts"
            or "identity_sessions"
            or "access_flow_revisions"))
        {
            throw new ArgumentOutOfRangeException(nameof(table));
        }
        if (sqlState is not (PostgresErrorCodes.CheckViolation or PostgresErrorCodes.UniqueViolation))
        {
            throw new ArgumentOutOfRangeException(nameof(sqlState));
        }
        var name = $"test_insert_fault_{Guid.NewGuid():N}";
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var targetGuard = table == "access_flow_revisions"
            ? $$"""
                IF NOT EXISTS (
                    SELECT 1 FROM access_flows
                    WHERE id = NEW.flow_id
                      AND app_environment_id = '{{environmentId:D}}'::uuid) THEN
                    RETURN NEW;
                END IF;
                """
            : $$"""
                IF NEW.app_environment_id != '{{environmentId:D}}'::uuid THEN
                    RETURN NEW;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM identities WHERE id = NEW.identity_id)
                   OR NOT EXISTS (
                       SELECT 1 FROM identity_identifiers
                       WHERE identity_id = NEW.identity_id AND scheme = 'email') THEN
                    RAISE EXCEPTION 'Insert fault reached before prerequisite account rows';
                END IF;
                """;
        command.CommandText = $$"""
            CREATE SEQUENCE {{name}};
            CREATE FUNCTION {{name}}() RETURNS trigger LANGUAGE plpgsql AS $fault$
            BEGIN
                {{targetGuard}}
                PERFORM nextval('{{name}}');
                RAISE EXCEPTION USING
                    ERRCODE = '{{sqlState}}',
                    CONSTRAINT = '{{name}}',
                    MESSAGE = 'Controlled integration-test insert failure';
            END;
            $fault$;
            CREATE TRIGGER {{name}} AFTER INSERT ON {{table}}
            FOR EACH ROW EXECUTE FUNCTION {{name}}();
            """;
        await command.ExecuteNonQueryAsync();
        await transaction.CommitAsync();
        return new PostgreSqlInsertFault(connectionString, table, name);
    }

    public async Task<bool> WasTriggeredAsync()
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        // Sequence advancement survives rollback, proving the intended fault was reached.
        command.CommandText = $"SELECT is_called FROM {name}";
        return (bool)(await command.ExecuteScalarAsync())!;
    }

    public async ValueTask DisposeAsync()
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            DROP TRIGGER {name} ON {table};
            DROP FUNCTION {name}();
            DROP SEQUENCE {name};
            """;
        await command.ExecuteNonQueryAsync();
    }
}
