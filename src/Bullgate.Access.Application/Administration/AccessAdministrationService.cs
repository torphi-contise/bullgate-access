using System.Security.Cryptography;
using System.Text.Json;
using Bullgate.Access.Application.Configuration;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Administration;

/// <summary>Exact function and input checks before Access-owned persistence.</summary>
public sealed class AccessAdministrationService(IAccessAdministrationStore store)
{
    public async Task<AdminPage<AdminIdentity>> ListIdentitiesAsync(
        AdminCallContext context, AdminIdentityQuery query, CancellationToken cancellationToken = default)
    {
        Require(context, AccessPermission.ListIdentities);
        RequireId(query.RealmId);
        RequirePageSize(query.PageSize);
        if (query.IdentityId == Guid.Empty || query.Email is { Length: 0 or > 320 }
            || query.Phone is { Length: 0 or > 32 })
            throw InvalidInput();
        var binding = Binding(new { query.RealmId, query.IdentityId, query.Email, query.Phone, query.PageSize });
        var afterId = DecodeCursor(query.Cursor, binding);
        var rows = await store.ListIdentitiesAsync(query, afterId, cancellationToken);
        return Page(rows, query.PageSize, binding, row => row.Id);
    }

    public async Task<AdminIdentity> ReadIdentityAsync(
        AdminCallContext context, Guid realmId, Guid identityId, CancellationToken cancellationToken = default)
    {
        Require(context, AccessPermission.ReadIdentities);
        RequireId(realmId);
        RequireId(identityId);
        return await store.ReadIdentityAsync(realmId, identityId, cancellationToken)
            ?? throw new AccessAdministrationException(404, "target-not-found");
    }

    public async Task<AdminPage<AdminEnvironment>> ListEnvironmentsAsync(
        AdminCallContext context, int pageSize = 25, string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        Require(context, AccessPermission.ManageConfiguration);
        RequirePageSize(pageSize);
        var binding = Binding(new { Resource = "environments", PageSize = pageSize });
        var rows = await store.ListEnvironmentsAsync(pageSize, DecodeCursor(cursor, binding), cancellationToken);
        return Page(rows, pageSize, binding, row => row.Id);
    }

    public Task<AdminOperationResult> RevokeSessionsAsync(
        AdminCallContext context, Guid realmId, Guid identityId, Guid operationId,
        CancellationToken cancellationToken = default) =>
        MutateIdentityAsync(context, AccessPermission.RevokeAllSessions, realmId, identityId, operationId, cancellationToken);

    public Task<AdminOperationResult> DeleteIdentityAsync(
        AdminCallContext context, Guid realmId, Guid identityId, Guid operationId,
        CancellationToken cancellationToken = default) =>
        MutateIdentityAsync(context, AccessPermission.DeleteIdentities, realmId, identityId, operationId, cancellationToken);

    public Task<AdminOperationResult> ReplaceConfigurationAsync(
        AdminCallContext context, Guid environmentId, Guid operationId, string? expectedRevision,
        AppEnvironmentConfiguration configuration, CancellationToken cancellationToken = default)
    {
        Require(context, AccessPermission.ManageConfiguration);
        RequireId(environmentId);
        RequireId(operationId);
        // Require one strong ETag, never a wildcard or weak match.
        if (expectedRevision is not { Length: 66 } || expectedRevision[0] != '"'
            || expectedRevision[^1] != '"') throw InvalidInput();
        if (!expectedRevision.AsSpan(1, 64).ToArray().All(char.IsAsciiHexDigit)) throw InvalidInput();
        try { AppEnvironmentConfigurationValidator.Validate(configuration, "configuration"); }
        catch (Exception exception) when (exception is ArgumentException or Bootstrap.BootstrapTopologyException)
        { throw InvalidInput(); }
        return store.MutateAsync(context,
            new AdminMutation(operationId, environmentId, Configuration: configuration, ExpectedRevision: expectedRevision),
            cancellationToken);
    }

    private Task<AdminOperationResult> MutateIdentityAsync(
        AdminCallContext context, string permission, Guid realmId, Guid identityId, Guid operationId,
        CancellationToken cancellationToken)
    {
        Require(context, permission);
        RequireId(realmId);
        RequireId(identityId);
        RequireId(operationId);
        return store.MutateAsync(context, new AdminMutation(operationId, identityId, realmId), cancellationToken);
    }

    private static void Require(AdminCallContext context, string permission)
    {
        if (context is null || !context.IsValid())
            throw new AccessAdministrationException(401, "admin-context-invalid");
        if (!string.Equals(context.Permission, permission, StringComparison.Ordinal))
            throw new AccessAdministrationException(403, "admin-permission-required");
    }

    private static void RequireId(Guid value) { if (value == Guid.Empty) throw InvalidInput(); }
    private static void RequirePageSize(int value) { if (value is < 1 or > 50) throw InvalidInput(); }
    private static AccessAdministrationException InvalidInput() => new(400, "admin-input-invalid");
    private static string Binding<T>(T input) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(input)));
    private sealed record CursorValue(Guid AfterId, string Binding);
    private static Guid? DecodeCursor(string? cursor, string binding)
    {
        if (cursor is null) return null;
        try
        {
            if (cursor.Length is 0 or > 512) throw InvalidInput();
            var encoded = cursor.Replace('-', '+').Replace('_', '/');
            var bytes = Convert.FromBase64String(encoded.PadRight((encoded.Length + 3) / 4 * 4, '='));
            var value = JsonSerializer.Deserialize<CursorValue>(bytes);
            if (value is null || value.AfterId == Guid.Empty || value.Binding != binding) throw InvalidInput();
            return value.AfterId;
        }
        catch (Exception exception) when (exception is FormatException or JsonException) { throw InvalidInput(); }
    }
    private static AdminPage<T> Page<T>(IReadOnlyList<T> rows, int size, string binding, Func<T, Guid> id)
    {
        var items = rows.Take(size).ToArray();
        var cursor = rows.Count > size
            ? Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new CursorValue(id(items[^1]), binding)))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_')
            : null;
        return new AdminPage<T>(items, cursor);
    }
}
