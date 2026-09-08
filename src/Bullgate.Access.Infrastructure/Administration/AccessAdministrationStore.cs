using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bullgate.Access.Application.Administration;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.Cryptography;
using Bullgate.Access.Domain.Administration;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Administration;

/// <summary>Database authority for bounded reads, local effects and committed Admin receipts.</summary>
internal sealed partial class AccessAdministrationStore(
    AccessDbContext dbContext, IAccessTopologyStore topologyStore,
    IInstallationKeyDeriver keyDeriver, TimeProvider timeProvider) : IAccessAdministrationStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public async Task<AdminOperationResult> MutateAsync(
        AdminCallContext context, AdminMutation mutation, CancellationToken cancellationToken)
    {
        var fingerprint = Fingerprint(context, mutation);
        dbContext.ChangeTracker.Clear();
        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
        // Serialize one caller/operation namespace before checking either the receipt or target.
        // Unrelated operations use independent locks; bootstrap retains its existing fixed key.
        var lockHash = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { AdminCallContext.CallerId, mutation.OperationId }));
        var lockId = BinaryPrimitives.ReadInt64BigEndian(lockHash);
        await dbContext.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock({lockId})", cancellationToken);
        var prior = await dbContext.AdminOperations.AsNoTracking().SingleOrDefaultAsync(
            item => item.CallerId == AdminCallContext.CallerId && item.OperationId == mutation.OperationId, cancellationToken);
        if (prior is not null)
        {
            if (!CryptographicOperations.FixedTimeEquals(prior.RequestFingerprint, fingerprint))
                throw new AccessAdministrationException(409, "operation-id-conflict");
            return JsonSerializer.Deserialize<AdminOperationResult>(prior.ResultJson, Json)
                ?? throw new InvalidOperationException("Committed administrative receipt is invalid.");
        }

        AdminOperationResult result;
        if (context.Permission == AccessPermission.ManageConfiguration)
            result = await ReplaceConfigurationAsync(context, mutation, cancellationToken);
        else if (context.Permission is AccessPermission.RevokeAllSessions or AccessPermission.DeleteIdentities)
            result = await MutateIdentityAsync(context, mutation, cancellationToken);
        else
            throw new AccessAdministrationException(403, "admin-permission-required");

        dbContext.AdminOperations.Add(new AdminOperation(mutation.OperationId, AdminCallContext.CallerId,
            context.OperatorId, context.SessionId, context.ScopeId, context.Permission,
            mutation.TargetId, mutation.RealmId, result.CommittedAt, fingerprint, JsonSerializer.Serialize(result, Json)));
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private byte[] Fingerprint(AdminCallContext context, AdminMutation mutation)
    {
        // Fresh sessions may retry the same human decision; original session attribution stays in the receipt.
        // The input may contain low-entropy provider secrets. Persist only a purpose-keyed HMAC.
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            AdminCallContext.CallerId, context.OperatorId, context.ScopeId, context.Permission, Mutation = mutation,
        }, Json);
        var key = keyDeriver.DeriveKey("admin-operation-input-v1");
        try { return HMACSHA256.HashData(key, bytes); }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(bytes); }
    }

    private static AccessAdministrationException NotFound() => new(404, "target-not-found");
    private static AccessAdministrationException InvalidInput() => new(400, "admin-input-invalid");

    private static string Revision(Guid id, int version, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        // All variable fields are length-framed by JSON; only encrypted bytes enter this digest.
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { id, version, nonce, ciphertext, tag });
        return $"\"{Convert.ToHexString(SHA256.HashData(bytes))}\"";
    }
}
