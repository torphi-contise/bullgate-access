namespace Bullgate.Access.Domain.Administration;

/// <summary>Committed administrative attribution and retry receipt, independent of erased identities.</summary>
public sealed class AdminOperation
{
    private AdminOperation() { }

    public AdminOperation(Guid operationId, string callerId, string operatorId, string sessionId,
        string scopeId, string permission, Guid targetId, Guid? realmId, DateTimeOffset committedAt,
        byte[] requestFingerprint, string resultJson)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(operationId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(targetId, Guid.Empty);
        if (requestFingerprint.Length != 32 || committedAt.Offset != TimeSpan.Zero)
            throw new ArgumentException("Invalid receipt fingerprint or timestamp.");
        OperationId = operationId;
        CallerId = callerId;
        OperatorId = operatorId;
        SessionId = sessionId;
        ScopeId = scopeId;
        Permission = permission;
        TargetId = targetId;
        RealmId = realmId;
        CommittedAt = committedAt;
        RequestFingerprint = requestFingerprint.ToArray();
        ResultJson = resultJson;
    }

    public Guid OperationId { get; private set; }
    public string CallerId { get; private set; } = null!;
    public string OperatorId { get; private set; } = null!;
    public string SessionId { get; private set; } = null!;
    public string ScopeId { get; private set; } = null!;
    public string Permission { get; private set; } = null!;
    public Guid TargetId { get; private set; }
    public Guid? RealmId { get; private set; }
    public DateTimeOffset CommittedAt { get; private set; }
    public byte[] RequestFingerprint { get; private set; } = [];
    public string ResultJson { get; private set; } = null!;
}
