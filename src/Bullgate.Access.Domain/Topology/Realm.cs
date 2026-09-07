namespace Bullgate.Access.Domain.Topology;

/// <summary>
/// Identity isolation boundary in which identifiers and social subjects are unique.
/// </summary>
public sealed class Realm
{
    private Realm()
    {
    }

    /// <summary>Creates an active identity partition inside one workspace.</summary>
    public Realm(Guid id, Guid workspaceId, string key, string name, DateTimeOffset createdAt)
    {
        Id = TopologyValue.Id(id, nameof(id));
        WorkspaceId = TopologyValue.Id(workspaceId, nameof(workspaceId));
        Key = TopologyValue.Key(key, nameof(key));
        Name = TopologyValue.Name(name, nameof(name));
        CreatedAt = TopologyValue.UtcTimestamp(createdAt, nameof(createdAt));
        IsActive = true;
    }

    /// <summary>Durable internal identity-partition identifier.</summary>
    public Guid Id { get; private set; }

    /// <summary>Workspace inside which identifiers and social subjects are isolated.</summary>
    public Guid WorkspaceId { get; private set; }

    /// <summary>Stable workspace-wide realm key.</summary>
    public string Key { get; private set; } = null!;

    /// <summary>Human-readable realm name.</summary>
    public string Name { get; private set; } = null!;

    /// <summary>Whether identities in this partition may authenticate.</summary>
    public bool IsActive { get; private set; }

    /// <summary>UTC creation time.</summary>
    public DateTimeOffset CreatedAt { get; private set; }
}
