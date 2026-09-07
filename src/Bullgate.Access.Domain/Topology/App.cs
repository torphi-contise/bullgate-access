namespace Bullgate.Access.Domain.Topology;

/// <summary>Consumer product registered inside a workspace.</summary>
public sealed class App
{
    private App()
    {
    }

    /// <summary>Creates an active consumer application inside one workspace.</summary>
    public App(Guid id, Guid workspaceId, string key, string name, DateTimeOffset createdAt)
    {
        Id = TopologyValue.Id(id, nameof(id));
        WorkspaceId = TopologyValue.Id(workspaceId, nameof(workspaceId));
        Key = TopologyValue.Key(key, nameof(key));
        Name = TopologyValue.Name(name, nameof(name));
        CreatedAt = TopologyValue.UtcTimestamp(createdAt, nameof(createdAt));
        IsActive = true;
    }

    /// <summary>Durable internal identifier.</summary>
    public Guid Id { get; private set; }

    /// <summary>Owning workspace and bootstrap natural-key scope.</summary>
    public Guid WorkspaceId { get; private set; }

    /// <summary>Stable natural key inside the workspace.</summary>
    public string Key { get; private set; } = null!;

    /// <summary>Human-readable application name.</summary>
    public string Name { get; private set; } = null!;

    /// <summary>Whether descendants may participate in effective authentication.</summary>
    public bool IsActive { get; private set; }

    /// <summary>UTC creation time.</summary>
    public DateTimeOffset CreatedAt { get; private set; }
}
