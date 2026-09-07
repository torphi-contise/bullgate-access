namespace Bullgate.Access.Domain.Topology;

/// <summary>Top-level ownership and isolation container for Bullgate resources.</summary>
public sealed class Workspace
{
    private Workspace()
    {
    }

    /// <summary>Creates an active top-level ownership boundary.</summary>
    public Workspace(Guid id, string key, string name, DateTimeOffset createdAt)
    {
        Id = TopologyValue.Id(id, nameof(id));
        Key = TopologyValue.Key(key, nameof(key));
        Name = TopologyValue.Name(name, nameof(name));
        CreatedAt = TopologyValue.UtcTimestamp(createdAt, nameof(createdAt));
        IsActive = true;
    }

    /// <summary>Durable internal identifier.</summary>
    public Guid Id { get; private set; }

    /// <summary>Stable natural key used by bootstrap reconciliation.</summary>
    public string Key { get; private set; } = null!;

    /// <summary>Human-readable workspace name.</summary>
    public string Name { get; private set; } = null!;

    /// <summary>Whether descendants may participate in effective authentication.</summary>
    public bool IsActive { get; private set; }

    /// <summary>UTC creation time.</summary>
    public DateTimeOffset CreatedAt { get; private set; }
}
