namespace Bullgate.Access.Domain.Topology;

/// <summary>
/// Trusted server-side consumer registered in one application environment.
/// </summary>
/// <remarks>
/// The client receives explicit permissions and one or more rotatable secret hashes.
/// It is not a mobile or browser application identity.
/// </remarks>
public sealed class IntegrationClient
{
    private IntegrationClient()
    {
    }

    /// <summary>Creates an active server-side client in one app environment.</summary>
    public IntegrationClient(
        Guid id,
        Guid appEnvironmentId,
        string key,
        string name,
        DateTimeOffset createdAt)
    {
        Id = TopologyValue.Id(id, nameof(id));
        AppEnvironmentId = TopologyValue.Id(appEnvironmentId, nameof(appEnvironmentId));
        Key = TopologyValue.Key(key, nameof(key));
        Name = TopologyValue.Name(name, nameof(name));
        CreatedAt = TopologyValue.UtcTimestamp(createdAt, nameof(createdAt));
        IsActive = true;
    }

    /// <summary>Internal topology identifier and credential owner.</summary>
    public Guid Id { get; private set; }

    /// <summary>Single environment that fixes app, realm, workspace, and provider scope.</summary>
    public Guid AppEnvironmentId { get; private set; }

    /// <summary>Stable manifest key used for idempotent topology reconciliation.</summary>
    public string Key { get; private set; } = null!;

    /// <summary>Operator-facing name; it grants no authority.</summary>
    public string Name { get; private set; } = null!;

    /// <summary>Local activity flag included in effective authentication scope.</summary>
    public bool IsActive { get; private set; }

    /// <summary>UTC topology creation time.</summary>
    public DateTimeOffset CreatedAt { get; private set; }
}

/// <summary>One stable Access permission granted to an integration client.</summary>
public sealed class IntegrationClientPermission
{
    private IntegrationClientPermission()
    {
    }

    /// <summary>Grants one name from the closed Access permission vocabulary.</summary>
    public IntegrationClientPermission(Guid integrationClientId, string value)
    {
        IntegrationClientId = TopologyValue.Id(integrationClientId, nameof(integrationClientId));
        Value = AccessPermission.RequireDefined(value, nameof(value));
    }

    /// <summary>Client receiving this grant.</summary>
    public Guid IntegrationClientId { get; private set; }

    /// <summary>Exact canonical permission required by an endpoint policy.</summary>
    public string Value { get; private set; } = null!;
}
