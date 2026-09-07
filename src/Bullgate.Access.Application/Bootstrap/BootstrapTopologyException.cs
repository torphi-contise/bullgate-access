namespace Bullgate.Access.Application.Bootstrap;

/// <summary>Reports a manifest contradiction or mismatch with persisted topology.</summary>
public sealed class BootstrapTopologyException(string message) : Exception(message);
