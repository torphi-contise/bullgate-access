namespace Bullgate.Access.Domain.Flows;

/// <summary>Persistence and cryptographic size limits shared by flow entities.</summary>
public static class AccessFlowLimits
{
    /// <summary>Exact SHA-256 request-payload hash length in bytes.</summary>
    public const int PayloadHashLength = 32;

    /// <summary>Maximum JSON string length persisted for one revision.</summary>
    public const int SnapshotMaxLength = 32_768;
}
