using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bullgate.Access.Cli;

/// <summary>
/// Defines strict manifest input and deterministic machine-readable result formats.
/// </summary>
internal static class JsonOptions
{
    public static JsonSerializerOptions Input { get; } = new()
    {
        // Manifest property names form a versioned contract. Case-insensitive or unknown
        // members could turn an operator typo into silently ignored security policy.
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static JsonSerializerOptions Output { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };
}
