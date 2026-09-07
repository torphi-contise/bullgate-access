namespace Bullgate.Access.Application.Flows;

/// <summary>
/// Protects and validates flow capabilities and generates terminal session tokens.
/// </summary>
/// <remarks>Raw capability and session material is server-only bearer authority.</remarks>
public interface IAccessFlowTokenService
{
    /// <summary>
    /// Derives the capability bound to one flow, integration client, and app environment.
    /// </summary>
    string IssueCapability(
        Guid flowId,
        Guid integrationClientId,
        Guid appEnvironmentId);

    /// <summary>
    /// Validates the complete capability shape and scoped value without accepting a
    /// flow id or token prefix as authority by itself.
    /// </summary>
    bool IsValidCapability(
        string? capability,
        Guid flowId,
        Guid integrationClientId,
        Guid appEnvironmentId);

    /// <summary>
    /// Deterministically derives the terminal product token for one committed flow
    /// request and returns the hash that is safe to persist.
    /// </summary>
    IssuedAccessFlowSessionToken IssueSession(
        Guid flowId,
        Guid requestId,
        Guid identityId,
        Guid appEnvironmentId);
}

/// <summary>Deterministically issued terminal session token and its persistent hash.</summary>
/// <remarks>
/// <see cref="Token"/> is clear bearer authority and must not be logged or persisted;
/// <see cref="TokenHash"/> is the durable replay verifier.
/// </remarks>
public sealed record IssuedAccessFlowSessionToken(string Token, byte[] TokenHash);
