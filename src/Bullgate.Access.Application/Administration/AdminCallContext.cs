namespace Bullgate.Access.Application.Administration;

/// <summary>Human attribution attested by the authenticated Admin server, never browser authority.</summary>
public sealed record AdminCallContext(
    string OperatorId,
    string SessionId,
    string ScopeId,
    string Permission)
{
    /// <summary>The single configured service caller for this contract version.</summary>
    public const string CallerId = "bullgate-admin";

    /// <summary>Checks bounded, nonempty opaque identifiers before accepting attribution.</summary>
    public bool IsValid() => ValidId(OperatorId) && ValidId(SessionId)
        && ValidId(ScopeId) && ValidId(Permission);

    private static bool ValidId(string? value) => value is { Length: > 0 and <= 128 }
        && !value.Any(char.IsWhiteSpace) && !value.Any(char.IsControl);
}
