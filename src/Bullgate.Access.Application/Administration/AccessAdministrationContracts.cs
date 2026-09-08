using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Administration;

/// <summary>Bounded exact directory input, not a human authorization partition.</summary>
public sealed record AdminIdentityQuery(
    Guid RealmId, Guid? IdentityId = null, string? Email = null, string? Phone = null,
    int PageSize = 25, string? Cursor = null);

/// <summary>Current identifier only; no proof history or provider credentials.</summary>
public sealed record AdminContact(string Value, bool Verified);

/// <summary>Secret-free Access identity detail shared by directory and point reads.</summary>
public sealed record AdminIdentity(
    Guid Id, Guid RealmId, string Lifecycle, DateTimeOffset CreatedAt,
    AdminContact? Email, AdminContact? Phone);

/// <summary>Environment selector and encrypted-envelope revision, never stored configuration.</summary>
public sealed record AdminEnvironment(
    Guid Id, Guid RealmId, Guid AppId, string AppName, string Key, string Name, string Revision);

/// <summary>One keyset page; no total count or snapshot promise.</summary>
public sealed record AdminPage<T>(IReadOnlyList<T> Items, string? NextCursor);

/// <summary>Committed mutation receipt safe to persist after identity erasure.</summary>
public sealed record AdminOperationResult(
    Guid OperationId, string Permission, Guid TargetId, DateTimeOffset CommittedAt,
    int? RevokedSessions = null, string? Revision = null);

/// <summary>Explicit mutation input; the complete replacement is never part of a result.</summary>
public sealed record AdminMutation(
    Guid OperationId, Guid TargetId, Guid? RealmId = null,
    AppEnvironmentConfiguration? Configuration = null, string? ExpectedRevision = null);

/// <summary>Stable, secret-free failure owned by the administrative contract.</summary>
public sealed class AccessAdministrationException(int statusCode, string code) : Exception(code)
{
    public int StatusCode { get; } = statusCode;
    public string Code { get; } = code;
}
