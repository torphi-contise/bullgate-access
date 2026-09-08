namespace Bullgate.Access.Domain.Topology;

/// <summary>
/// Stable Access-owned permission names, with separate allowed caller vocabularies.
/// </summary>
/// <remarks>
/// Defining a constant does not expose an HTTP operation. Endpoint mapping must opt
/// into a permission explicitly, and the authenticated credential still fixes the
/// environment and realm scope.
/// </remarks>
public static class AccessPermission
{
    /// <summary>Starts, reads, and advances AccessFlow journeys.</summary>
    public const string ExecuteFlows = "access:flows:execute";
    /// <summary>Reads the activity and scope of an identity session bearer.</summary>
    public const string IntrospectSessions = "access:sessions:introspect";
    /// <summary>Revokes the session selected by the submitted bearer.</summary>
    public const string RevokeCurrentSession = "access:sessions:revoke-current";
    /// <summary>Mutates or erases the identity selected by an active product session.</summary>
    public const string ManageCurrentIdentity = "access:identities:manage-current";
    /// <summary>Reads identities within the credential-fixed realm.</summary>
    public const string ReadIdentities = "access:identities:read";
    /// <summary>Reserved vocabulary for blocking scoped identities.</summary>
    public const string BlockIdentities = "access:identities:block";
    /// <summary>Reserved vocabulary for unblocking scoped identities.</summary>
    public const string UnblockIdentities = "access:identities:unblock";
    /// <summary>Revokes all current identity sessions through administrative authentication only.</summary>
    public const string RevokeAllSessions = "access:sessions:revoke-all";

    /// <summary>Enumerates identities through the trusted Admin service.</summary>
    public const string ListIdentities = "access:identities:list";
    /// <summary>Erases the selected Access identity through the trusted Admin service.</summary>
    public const string DeleteIdentities = "access:identities:delete";
    /// <summary>Reads target revisions and replaces complete environment configuration.</summary>
    public const string ManageConfiguration = "access:configuration:manage";

    /// <summary>Exact administrative functions; this does not widen consumer grants.</summary>
    public static IReadOnlyList<string> Administrative { get; } = Array.AsReadOnly(
    [
        ListIdentities,
        ReadIdentities,
        RevokeAllSessions,
        DeleteIdentities,
        ManageConfiguration,
    ]);

    /// <summary>Closed permission vocabulary accepted in persisted integration clients.</summary>
    public static IReadOnlyList<string> All { get; } = Array.AsReadOnly(
    [
        ExecuteFlows,
        IntrospectSessions,
        RevokeCurrentSession,
        ManageCurrentIdentity,
        ReadIdentities,
        BlockIdentities,
        UnblockIdentities,
        RevokeAllSessions,
    ]);

    /// <summary>Returns whether a value is part of the Access permission vocabulary.</summary>
    public static bool IsDefined(string value) => value is
        ExecuteFlows
        or IntrospectSessions
        or RevokeCurrentSession
        or ManageCurrentIdentity
        or ReadIdentities
        or BlockIdentities
        or UnblockIdentities
        or RevokeAllSessions;

    /// <summary>Validates and returns a permission suitable for persisted topology.</summary>
    public static string RequireDefined(string value, string parameterName)
    {
        TopologyValue.Permission(value, parameterName);

        if (!IsDefined(value))
        {
            throw new ArgumentException("Permission is not defined by Bullgate Access.", parameterName);
        }

        return value;
    }
}
