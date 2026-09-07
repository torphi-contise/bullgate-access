namespace Bullgate.Access.Api.Authentication;

/// <summary>
/// Defines the private authentication scheme and claim names used to carry the fixed
/// integration-client topology and permission scope through the HTTP pipeline.
/// </summary>
internal static class IntegrationClientAuthenticationDefaults
{
    /// <summary>Private ASP.NET Core authentication-scheme name.</summary>
    public const string Scheme = "BullgateIntegrationClient";

    /// <summary>Repeated claim type containing one stored permission value.</summary>
    public const string PermissionClaim = "bullgate:permission";

    /// <summary>Claim type for the authenticated workspace boundary.</summary>
    public const string WorkspaceIdClaim = "bullgate:workspace_id";

    /// <summary>Claim type for the authenticated app boundary.</summary>
    public const string AppIdClaim = "bullgate:app_id";

    /// <summary>Claim type for the authenticated environment boundary.</summary>
    public const string AppEnvironmentIdClaim = "bullgate:app_environment_id";

    /// <summary>Claim type for the authenticated identity-realm boundary.</summary>
    public const string RealmIdClaim = "bullgate:realm_id";
}
