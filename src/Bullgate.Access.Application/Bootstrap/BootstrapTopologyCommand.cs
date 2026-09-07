using System.Text.Json;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Bootstrap;

/// <summary>Declarative root manifest for one workspace topology.</summary>
public sealed record BootstrapTopologyCommand(
    string WorkspaceKey,
    string WorkspaceName,
    IReadOnlyList<BootstrapAppDefinition> Apps);

/// <summary>Declares one app and all realms and environments it owns.</summary>
public sealed record BootstrapAppDefinition(
    string Key,
    string Name,
    IReadOnlyList<BootstrapRealmDefinition> Realms,
    IReadOnlyList<BootstrapEnvironmentDefinition> Environments);

/// <summary>Declares a stable identity-partition key within a workspace.</summary>
public sealed record BootstrapRealmDefinition(string Key, string Name);

/// <summary>
/// Declares one deployable environment, its policy, providers, public values, and clients.
/// </summary>
public sealed record BootstrapEnvironmentDefinition(
    string Key,
    string Name,
    string RealmKey,
    AppAccessPolicy AccessPolicy,
    AppVerificationPolicy VerificationPolicy,
    AppRecoveryPolicy RecoveryPolicy,
    AppEnvironmentProviders Providers,
    DevelopmentBypassConfiguration DevelopmentBypass,
    AppEnvironmentPublicConfiguration PublicConfiguration,
    IReadOnlyList<BootstrapIntegrationClientDefinition> IntegrationClients,
    IReadOnlyList<BootstrapApplicationClientDefinition> ApplicationClients)
{
    /// <summary>
    /// Creates an environment definition with an empty version-1 public document for
    /// callers that do not yet provide public metadata.
    /// </summary>
    public BootstrapEnvironmentDefinition(
        string key,
        string name,
        string realmKey,
        AppAccessPolicy accessPolicy,
        AppVerificationPolicy verificationPolicy,
        AppRecoveryPolicy recoveryPolicy,
        AppEnvironmentProviders providers,
        DevelopmentBypassConfiguration developmentBypass,
        IReadOnlyList<BootstrapIntegrationClientDefinition> integrationClients,
        IReadOnlyList<BootstrapApplicationClientDefinition> applicationClients)
        : this(
            key,
            name,
            realmKey,
            accessPolicy,
            verificationPolicy,
            recoveryPolicy,
            providers,
            developmentBypass,
            new AppEnvironmentPublicConfiguration(
                1,
                JsonSerializer.SerializeToElement(new { })),
            integrationClients,
            applicationClients)
    {
    }

    /// <summary>
    /// Builds the complete secret-bearing environment document that bootstrap protects
    /// before persistence; this projection is not public client configuration.
    /// </summary>
    public AppEnvironmentConfiguration Configuration => new(
        AccessPolicy,
        VerificationPolicy,
        RecoveryPolicy,
        Providers,
        DevelopmentBypass,
        PublicConfiguration,
        IntegrationClients.Select(client =>
            new AppEnvironmentIntegrationClientConfiguration(
                client.Key,
                client.Name,
                client.Permissions)).ToArray(),
        ApplicationClients.Select(client =>
            new AppEnvironmentApplicationClientConfiguration(
                client.Key,
                client.Name,
                client.Platform,
                client.ApplicationId,
                client.SigningIdentity,
                client.SmsRetrieverAppHash,
                client.PublicConfiguration)).ToArray());
}

/// <summary>Declares one server integration client and its exact permission set.</summary>
public sealed record BootstrapIntegrationClientDefinition(
    string Key,
    string Name,
    IReadOnlyList<string> Permissions);

/// <summary>Declares public metadata for a mobile or web build family.</summary>
public sealed record BootstrapApplicationClientDefinition(
    string Key,
    string Name,
    ApplicationClientPlatform Platform,
    string? ApplicationId,
    string? SigningIdentity,
    string? SmsRetrieverAppHash,
    JsonElement PublicConfiguration);

/// <summary>Reports resolved resource ids and credentials issued during this run.</summary>
public sealed record BootstrapTopologyResult(
    Guid WorkspaceId,
    IReadOnlyList<BootstrapResolvedResource> Resources,
    IReadOnlyList<IssuedIntegrationClientCredential> IssuedCredentials);

/// <summary>Maps a manifest path to its persistent resource id.</summary>
public sealed record BootstrapResolvedResource(string Type, string Path, Guid Id);

/// <summary>
/// One-time clear credential returned only for a newly created integration client.
/// </summary>
public sealed record IssuedIntegrationClientCredential(
    string IntegrationClientPath,
    Guid IntegrationClientId,
    Guid CredentialId,
    string Token);
