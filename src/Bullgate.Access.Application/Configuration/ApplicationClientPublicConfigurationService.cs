using System.Text.Json;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.Application.Configuration;

/// <summary>
/// Public environment values plus metadata for the requested application build family.
/// </summary>
public sealed record ApplicationClientPublicConfiguration(
    int ConfigurationVersion,
    JsonElement Common,
    ApplicationClientPublicMetadata Client);

/// <summary>
/// Non-secret platform metadata selected by the stable application-client key.
/// </summary>
public sealed record ApplicationClientPublicMetadata(
    string Key,
    string Name,
    string Platform,
    string? ApplicationId,
    string? SigningIdentity,
    string? SmsRetrieverAppHash,
    JsonElement Configuration);

/// <summary>
/// Projects a deliberately public subset of protected environment configuration.
/// </summary>
public sealed class ApplicationClientPublicConfigurationService(
    IAppEnvironmentConfigurationReader configurations)
{
    /// <summary>
    /// Selects explicitly public common and client metadata from one authenticated
    /// environment configuration.
    /// </summary>
    /// <returns>
    /// The public projection, or <see langword="null"/> when the public key is invalid,
    /// the environment is unavailable, or the key is not declared in that environment.
    /// </returns>
    /// <remarks>
    /// The app environment is fixed by integration authentication before this service is
    /// called. <paramref name="applicationClientKey"/> is only a selector inside that
    /// scope and is never accepted as authorization.
    /// </remarks>
    public async Task<ApplicationClientPublicConfiguration?> FindAsync(
        Guid appEnvironmentId,
        string? applicationClientKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(appEnvironmentId, Guid.Empty);

        string validatedKey;
        try
        {
            validatedKey = TopologyValue.Key(
                applicationClientKey!,
                nameof(applicationClientKey));
        }
        catch (ArgumentException)
        {
            return null;
        }

        var configuration = await configurations.FindAsync(
            appEnvironmentId,
            cancellationToken);
        // The key selects metadata only after integration authentication has fixed the
        // environment. It is public routing input, never an authorization credential.
        var client = configuration?.ApplicationClients.SingleOrDefault(
            item => string.Equals(
                item.Key,
                validatedKey,
                StringComparison.Ordinal));
        if (configuration is null || client is null)
        {
            return null;
        }

        // Clone JsonElement values before returning them so the projection owns its data
        // independently of serializer/document lifetimes and cannot expose the containing
        // secret-bearing configuration object.
        return new ApplicationClientPublicConfiguration(
            configuration.PublicConfiguration.Version,
            configuration.PublicConfiguration.Values.Clone(),
            new ApplicationClientPublicMetadata(
                client.Key,
                client.Name,
                client.Platform switch
                {
                    ApplicationClientPlatform.Android => "android",
                    ApplicationClientPlatform.Ios => "ios",
                    ApplicationClientPlatform.Web => "web",
                    _ => throw new InvalidOperationException(
                        "Application client platform is unsupported."),
                },
                client.ApplicationId,
                client.SigningIdentity,
                client.SmsRetrieverAppHash,
                client.PublicConfiguration.Clone()));
    }
}
