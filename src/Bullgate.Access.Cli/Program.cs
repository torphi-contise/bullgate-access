using System.Text.Json;
using System.Text.Json.Serialization;
using Bullgate.Access.Application;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Cli;
using Bullgate.Access.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

return await RunAsync(args);

static async Task<int> RunAsync(string[] args)
{
    try
    {
        var manifestPath = ParseManifestPath(args);
        var manifest = await ReadManifestAsync(manifestPath);
        var command = manifest.ToCommand();

        var builder = Host.CreateApplicationBuilder([]);
        // Keep stdout reserved for the single machine-readable result document. Default
        // host log providers could interleave text with JSON or expose bootstrap data.
        builder.Logging.ClearProviders();
        builder.Services.AddAccessApplication();
        builder.Services.AddAccessInfrastructure(builder.Configuration);

        using var host = builder.Build();
        await using var scope = host.Services.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
        var result = await handler.HandleAsync(command);

        var output = JsonSerializer.Serialize(result, JsonOptions.Output);
        // Newly issued clear credentials appear only in this result. Operators must
        // capture stdout as secret material rather than route it to ordinary logs.
        await Console.Out.WriteLineAsync(output);

        if (result.IssuedCredentials.Count == 0)
        {
            await Console.Error.WriteLineAsync("Bootstrap completed; no new credentials were issued.");
        }
        else
        {
            await Console.Error.WriteLineAsync(
                $"Bootstrap completed; {result.IssuedCredentials.Count} credential(s) issued once.");
        }

        return 0;
    }
    catch (CliUsageException exception)
    {
        await Console.Error.WriteLineAsync(exception.Message);
        WriteUsage();
        return 2;
    }
    catch (JsonException exception)
    {
        await Console.Error.WriteLineAsync($"Invalid bootstrap manifest: {exception.Message}");
        return 2;
    }
    catch (BootstrapTopologyException exception)
    {
        await Console.Error.WriteLineAsync($"Bootstrap rejected: {exception.Message}");
        return 2;
    }
    catch (ArgumentException exception)
    {
        await Console.Error.WriteLineAsync($"Bootstrap rejected: {exception.Message}");
        return 2;
    }
    catch (Exception exception)
    {
        await Console.Error.WriteLineAsync($"Bootstrap failed: {exception.Message}");
        return 1;
    }
}

static string ParseManifestPath(string[] args)
{
    if (args.Length == 1 && args[0] is "--help" or "-h")
    {
        throw new CliUsageException("Bullgate Access topology bootstrap.");
    }

    if (args.Length != 3
        || !string.Equals(args[0], "bootstrap", StringComparison.Ordinal)
        || !string.Equals(args[1], "--manifest", StringComparison.Ordinal))
    {
        // The CLI intentionally exposes one exact non-interactive grammar. Silently
        // accepting extra arguments could apply a different manifest than automation
        // intended.
        throw new CliUsageException("Expected the bootstrap command and one manifest path.");
    }

    var path = Path.GetFullPath(args[2]);
    if (!File.Exists(path))
    {
        throw new CliUsageException($"Manifest file does not exist: {path}");
    }

    return path;
}

static async Task<BootstrapManifest> ReadManifestAsync(string path)
{
    await using var stream = File.OpenRead(path);
    return await JsonSerializer.DeserializeAsync<BootstrapManifest>(stream, JsonOptions.Input)
        ?? throw new JsonException("The document is empty.");
}

static void WriteUsage() => Console.Error.WriteLine(
    "Usage: Bullgate.Access.Cli bootstrap --manifest <path-to-json>");

namespace Bullgate.Access.Cli
{
    /// <summary>Represents command-line input that is invalid before bootstrap begins.</summary>
    internal sealed class CliUsageException(string message) : Exception(message);

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
}
