using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;

namespace Bullgate.Access.Cli;

/// <summary>
/// Parses the bootstrap command line, reads the manifest, runs the topology
/// bootstrap, and maps every outcome to an operator message and an exit code.
/// </summary>
/// <remarks>
/// The output streams and the bootstrap execution are supplied by the caller rather
/// than reached through <see cref="Console"/> and a host container. This tool applies
/// migrations, generates the master key, and issues integration credentials, so its
/// exit-code contract and its failure messages need to be exercisable without a
/// database and without a real console.
/// </remarks>
internal sealed class BootstrapCli(
    TextWriter output,
    TextWriter error,
    Func<BootstrapTopologyCommand, CancellationToken, Task<BootstrapTopologyResult>> execute)
{
    private const string Usage =
        "Usage: Bullgate.Access.Cli bootstrap --manifest <path-to-json>";

    /// <summary>Runs one bootstrap invocation.</summary>
    /// <returns>
    /// Zero when the topology was applied, two when the input or the manifest was
    /// rejected before any change, and one when the run failed for any other reason.
    /// </returns>
    public async Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        try
        {
            var manifestPath = ParseManifestPath(args);
            var manifest = await ReadManifestAsync(manifestPath);
            var result = await execute(manifest.ToCommand(), cancellationToken);

            var document = JsonSerializer.Serialize(result, JsonOptions.Output);
            // Newly issued clear credentials appear only in this result. Operators must
            // capture stdout as secret material rather than route it to ordinary logs.
            await output.WriteLineAsync(document);

            if (result.IssuedCredentials.Count == 0)
            {
                await error.WriteLineAsync("Bootstrap completed; no new credentials were issued.");
            }
            else
            {
                await error.WriteLineAsync(
                    $"Bootstrap completed; {result.IssuedCredentials.Count} credential(s) issued once.");
            }

            return 0;
        }
        catch (CliUsageException exception)
        {
            await error.WriteLineAsync(exception.Message);
            await error.WriteLineAsync(Usage);
            return 2;
        }
        catch (JsonException exception)
        {
            await error.WriteLineAsync($"Invalid bootstrap manifest: {exception.Message}");
            return 2;
        }
        catch (BootstrapTopologyException exception)
        {
            await error.WriteLineAsync($"Bootstrap rejected: {exception.Message}");
            return 2;
        }
        catch (ArgumentException exception)
        {
            await error.WriteLineAsync($"Bootstrap rejected: {exception.Message}");
            return 2;
        }
        catch (Exception exception)
        {
            await error.WriteLineAsync($"Bootstrap failed: {exception.Message}");
            return 1;
        }
    }

    private static string ParseManifestPath(string[] args)
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

    private static async Task<BootstrapManifest> ReadManifestAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<BootstrapManifest>(stream, JsonOptions.Input)
            ?? throw new JsonException("The document is empty.");
    }
}
