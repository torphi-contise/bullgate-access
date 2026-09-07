using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Cli;

namespace Bullgate.Access.UnitTests;

/// <summary>
/// Covers the exit-code contract and the operator messages of the bootstrap tool.
/// </summary>
/// <remarks>
/// This CLI applies migrations, generates the master key, and issues integration
/// credentials, so its failure paths are part of the installation contract. Each case
/// asserts both the exit code that automation reads and the text an operator sees.
/// </remarks>
public sealed class BootstrapCliTests : IDisposable
{
    private const string MinimalManifest =
        """{"manifestVersion":2,"workspace":{"key":"example","name":"Example","apps":[]}}""";

    private readonly List<string> temporaryFiles = [];
    private readonly StringWriter output = new();
    private readonly StringWriter error = new();

    public void Dispose()
    {
        output.Dispose();
        error.Dispose();
        foreach (var path in temporaryFiles)
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task RunAsync_WithoutIssuedCredentials_ReportsCompletionAndSucceeds()
    {
        var result = CreateResult();

        var exitCode = await RunAsync(Arguments(MinimalManifest), (_, _) => Task.FromResult(result));

        Assert.Equal(0, exitCode);
        Assert.Contains("Bootstrap completed; no new credentials were issued.", error.ToString());
        // stdout carries the machine-readable document and nothing else.
        using var document = JsonDocument.Parse(output.ToString());
        Assert.Equal(
            result.WorkspaceId,
            document.RootElement.GetProperty("workspaceId").GetGuid());
    }

    [Fact]
    public async Task RunAsync_WithIssuedCredentials_ReportsTheOneTimeCountAndSucceeds()
    {
        var result = CreateResult(new IssuedIntegrationClientCredential(
            "example/example-app/development/integration-clients/api",
            Guid.NewGuid(),
            Guid.NewGuid(),
            "bgic_example.secret"));

        var exitCode = await RunAsync(Arguments(MinimalManifest), (_, _) => Task.FromResult(result));

        Assert.Equal(0, exitCode);
        Assert.Contains("1 credential(s) issued once.", error.ToString());
    }

    [Fact]
    public async Task RunAsync_WithShippedExampleManifest_ConvertsAndSucceeds()
    {
        BootstrapTopologyCommand? captured = null;
        var manifest = await File.ReadAllTextAsync("bootstrap.development.example.json");

        var exitCode = await RunAsync(
            Arguments(manifest),
            (command, _) =>
            {
                captured = command;
                return Task.FromResult(CreateResult());
            });

        Assert.Equal(0, exitCode);
        // The example that ships with the repository must keep converting; it is the
        // document operators copy when they bootstrap their first installation.
        Assert.NotNull(captured);
        Assert.Equal("example", captured.WorkspaceKey);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    public async Task RunAsync_WithHelpRequest_PrintsUsageAndRejects(string flag)
    {
        var exitCode = await RunAsync([flag], NotExecuted);

        Assert.Equal(2, exitCode);
        Assert.Contains("Bullgate Access topology bootstrap.", error.ToString());
        Assert.Contains("Usage: Bullgate.Access.Cli bootstrap --manifest", error.ToString());
    }

    [Theory]
    [InlineData]
    [InlineData("bootstrap")]
    [InlineData("bootstrap", "--manifest")]
    [InlineData("apply", "--manifest", "manifest.json")]
    [InlineData("bootstrap", "--file", "manifest.json")]
    [InlineData("bootstrap", "--manifest", "manifest.json", "--extra")]
    public async Task RunAsync_WithUnexpectedGrammar_RejectsWithoutReadingAnything(
        params string[] args)
    {
        var exitCode = await RunAsync(args, NotExecuted);

        Assert.Equal(2, exitCode);
        Assert.Contains("Expected the bootstrap command and one manifest path.", error.ToString());
    }

    [Fact]
    public async Task RunAsync_WithMissingManifestFile_RejectsBeforeAnyChange()
    {
        var absent = Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}.json");

        var exitCode = await RunAsync(["bootstrap", "--manifest", absent], NotExecuted);

        Assert.Equal(2, exitCode);
        Assert.Contains("Manifest file does not exist:", error.ToString());
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("")]
    [InlineData("""{"manifestVersion":2,"workspace":{"key":"example","name":"E","apps":[],"extra":1}}""")]
    public async Task RunAsync_WithUnreadableManifest_ReportsInvalidManifest(string content)
    {
        var exitCode = await RunAsync(Arguments(content), NotExecuted);

        Assert.Equal(2, exitCode);
        Assert.Contains("Invalid bootstrap manifest:", error.ToString());
    }

    [Fact]
    public async Task RunAsync_WithUnsupportedManifestVersion_IsRejectedByConversion()
    {
        var manifest = """{"manifestVersion":1,"workspace":{"key":"e","name":"E","apps":[]}}""";

        var exitCode = await RunAsync(Arguments(manifest), NotExecuted);

        Assert.Equal(2, exitCode);
        Assert.Contains("Bootstrap rejected:", error.ToString());
        Assert.Contains("Unsupported manifestVersion '1'", error.ToString());
    }

    [Fact]
    public async Task RunAsync_WhenTopologyIsRejected_ReportsRejectionAndDoesNotFail()
    {
        var exitCode = await RunAsync(
            Arguments(MinimalManifest),
            (_, _) => throw new BootstrapTopologyException("realm key is duplicated"));

        Assert.Equal(2, exitCode);
        Assert.Contains("Bootstrap rejected: realm key is duplicated", error.ToString());
    }

    [Fact]
    public async Task RunAsync_WhenAnArgumentIsRejected_ReportsRejection()
    {
        var exitCode = await RunAsync(
            Arguments(MinimalManifest),
            (_, _) => throw new ArgumentException("workspace key is empty"));

        Assert.Equal(2, exitCode);
        Assert.Contains("Bootstrap rejected: workspace key is empty", error.ToString());
    }

    [Fact]
    public async Task RunAsync_WhenBootstrapFailsUnexpectedly_SeparatesFailureFromRejection()
    {
        var exitCode = await RunAsync(
            Arguments(MinimalManifest),
            (_, _) => throw new InvalidOperationException("the database is unreachable"));

        // Exit code one distinguishes an incomplete run from input that was rejected
        // before any change, so automation can retry the first and must not retry the
        // second.
        Assert.Equal(1, exitCode);
        Assert.Contains("Bootstrap failed: the database is unreachable", error.ToString());
    }

    [Fact]
    public async Task RunAsync_WhenBootstrapSucceeds_PassesTheCancellationTokenThrough()
    {
        using var cancellation = new CancellationTokenSource();
        CancellationToken observed = default;

        var exitCode = await RunAsync(
            Arguments(MinimalManifest),
            (_, token) =>
            {
                observed = token;
                return Task.FromResult(CreateResult());
            },
            cancellation.Token);

        Assert.Equal(0, exitCode);
        Assert.Equal(cancellation.Token, observed);
    }

    private static Task<BootstrapTopologyResult> NotExecuted(
        BootstrapTopologyCommand command,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "The bootstrap must not run when the input was already rejected.");

    private static BootstrapTopologyResult CreateResult(
        params IssuedIntegrationClientCredential[] credentials) =>
        new(Guid.NewGuid(), [], credentials);

    private Task<int> RunAsync(
        string[] args,
        Func<BootstrapTopologyCommand, CancellationToken, Task<BootstrapTopologyResult>> execute,
        CancellationToken cancellationToken = default) =>
        new BootstrapCli(output, error, execute).RunAsync(args, cancellationToken);

    private string[] Arguments(string manifestContent)
    {
        var path = Path.Combine(Path.GetTempPath(), $"manifest-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, manifestContent);
        temporaryFiles.Add(path);
        return ["bootstrap", "--manifest", path];
    }
}
