using Bullgate.Access.Application;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Cli;
using Bullgate.Access.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// Composition root only. The command behaviour lives in BootstrapCli, which receives
// its streams and its execution so it can be tested without a host or a database.
return await new BootstrapCli(Console.Out, Console.Error, ExecuteAsync).RunAsync(args);

static async Task<BootstrapTopologyResult> ExecuteAsync(
    BootstrapTopologyCommand command,
    CancellationToken cancellationToken)
{
    var builder = Host.CreateApplicationBuilder([]);
    // Keep stdout reserved for the single machine-readable result document. Default
    // host log providers could interleave text with JSON or expose bootstrap data.
    builder.Logging.ClearProviders();
    builder.Services.AddAccessApplication();
    builder.Services.AddAccessInfrastructure(builder.Configuration);

    using var host = builder.Build();
    await using var scope = host.Services.CreateAsyncScope();
    var handler = scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>();
    return await handler.HandleAsync(command, cancellationToken);
}
