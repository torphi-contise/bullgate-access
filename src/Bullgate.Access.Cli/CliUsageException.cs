namespace Bullgate.Access.Cli;

/// <summary>Represents command-line input that is invalid before bootstrap begins.</summary>
internal sealed class CliUsageException(string message) : Exception(message);
