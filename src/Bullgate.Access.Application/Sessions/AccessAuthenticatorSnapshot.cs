namespace Bullgate.Access.Application.Sessions;

/// <summary>
/// Read-only projection of the authenticators currently capable of recovering or
/// authenticating an identity; provider emails are informational metadata.
/// </summary>
public sealed record AccessAuthenticatorSnapshot(
    bool HasPassword,
    bool HasGoogle,
    string? GoogleEmail,
    bool HasApple,
    string? AppleEmail)
{
    public static AccessAuthenticatorSnapshot PasswordOnly { get; } =
        new(true, false, null, false, null);
}
