namespace Bullgate.Access.Application.EmailPassword;

/// <summary>
/// Hashes and verifies identity passwords without exposing a provider-specific format
/// to the application layer.
/// </summary>
public interface IPasswordHashService
{
    /// <summary>Creates a provider-encoded, salted password hash for persistence.</summary>
    /// <remarks>The clear password must not be retained or logged by the implementation.</remarks>
    string Hash(string password);

    /// <summary>Verifies a clear candidate without exposing provider-specific result codes.</summary>
    bool Verify(string passwordHash, string password);
}
