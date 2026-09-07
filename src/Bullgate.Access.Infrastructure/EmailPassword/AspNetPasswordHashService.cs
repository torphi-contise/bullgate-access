using Bullgate.Access.Application.EmailPassword;
using Microsoft.AspNetCore.Identity;

namespace Bullgate.Access.Infrastructure.EmailPassword;

/// <summary>
/// Adapts the ASP.NET Core Identity password hasher without exposing its encoded hash
/// format or version markers to the application layer.
/// </summary>
/// <remarks>
/// `SuccessRehashNeeded` is accepted as a valid password. Automatic rehash-on-login is
/// not part of this adapter's current contract and must be added as an explicit
/// credential-update operation if required.
/// </remarks>
internal sealed class AspNetPasswordHashService : IPasswordHashService
{
    private static readonly object Marker = new();
    private readonly PasswordHasher<object> passwordHasher = new();

    public string Hash(string password) => passwordHasher.HashPassword(Marker, password);

    public bool Verify(string passwordHash, string password) =>
        // Both Success and SuccessRehashNeeded prove the presented password. Only
        // Failed is an authentication failure.
        passwordHasher.VerifyHashedPassword(Marker, passwordHash, password)
        != PasswordVerificationResult.Failed;
}
