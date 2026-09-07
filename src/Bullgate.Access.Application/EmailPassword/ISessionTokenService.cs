namespace Bullgate.Access.Application.EmailPassword;

/// <summary>Generates opaque session bearer material and its persistence hash.</summary>
public interface ISessionTokenService
{
    /// <summary>Creates fresh clear session bearer material and its persistence hash.</summary>
    /// <returns>A one-time delivery value paired with its non-reversible storage form.</returns>
    IssuedSessionToken Issue();

    /// <summary>Validates the fixed public token shape and derives its lookup hash.</summary>
    /// <param name="token">Untrusted clear bearer supplied by a BFF.</param>
    /// <param name="tokenHash">Derived fixed-size hash, or an empty array on failure.</param>
    /// <returns><see langword="false"/> without hashing when the token shape is malformed.</returns>
    bool TryHash(string? token, out byte[] tokenHash);
}

/// <summary>One-time clear session token and the only representation safe to persist.</summary>
/// <remarks>The clear <see cref="Token"/> is bearer authority and must not be logged.</remarks>
/// <param name="Token">Clear bearer returned exactly once to trusted orchestration.</param>
/// <param name="TokenHash">Non-reversible value persisted with the session.</param>
public sealed record IssuedSessionToken(string Token, byte[] TokenHash);
