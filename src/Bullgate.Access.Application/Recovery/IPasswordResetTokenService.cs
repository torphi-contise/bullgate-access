namespace Bullgate.Access.Application.Recovery;

/// <summary>Generates opaque password-reset bearer material and its storage hash.</summary>
public interface IPasswordResetTokenService
{
    /// <summary>Creates fresh clear bearer material and the only representation safe to persist.</summary>
    /// <returns>A one-time delivery value paired with its non-reversible storage form.</returns>
    IssuedPasswordResetToken Issue();

    /// <summary>Validates the fixed public token shape and derives its lookup hash.</summary>
    /// <param name="token">Untrusted clear bearer submitted through a recovery channel.</param>
    /// <param name="tokenHash">Derived fixed-size hash, or an empty array on failure.</param>
    /// <returns><see langword="false"/> without hashing when the token shape is malformed.</returns>
    bool TryHash(string? token, out byte[] tokenHash);
}

/// <summary>One-time clear reset token and the only representation safe to persist.</summary>
/// <remarks>The clear <see cref="Token"/> is bearer authority and must not be logged.</remarks>
/// <param name="Token">Clear single-use bearer returned only to its intended delivery path.</param>
/// <param name="TokenHash">Non-reversible value persisted with lifecycle state.</param>
public sealed record IssuedPasswordResetToken(string Token, byte[] TokenHash);
