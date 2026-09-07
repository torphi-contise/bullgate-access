using System.Security.Cryptography;
using System.Text;
using Bullgate.Access.Application.Cryptography;
using Bullgate.Access.Application.Flows;

namespace Bullgate.Access.Infrastructure.Flows;

/// <summary>
/// Derives flow capabilities and terminal session tokens deterministically from fixed
/// server-owned scope using a purpose-specific HMAC-SHA-256 key.
/// </summary>
/// <remarks>
/// Deterministic issuance lets exact request replay reproduce the original clear token
/// while PostgreSQL retains only its hash. Capability and session domains are separated
/// so authority from one purpose cannot be substituted for the other.
/// </remarks>
internal sealed class HmacAccessFlowTokenService : IAccessFlowTokenService, IDisposable
{
    private const string CapabilityPrefix = "bgf_";
    private const string SessionPrefix = "bgs_";
    private const int EncodedDigestLength = 43;
    internal const string KeyPurpose = "access-flow-token-v1";
    private readonly byte[] key;

    public HmacAccessFlowTokenService(IInstallationKeyDeriver keyDeriver)
    {
        ArgumentNullException.ThrowIfNull(keyDeriver);
        key = keyDeriver.DeriveKey(KeyPurpose);
    }

    public string IssueCapability(
        Guid flowId,
        Guid integrationClientId,
        Guid appEnvironmentId) =>
        IssueToken(
            CapabilityPrefix,
            "capability",
            flowId,
            integrationClientId,
            appEnvironmentId);

    public bool IsValidCapability(
        string? capability,
        Guid flowId,
        Guid integrationClientId,
        Guid appEnvironmentId)
    {
        if (!HasTokenShape(capability, CapabilityPrefix))
        {
            return false;
        }

        var expected = IssueCapability(flowId, integrationClientId, appEnvironmentId);
        var presentedBytes = Encoding.ASCII.GetBytes(capability!);
        var expectedBytes = Encoding.ASCII.GetBytes(expected);
        try
        {
            // Compare complete canonical token bytes in constant time. A matching prefix
            // or digest fragment must not disclose incremental validation information.
            return CryptographicOperations.FixedTimeEquals(
                presentedBytes,
                expectedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(presentedBytes);
            CryptographicOperations.ZeroMemory(expectedBytes);
        }
    }

    public IssuedAccessFlowSessionToken IssueSession(
        Guid flowId,
        Guid requestId,
        Guid identityId,
        Guid appEnvironmentId)
    {
        var token = IssueToken(
            SessionPrefix,
            "session",
            flowId,
            requestId,
            identityId,
            appEnvironmentId);
        // Request id participates in derivation so a replay of the same committed
        // request reproduces its session, while another terminal request cannot.
        var tokenBytes = Encoding.ASCII.GetBytes(token);
        try
        {
            return new IssuedAccessFlowSessionToken(
                token,
                SHA256.HashData(tokenBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenBytes);
        }
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(key);

    private string IssueToken(string prefix, string domain, params Guid[] values)
    {
        // Newline-delimited fixed-format UUIDs make the signed material unambiguous;
        // the explicit domain provides cryptographic separation beyond token prefixes.
        var material = Encoding.ASCII.GetBytes(
            string.Join('\n', new[] { domain }.Concat(values.Select(value => value.ToString("D")))));
        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];

        try
        {
            HMACSHA256.HashData(key, material, digest);
            return prefix + Convert.ToBase64String(digest)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static bool HasTokenShape(string? token, string prefix)
    {
        // Shape validation is deliberately separate from authority validation. A token
        // becomes authoritative only after the expected scoped HMAC matches.
        if (token is null || token.Length != prefix.Length + EncodedDigestLength)
        {
            return false;
        }

        if (!token.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        for (var index = prefix.Length; index < token.Length; index++)
        {
            var value = token[index];
            if (value is not (>= 'A' and <= 'Z')
                and not (>= 'a' and <= 'z')
                and not (>= '0' and <= '9')
                and not '-'
                and not '_')
            {
                return false;
            }
        }

        return true;
    }
}
