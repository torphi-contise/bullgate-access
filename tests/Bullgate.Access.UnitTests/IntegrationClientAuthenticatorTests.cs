using System.Security.Cryptography;
using Bullgate.Access.Application.IntegrationClients;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.UnitTests;

public sealed class IntegrationClientAuthenticatorTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-08-31T20:00:00Z");

    private static readonly Guid CredentialId =
        Guid.Parse("0198f4e4-62d8-7f91-bd5d-37f3a7b51854");

    [Fact]
    public async Task ValidCredential_DerivesScopeAndPermissionsFromStoredClient()
    {
        var secret = CreateSecret(1);
        var candidate = CreateCandidate(secret);
        var authenticator = CreateAuthenticator(candidate);
        var token = IntegrationClientCredentialToken.Create(CredentialId, secret);

        var context = await authenticator.AuthenticateAsync(token);

        Assert.NotNull(context);
        Assert.Equal(candidate.IntegrationClientId, context.IntegrationClientId);
        Assert.Equal(candidate.AppEnvironmentId, context.AppEnvironmentId);
        Assert.Equal(candidate.AppId, context.AppId);
        Assert.Equal(candidate.RealmId, context.RealmId);
        Assert.Equal(candidate.WorkspaceId, context.WorkspaceId);
        Assert.Equal(
            candidate.Permissions.Order(StringComparer.Ordinal),
            context.Permissions.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("malformed")]
    [InlineData("unknown")]
    [InlineData("wrong-secret")]
    [InlineData("expired")]
    [InlineData("revoked")]
    [InlineData("future")]
    [InlineData("inactive")]
    [InlineData("unknown-permission")]
    [InlineData("unknown-algorithm")]
    [InlineData("invalid-hash-length")]
    public async Task InvalidCredentialVariants_ReturnTheSameUnauthenticatedResult(string variant)
    {
        var secret = CreateSecret(1);
        var token = IntegrationClientCredentialToken.Create(CredentialId, secret);
        IntegrationClientAuthenticationCandidate? candidate = CreateCandidate(secret);

        switch (variant)
        {
            case "malformed":
                token = "not-a-bullgate-credential";
                break;
            case "unknown":
                candidate = null;
                break;
            case "wrong-secret":
                token = IntegrationClientCredentialToken.Create(
                    CredentialId,
                    CreateSecret(101));
                break;
            case "expired":
                candidate = candidate with { ExpiresAt = Now };
                break;
            case "revoked":
                candidate = candidate with { RevokedAt = Now.AddMinutes(-1) };
                break;
            case "future":
                candidate = candidate with { CreatedAt = Now.AddMinutes(1) };
                break;
            case "inactive":
                candidate = candidate with { IsScopeActive = false };
                break;
            case "unknown-permission":
                candidate = candidate with { Permissions = ["access:unknown"] };
                break;
            case "unknown-algorithm":
                candidate = candidate with { HashAlgorithm = "sha512-v1" };
                break;
            case "invalid-hash-length":
                candidate = candidate with { SecretHash = new byte[31] };
                break;
            default:
                throw new InvalidOperationException($"Unknown test variant '{variant}'.");
        }

        var authenticator = CreateAuthenticator(candidate);

        var context = await authenticator.AuthenticateAsync(token);

        Assert.Null(context);
    }

    [Fact]
    public async Task NonCanonicalCredentialId_IsRejectedBeforeDatabaseLookup()
    {
        var store = new StubAuthenticationStore(CreateCandidate(CreateSecret(1)));
        var authenticator = new IntegrationClientAuthenticator(
            store,
            new FixedTimeProvider());
        var canonical = IntegrationClientCredentialToken.Create(CredentialId, CreateSecret(1));
        var upperCaseCredentialId = string.Concat(
            IntegrationClientCredentialToken.Prefix,
            CredentialId.ToString("D").ToUpperInvariant(),
            canonical.AsSpan(IntegrationClientCredentialToken.Prefix.Length + 36));

        var context = await authenticator.AuthenticateAsync(upperCaseCredentialId);

        Assert.Null(context);
        Assert.Equal(0, store.LookupCount);
    }

    [Fact]
    public async Task NonCanonicalBase64UrlSecret_IsRejectedBeforeDatabaseLookup()
    {
        const string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var store = new StubAuthenticationStore(CreateCandidate(CreateSecret(1)));
        var authenticator = new IntegrationClientAuthenticator(
            store,
            new FixedTimeProvider());
        var canonical = IntegrationClientCredentialToken.Create(CredentialId, CreateSecret(1));
        var finalCharacterIndex = alphabet.IndexOf(canonical[^1], StringComparison.Ordinal);
        Assert.Equal(0, finalCharacterIndex & 0b11);
        var nonCanonical = canonical[..^1] + alphabet[finalCharacterIndex + 1];

        var context = await authenticator.AuthenticateAsync(nonCanonical);

        Assert.Null(context);
        Assert.Equal(0, store.LookupCount);
    }

    private static IntegrationClientAuthenticator CreateAuthenticator(
        IntegrationClientAuthenticationCandidate? candidate) =>
        new(new StubAuthenticationStore(candidate), new FixedTimeProvider());

    private static IntegrationClientAuthenticationCandidate CreateCandidate(byte[] secret) =>
        new(
            CredentialId,
            Guid.Parse("0198f4e8-f048-723a-adf8-2c562434b9d2"),
            Guid.Parse("0198f4e9-2c13-72f1-a665-936d6e06cf48"),
            Guid.Parse("0198f4e9-634b-7bee-b4ce-05e0cae9aeb0"),
            Guid.Parse("0198f4e9-9598-781a-8c76-23d488c5fb8a"),
            Guid.Parse("0198f4e9-c3c2-764c-9469-6156800c8c7d"),
            SHA256.HashData(secret),
            IntegrationClientSecret.Sha256V1,
            Now.AddMinutes(-1),
            Now.AddHours(1),
            null,
            true,
            [AccessPermission.ExecuteFlows, AccessPermission.IntrospectSessions]);

    private static byte[] CreateSecret(int start) =>
        Enumerable.Range(start, IntegrationClientCredentialToken.SecretByteCount)
            .Select(value => checked((byte)value))
            .ToArray();

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class StubAuthenticationStore(
        IntegrationClientAuthenticationCandidate? candidate)
        : IIntegrationClientAuthenticationStore
    {
        public int LookupCount { get; private set; }

        public Task<IntegrationClientAuthenticationCandidate?> FindByCredentialIdAsync(
            Guid credentialId,
            CancellationToken cancellationToken)
        {
            LookupCount++;
            return Task.FromResult(
                candidate?.CredentialId == credentialId ? candidate : null);
        }
    }
}
