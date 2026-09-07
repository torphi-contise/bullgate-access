using Bullgate.Access.Application.Identities;

namespace Bullgate.Access.UnitTests;

public sealed class IdentityEmailReaderTests
{
    [Fact]
    public async Task GetAsync_UsesTheAuthenticatedRealmAndIdentity()
    {
        var realmId = Guid.NewGuid();
        var identityId = Guid.NewGuid();
        var store = new RecordingStore("person@example.com");
        var reader = new IdentityEmailReader(store);

        var email = await reader.GetAsync(realmId, identityId);

        Assert.Equal("person@example.com", email);
        Assert.Equal(realmId, store.RealmId);
        Assert.Equal(identityId, store.IdentityId);
    }

    [Fact]
    public async Task GetAsync_RejectsEmptyScopeIdentifiers()
    {
        var reader = new IdentityEmailReader(new RecordingStore(null));

        await Assert.ThrowsAsync<ArgumentException>(
            () => reader.GetAsync(Guid.Empty, Guid.NewGuid()));
        await Assert.ThrowsAsync<ArgumentException>(
            () => reader.GetAsync(Guid.NewGuid(), Guid.Empty));
    }

    private sealed class RecordingStore(string? email) : IIdentityEmailStore
    {
        public Guid? RealmId { get; private set; }

        public Guid? IdentityId { get; private set; }

        public Task<string?> FindAsync(
            Guid realmId,
            Guid identityId,
            CancellationToken cancellationToken)
        {
            RealmId = realmId;
            IdentityId = identityId;
            return Task.FromResult(email);
        }
    }
}
