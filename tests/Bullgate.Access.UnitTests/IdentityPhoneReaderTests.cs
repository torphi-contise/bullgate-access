using Bullgate.Access.Application.Identities;

namespace Bullgate.Access.UnitTests;

public sealed class IdentityPhoneReaderTests
{
    [Fact]
    public async Task GetAsync_UsesTheAuthenticatedRealmAndIdentity()
    {
        var realmId = Guid.NewGuid();
        var identityId = Guid.NewGuid();
        var expected = new IdentityPhone(
            "+5511987654321",
            new DateTimeOffset(2026, 9, 2, 20, 0, 0, TimeSpan.Zero));
        var store = new RecordingStore(expected);
        var reader = new IdentityPhoneReader(store);

        var phone = await reader.GetAsync(realmId, identityId);

        Assert.Equal(expected, phone);
        Assert.Equal(realmId, store.RealmId);
        Assert.Equal(identityId, store.IdentityId);
    }

    [Fact]
    public async Task GetAsync_RejectsEmptyScopeIdentifiers()
    {
        var reader = new IdentityPhoneReader(new RecordingStore(null));

        await Assert.ThrowsAsync<ArgumentException>(
            () => reader.GetAsync(Guid.Empty, Guid.NewGuid()));
        await Assert.ThrowsAsync<ArgumentException>(
            () => reader.GetAsync(Guid.NewGuid(), Guid.Empty));
    }

    private sealed class RecordingStore(IdentityPhone? phone) : IIdentityPhoneStore
    {
        public Guid? RealmId { get; private set; }

        public Guid? IdentityId { get; private set; }

        public Task<IdentityPhone?> FindAsync(
            Guid realmId,
            Guid identityId,
            CancellationToken cancellationToken)
        {
            RealmId = realmId;
            IdentityId = identityId;
            return Task.FromResult(phone);
        }
    }
}
