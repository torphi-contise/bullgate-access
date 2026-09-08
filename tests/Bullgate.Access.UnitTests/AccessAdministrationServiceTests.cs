using System.Text.Json;
using Bullgate.Access.Application.Administration;
using Bullgate.Access.Domain.Topology;

namespace Bullgate.Access.UnitTests;

public sealed class AccessAdministrationServiceTests
{
    private static readonly Guid Realm = Guid.NewGuid();
    private static readonly Guid Target = Guid.NewGuid();
    private static readonly Guid Operation = Guid.NewGuid();
    private static AdminCallContext Context(string permission) => new("operator", "session", "scope", permission);

    [Fact]
    public void AdministrativeCatalog_DoesNotWidenConsumerCredentialVocabulary()
    {
        Assert.Equal(5, AccessPermission.Administrative.Count);
        Assert.Equal(8, AccessPermission.All.Count);
        foreach (var key in new[] { AccessPermission.ListIdentities, AccessPermission.DeleteIdentities, AccessPermission.ManageConfiguration })
        {
            Assert.Contains(key, AccessPermission.Administrative);
            Assert.False(AccessPermission.IsDefined(key));
            Assert.Throws<ArgumentException>(() => AccessPermission.RequireDefined(key, "permission"));
        }
        Assert.True(AccessPermission.IsDefined(AccessPermission.ReadIdentities));
        Assert.True(AccessPermission.IsDefined(AccessPermission.RevokeAllSessions));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public async Task EachOperation_RequiresItsOwnExactPermissionBeforeStorage(int operation)
    {
        var store = new Store();
        var service = new AccessAdministrationService(store);
        var context = Context("access:identities:*");
        var failure = await Assert.ThrowsAsync<AccessAdministrationException>(async () =>
        {
            switch (operation)
            {
                case 0: await service.ListIdentitiesAsync(context, new(Realm)); break;
                case 1: await service.ReadIdentityAsync(context, Realm, Target); break;
                case 2: await service.RevokeSessionsAsync(context, Realm, Target, Operation); break;
                case 3: await service.DeleteIdentityAsync(context, Realm, Target, Operation); break;
                case 4: await service.ListEnvironmentsAsync(context); break;
                default: await service.ReplaceConfigurationAsync(context, Target, Operation, Revision, Configuration()); break;
            }
        });
        Assert.Equal(403, failure.StatusCode);
        Assert.Equal(0, store.Calls);
    }

    [Theory]
    [InlineData(-1)] [InlineData(0)] [InlineData(51)]
    public async Task List_RejectsUnboundedInputBeforeStorage(int size)
    {
        var store = new Store();
        var failure = await Assert.ThrowsAsync<AccessAdministrationException>(() =>
            new AccessAdministrationService(store).ListIdentitiesAsync(Context(AccessPermission.ListIdentities), new(Realm, PageSize: size)));
        Assert.Equal(400, failure.StatusCode);
        Assert.Equal(0, store.Calls);
    }

    [Fact]
    public async Task InvalidContextAndEmptyTargets_DoNotReachStorage()
    {
        var store = new Store();
        var service = new AccessAdministrationService(store);
        var invalid = await Assert.ThrowsAsync<AccessAdministrationException>(() =>
            service.DeleteIdentityAsync(Context(AccessPermission.DeleteIdentities) with { OperatorId = " " }, Realm, Target, Operation));
        Assert.Equal(401, invalid.StatusCode);
        var empty = await Assert.ThrowsAsync<AccessAdministrationException>(() =>
            service.RevokeSessionsAsync(Context(AccessPermission.RevokeAllSessions), Guid.Empty, Target, Operation));
        Assert.Equal(400, empty.StatusCode);
        Assert.Equal(0, store.Calls);
    }

    [Fact]
    public async Task Page_CursorRemainsBoundToExactQuery()
    {
        var store = new Store();
        var service = new AccessAdministrationService(store);
        var query = new AdminIdentityQuery(Realm, Email: "exact@example.test", PageSize: 1);
        var first = await service.ListIdentitiesAsync(Context(AccessPermission.ListIdentities), query);
        Assert.Single(first.Items);
        Assert.NotNull(first.NextCursor);
        await service.ListIdentitiesAsync(Context(AccessPermission.ListIdentities), query with { Cursor = first.NextCursor });
        Assert.Equal(first.Items[0].Id, store.AfterId);
        var failure = await Assert.ThrowsAsync<AccessAdministrationException>(() => service.ListIdentitiesAsync(
            Context(AccessPermission.ListIdentities), query with { Cursor = first.NextCursor, Email = "different@example.test" }));
        Assert.Equal(400, failure.StatusCode);
        Assert.Equal(2, store.Calls);
    }

    [Theory]
    [InlineData(null)] [InlineData("*")] [InlineData("W/\"invalid\"")] [InlineData("invalid")]
    public async Task Configuration_RequiresOneStrongEnvelopeRevision(string? revision)
    {
        var store = new Store();
        var failure = await Assert.ThrowsAsync<AccessAdministrationException>(() =>
            new AccessAdministrationService(store).ReplaceConfigurationAsync(Context(AccessPermission.ManageConfiguration),
                Target, Operation, revision, Configuration()));
        Assert.Equal(400, failure.StatusCode);
        Assert.Equal(0, store.Calls);
    }

    [Fact]
    public async Task Configuration_InvalidProviderCombinationAndNullClients_AreSecretFreeFailures()
    {
        var store = new Store();
        var service = new AccessAdministrationService(store);
        var configuration = Configuration();
        foreach (var invalid in new[]
        {
            configuration with { IntegrationClients = null! },
            configuration with { ApplicationClients = [null!] },
            configuration with { Providers = new(new("secret-host", 0, "user", "secret-password", "x", "x", true, true), null, null, null) },
        })
        {
            var failure = await Assert.ThrowsAsync<AccessAdministrationException>(() => service.ReplaceConfigurationAsync(
                Context(AccessPermission.ManageConfiguration), Target, Operation, Revision, invalid));
            Assert.Equal("admin-input-invalid", failure.Message);
        }
        Assert.Equal(0, store.Calls);
    }

    [Fact]
    public async Task ValidConfiguration_PassesCompleteReplacementAndAuthorityToStore()
    {
        var store = new Store();
        var configuration = Configuration();
        await new AccessAdministrationService(store).ReplaceConfigurationAsync(Context(AccessPermission.ManageConfiguration),
            Target, Operation, Revision, configuration);
        Assert.Same(configuration, store.Mutation!.Configuration);
        Assert.Equal(Revision, store.Mutation.ExpectedRevision);
        Assert.Equal(Target, store.Mutation.TargetId);
    }

    private static string Revision => $"\"{new string('A', 64)}\"";
    private static AppEnvironmentConfiguration Configuration() => new(
        new(new(true, true, IdentifierVerificationPolicy.Disabled), new(false, false, IdentifierVerificationPolicy.Disabled), new(true, false, false)),
        new(10, 5, 5, 120, 15, 5), new(null, 60, 5, 10, 5, 5, 120), new(null, null, null, null),
        new(false, null, null), new(1, JsonSerializer.SerializeToElement(new { })), [], []);

    private sealed class Store : IAccessAdministrationStore
    {
        public int Calls { get; private set; }
        public Guid? AfterId { get; private set; }
        public AdminMutation? Mutation { get; private set; }
        public Task<IReadOnlyList<AdminIdentity>> ListIdentitiesAsync(AdminIdentityQuery query, Guid? afterId, CancellationToken cancellationToken)
        {
            Calls++; AfterId = afterId;
            IReadOnlyList<AdminIdentity> rows = [new(Target, Realm, "Active", DateTimeOffset.UtcNow, null, null), new(Guid.NewGuid(), Realm, "Active", DateTimeOffset.UtcNow, null, null)];
            return Task.FromResult(rows);
        }
        public Task<AdminIdentity?> ReadIdentityAsync(Guid realmId, Guid identityId, CancellationToken cancellationToken)
        { Calls++; return Task.FromResult<AdminIdentity?>(null); }
        public Task<IReadOnlyList<AdminEnvironment>> ListEnvironmentsAsync(int pageSize, Guid? afterId, CancellationToken cancellationToken)
        { Calls++; return Task.FromResult<IReadOnlyList<AdminEnvironment>>([]); }
        public Task<AdminOperationResult> MutateAsync(AdminCallContext context, AdminMutation mutation, CancellationToken cancellationToken)
        {
            Calls++; Mutation = mutation;
            return Task.FromResult(new AdminOperationResult(mutation.OperationId, context.Permission, mutation.TargetId, DateTimeOffset.UtcNow));
        }
    }
}
