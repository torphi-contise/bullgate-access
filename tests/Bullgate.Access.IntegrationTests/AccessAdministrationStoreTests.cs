using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Bullgate.Access.Application.Administration;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.EmailPassword;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Bullgate.Access.IntegrationTests;

public sealed class AccessAdministrationStoreTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private AccessAdministrationTestHost host = null!;
    public async Task InitializeAsync() { host = new(database.ConnectionString); await host.InitializeAsync(migrate: true); }
    public Task DisposeAsync() => host.DisposeAsync().AsTask();

    [Fact]
    public async Task Migration_AppliesToDisposablePostgresAndMatchesCurrentModel()
    {
        await using var db = host.MigrationContext();
        Assert.Contains(await db.Database.GetAppliedMigrationsAsync(), name => name.EndsWith("_AddAccessAdminOperations", StringComparison.Ordinal));
        Assert.False(db.Database.HasPendingModelChanges());
        Assert.Empty(db.Model.FindEntityType("Bullgate.Access.Domain.Administration.AdminOperation")!.GetForeignKeys());
        await db.AdminOperations.CountAsync();
    }

    [Fact]
    public async Task ConcurrentSameOperation_CommitsOnceAndConflictingReuseFails()
    {
        var user = await host.RegisterAsync();
        var id = Guid.NewGuid();
        var path = host.IdentityPath(user.Id) + "/sessions/revoke";
        var replies = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => host.SendAsync(HttpMethod.Post, path, AccessPermission.RevokeAllSessions, id)));
        var results = new List<AdminOperationResult>();
        foreach (var reply in replies)
        {
            using (reply) { reply.EnsureSuccessStatusCode(); results.Add((await reply.Content.ReadFromJsonAsync<AdminOperationResult>())!); }
        }
        Assert.All(results, item => Assert.Equal(results[0], item));
        Assert.Equal(1, results[0].RevokedSessions);
        using var conflict = await host.SendAsync(HttpMethod.Delete, host.IdentityPath(user.Id), AccessPermission.DeleteIdentities, id);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        using var otherOperator = await host.SendAsync(HttpMethod.Post, path, AccessPermission.RevokeAllSessions, id,
            context: AccessAdministrationTestHost.Context(AccessPermission.RevokeAllSessions) with { OperatorId = "different-operator" });
        Assert.Equal(HttpStatusCode.Conflict, otherOperator.StatusCode);
        await using var scope = host.Api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(1, await db.AdminOperations.CountAsync(item => item.OperationId == id));
        Assert.True(await db.Identities.AnyAsync(item => item.Id == user.Id));
    }

    [Fact]
    public async Task ConcurrentConfigurationEditors_HaveOneCommitAndOneStaleRevision()
    {
        var revision = await host.RevisionAsync();
        var first = host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration, Guid.NewGuid(), host.Configuration, revision);
        var second = host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration, Guid.NewGuid(), host.Configuration, revision);
        var replies = await Task.WhenAll(first, second);
        Assert.Single(replies, item => item.StatusCode == HttpStatusCode.OK);
        Assert.Single(replies, item => item.StatusCode == HttpStatusCode.PreconditionFailed);
        foreach (var reply in replies) reply.Dispose();
    }

    [Fact]
    public async Task CliReapply_StillOwnsItsExplicitWriteAndInvalidatesOldEditorRevision()
    {
        var revision = await host.RevisionAsync();
        await using var scope = host.Api.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>().HandleAsync(host.Command);
        Assert.NotEqual(revision, await host.RevisionAsync());
        using var stale = await host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration,
            Guid.NewGuid(), host.Configuration, revision);
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
    }

    [Fact]
    public async Task OmittedClientDeclarations_DoNotEraseTopologyOrCredentials()
    {
        var revision = await host.RevisionAsync();
        using var response = await host.SendAsync(HttpMethod.Put, host.ConfigurationPath, AccessPermission.ManageConfiguration,
            Guid.NewGuid(), host.Configuration with { IntegrationClients = [], ApplicationClients = [] }, revision);
        response.EnsureSuccessStatusCode();
        await using var scope = host.Api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var integration = await db.IntegrationClients.SingleAsync(item => item.AppEnvironmentId == host.EnvironmentId);
        Assert.True(await db.IntegrationClientSecrets.AnyAsync(item => item.IntegrationClientId == integration.Id));
        Assert.True(await db.ApplicationClients.AnyAsync(item => item.AppEnvironmentId == host.EnvironmentId));
        using var publicResponse = await host.Consumer.GetAsync("/v1/config/application-clients/web");
        Assert.Equal(HttpStatusCode.NotFound, publicResponse.StatusCode);
    }

    [Fact]
    public async Task Erasure_DeletesAttributableGraphPreservesOtherIdentityAndReplaysAfterTargetIsGone()
    {
        var user = await host.RegisterAsync();
        var other = await host.RegisterAsync();
        Guid flowId;
        Guid challengeId;
        await using (var scope = host.Api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var now = DateTimeOffset.UtcNow;
            var otherSession = await db.IdentitySessions.SingleAsync(item => item.IdentityId == other.Id);
            var integration = await db.IntegrationClients.SingleAsync(item => item.AppEnvironmentId == host.EnvironmentId);
            var app = await db.ApplicationClients.SingleAsync(item => item.AppEnvironmentId == host.EnvironmentId);
            var phoneId = Guid.CreateVersion7();
            db.IdentityIdentifiers.Add(new(phoneId, user.Id, host.RealmId, IdentifierScheme.Phone, "+5511999990002", now, now, "test"));
            db.PasswordResetTokens.Add(new(Guid.CreateVersion7(), user.Id, host.EnvironmentId, RandomNumberGenerator.GetBytes(32), now, now.AddMinutes(30)));
            db.PhonePasswordResetChallenges.Add(new(Guid.CreateVersion7(), user.Id, host.EnvironmentId, "+5511999990002",
                RandomNumberGenerator.GetBytes(32), 5, now, now.AddMinutes(10), now.AddMinutes(1)));
            db.SocialCredentials.Add(new(Guid.CreateVersion7(), user.Id, host.RealmId, SocialProvider.Google, "unique-subject-" + user.Id, user.Email, now));
            flowId = Guid.CreateVersion7();
            db.AccessFlows.Add(new(flowId, host.RealmId, host.EnvironmentId, integration.Id, app.Id, other.Id, null, otherSession.Id, 1,
                AccessFlowIntent.ManagePhone, now, now.AddMinutes(30)));
            db.AccessFlowDataSubjects.AddRange(new AccessFlowDataSubject(host.RealmId, flowId, user.Id, now), new(host.RealmId, flowId, other.Id, now));
            db.AccessFlowRevisions.Add(new(flowId, 1, "{}", now));
            db.AccessFlowRequests.Add(new(integration.Id, Guid.NewGuid(), flowId, AccessFlowRequestKind.Start, RandomNumberGenerator.GetBytes(32), 1, now));
            challengeId = Guid.CreateVersion7();
            var challenge = new ProofChallenge(challengeId, flowId, other.Id, ProofChallengeType.PhonePossession, ProofChallengeChannel.Sms,
                IdentifierScheme.Phone, "+5511999990002", RandomNumberGenerator.GetBytes(32), "fake-provider-reference", 5, now, now.AddMinutes(10), now.AddMinutes(1));
            challenge.Verify(now);
            db.ProofChallenges.Add(challenge);
            db.ProofAttempts.Add(new(Guid.CreateVersion7(), challengeId, ProofAttemptOutcome.Succeeded, now));
            db.IdentityProofs.Add(new(Guid.CreateVersion7(), flowId, other.Id, challengeId, ProofChallengeType.PhonePossession, phoneId, now));
            db.PhoneRegistrationConflicts.Add(new(flowId, user.Id, phoneId, now, now.AddMinutes(20)));
            await db.SaveChangesAsync();
        }
        var id = Guid.NewGuid();
        var replies = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => host.SendAsync(HttpMethod.Delete, host.IdentityPath(user.Id), AccessPermission.DeleteIdentities, id)));
        AdminOperationResult? result = null;
        foreach (var reply in replies)
        {
            using (reply)
            {
                reply.EnsureSuccessStatusCode();
                var current = await reply.Content.ReadFromJsonAsync<AdminOperationResult>();
                if (result is null) result = current; else Assert.Equal(result, current);
            }
        }
        await using var verification = host.Api.Services.CreateAsyncScope();
        var stored = verification.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await stored.Identities.AnyAsync(item => item.Id == user.Id));
        Assert.True(await stored.Identities.AnyAsync(item => item.Id == other.Id));
        Assert.False(await stored.IdentityIdentifiers.AnyAsync(item => item.IdentityId == user.Id));
        Assert.False(await stored.PasswordCredentials.AnyAsync(item => item.IdentityId == user.Id));
        Assert.False(await stored.SocialCredentials.AnyAsync(item => item.IdentityId == user.Id));
        Assert.False(await stored.IdentitySessions.AnyAsync(item => item.IdentityId == user.Id));
        Assert.False(await stored.RegistrationContexts.AnyAsync(item => item.IdentityId == user.Id));
        Assert.False(await stored.PasswordResetTokens.AnyAsync(item => item.IdentityId == user.Id));
        Assert.False(await stored.PhonePasswordResetChallenges.AnyAsync(item => item.IdentityId == user.Id));
        Assert.False(await stored.AccessFlows.AnyAsync(item => item.Id == flowId));
        Assert.False(await stored.AccessFlowDataSubjects.AnyAsync(item => item.FlowId == flowId));
        Assert.False(await stored.AccessFlowRevisions.AnyAsync(item => item.FlowId == flowId));
        Assert.False(await stored.AccessFlowRequests.AnyAsync(item => item.FlowId == flowId));
        Assert.False(await stored.ProofChallenges.AnyAsync(item => item.Id == challengeId));
        Assert.False(await stored.ProofAttempts.AnyAsync(item => item.ChallengeId == challengeId));
        Assert.False(await stored.IdentityProofs.AnyAsync(item => item.AccessFlowId == flowId));
        Assert.False(await stored.PhoneRegistrationConflicts.AnyAsync(item => item.AccessFlowId == flowId));
        var receipt = await stored.AdminOperations.SingleAsync(item => item.OperationId == id);
        Assert.DoesNotContain(user.Email, receipt.ResultJson);
        Assert.Equal("session-1", receipt.SessionId);
        using var fresh = await host.SendAsync(HttpMethod.Delete, host.IdentityPath(user.Id), AccessPermission.DeleteIdentities, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.NotFound, fresh.StatusCode);
    }

    [Fact]
    public async Task Revocation_WaitsForAlreadyInsertedSessionThenIncludesItInTheCut()
    {
        var user = await host.RegisterAsync();
        await using var writer = host.Api.Services.CreateAsyncScope();
        var db = writer.ServiceProvider.GetRequiredService<AccessDbContext>();
        await using var transaction = await db.Database.BeginTransactionAsync();
        var session = Session(user.Id);
        await writer.ServiceProvider.GetRequiredService<IEmailPasswordAccessStore>().AddSessionAsync(session, default);
        var revoke = host.SendAsync(HttpMethod.Post, host.IdentityPath(user.Id) + "/sessions/revoke", AccessPermission.RevokeAllSessions, Guid.NewGuid());
        await WaitForBlockedQueryAsync("%SELECT * FROM identities%FOR UPDATE%");
        await transaction.CommitAsync();
        using var response = await revoke.WaitAsync(TimeSpan.FromSeconds(10));
        response.EnsureSuccessStatusCode();
        Assert.Equal(2, (await response.Content.ReadFromJsonAsync<AdminOperationResult>())!.RevokedSessions);
        db.ChangeTracker.Clear();
        Assert.NotNull((await db.IdentitySessions.SingleAsync(item => item.Id == session.Id)).RevokedAt);
    }

    [Fact]
    public async Task NewIssuanceBlockedBehindRevocation_RemainsAllowedAfterTheCut()
    {
        var user = await host.RegisterAsync();
        await using var blocker = host.Api.Services.CreateAsyncScope();
        var blockerDb = blocker.ServiceProvider.GetRequiredService<AccessDbContext>();
        await using var transaction = await blockerDb.Database.BeginTransactionAsync();
        await blockerDb.IdentitySessions.FromSqlInterpolated($"SELECT * FROM identity_sessions WHERE identity_id = {user.Id} FOR UPDATE").ToArrayAsync();
        var revoke = host.SendAsync(HttpMethod.Post, host.IdentityPath(user.Id) + "/sessions/revoke", AccessPermission.RevokeAllSessions, Guid.NewGuid());
        await WaitForBlockedQueryAsync("%UPDATE identity_sessions%");
        await using var issuer = host.Api.Services.CreateAsyncScope();
        var session = Session(user.Id);
        var issue = issuer.ServiceProvider.GetRequiredService<IEmailPasswordAccessStore>().AddSessionAsync(session, default);
        await WaitForBlockedQueryAsync("%INSERT INTO identity_sessions%");
        await transaction.CommitAsync();
        using var response = await revoke.WaitAsync(TimeSpan.FromSeconds(10));
        await issue.WaitAsync(TimeSpan.FromSeconds(10));
        response.EnsureSuccessStatusCode();
        Assert.Equal(1, (await response.Content.ReadFromJsonAsync<AdminOperationResult>())!.RevokedSessions);
        Assert.Null((await blockerDb.IdentitySessions.AsNoTracking().SingleAsync(item => item.Id == session.Id)).RevokedAt);
    }

    [Fact]
    public async Task FlowIssuanceOverlappingRevocation_RechecksSourceAndCannotIssueASuccessor()
    {
        var policy = TestAccessPolicies.Create();
        var original = host.Command.Apps[0].Environments[0];
        var updated = original with
        {
            AccessPolicy = policy,
            Providers = TestEnvironmentConfigurations.Providers(policy),
            DevelopmentBypass = TestEnvironmentConfigurations.DevelopmentBypass(policy),
        };
        await using (var setup = host.Api.Services.CreateAsyncScope())
        {
            await setup.ServiceProvider.GetRequiredService<BootstrapTopologyHandler>().HandleAsync(host.Command with
            { Apps = [host.Command.Apps[0] with { Environments = [updated, host.Command.Apps[0].Environments[1]] }] });
        }
        var user = await host.RegisterAsync();
        using var started = await host.Consumer.PostAsJsonAsync("/v1/access/flows", new
        {
            requestId = Guid.NewGuid(), protocolVersions = new[] { 1 }, intent = "continueRegistration",
            applicationClientKey = "web", sessionToken = user.Token,
        });
        started.EnsureSuccessStatusCode();
        var body = await started.Content.ReadFromJsonAsync<JsonElement>();
        var snapshot = body.GetProperty("snapshot");
        var flowId = snapshot.GetProperty("flowId").GetGuid();
        var action = Assert.Single(snapshot.GetProperty("actions").EnumerateArray(), item => item.GetProperty("type").GetString() == "skipRegistration");

        await using var blocker = host.Api.Services.CreateAsyncScope();
        var db = blocker.ServiceProvider.GetRequiredService<AccessDbContext>();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.IdentitySessions.FromSqlInterpolated($"SELECT * FROM identity_sessions WHERE identity_id = {user.Id} FOR UPDATE").ToArrayAsync();
        var revoke = host.SendAsync(HttpMethod.Post, host.IdentityPath(user.Id) + "/sessions/revoke", AccessPermission.RevokeAllSessions, Guid.NewGuid());
        await WaitForBlockedQueryAsync("%UPDATE identity_sessions%");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/v1/access/flows/{flowId}/actions")
        {
            Content = JsonContent.Create(new { requestId = Guid.NewGuid(), expectedRevision = 1,
                action = new { id = action.GetProperty("id").GetGuid(), type = "skipRegistration" } }),
        };
        request.Headers.Add("Bullgate-Flow-Capability", body.GetProperty("flowCapability").GetString());
        var advance = host.Consumer.SendAsync(request);
        await WaitForBlockedQueryAsync("%SELECT * FROM identities%FOR UPDATE%");
        await transaction.CommitAsync();
        using var revoked = await revoke.WaitAsync(TimeSpan.FromSeconds(10));
        revoked.EnsureSuccessStatusCode();
        using var advanced = await advance.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(advanced.IsSuccessStatusCode);
        Assert.False(await db.IdentitySessions.AnyAsync(item => item.IdentityId == user.Id && item.Purpose == IdentitySessionPurpose.Product));
        Assert.Equal(1, (await db.AccessFlows.AsNoTracking().SingleAsync(item => item.Id == flowId)).CurrentRevision);
    }

    private IdentitySession Session(Guid identityId)
    {
        var now = DateTimeOffset.UtcNow;
        return new(Guid.CreateVersion7(), identityId, host.EnvironmentId, IdentitySessionPurpose.Product,
            RandomNumberGenerator.GetBytes(32), now, now.AddDays(1));
    }

    private async Task WaitForBlockedQueryAsync(string pattern)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync(deadline.Token);
        await using var command = new NpgsqlCommand(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE @pattern)", connection);
        command.Parameters.AddWithValue("pattern", pattern);
        while (!((bool?)await command.ExecuteScalarAsync(deadline.Token) ?? false))
            await Task.Delay(20, deadline.Token);
    }
}
