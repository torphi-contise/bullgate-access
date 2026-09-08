using Bullgate.Access.Domain.Administration;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Microsoft.EntityFrameworkCore;

namespace Bullgate.Access.Infrastructure.Persistence;

/// <summary>
/// Entity Framework persistence boundary for topology, identities, sessions, proofs,
/// recovery material, and the complete AccessFlow history.
/// </summary>
public sealed class AccessDbContext(DbContextOptions<AccessDbContext> options)
    : DbContext(options)
{
    public DbSet<Workspace> Workspaces => Set<Workspace>();
    public DbSet<AdminOperation> AdminOperations => Set<AdminOperation>();
    public DbSet<App> Apps => Set<App>();
    public DbSet<Realm> Realms => Set<Realm>();
    public DbSet<AppEnvironment> AppEnvironments => Set<AppEnvironment>();
    public DbSet<IntegrationClient> IntegrationClients => Set<IntegrationClient>();
    public DbSet<IntegrationClientPermission> IntegrationClientPermissions =>
        Set<IntegrationClientPermission>();
    public DbSet<IntegrationClientSecret> IntegrationClientSecrets =>
        Set<IntegrationClientSecret>();
    public DbSet<ApplicationClient> ApplicationClients => Set<ApplicationClient>();
    public DbSet<Identity> Identities => Set<Identity>();
    public DbSet<IdentityIdentifier> IdentityIdentifiers => Set<IdentityIdentifier>();
    public DbSet<PasswordCredential> PasswordCredentials => Set<PasswordCredential>();
    public DbSet<SocialCredential> SocialCredentials => Set<SocialCredential>();
    public DbSet<RegistrationContext> RegistrationContexts => Set<RegistrationContext>();
    public DbSet<IdentitySession> IdentitySessions => Set<IdentitySession>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<PhonePasswordResetChallenge> PhonePasswordResetChallenges =>
        Set<PhonePasswordResetChallenge>();
    public DbSet<ProofChallenge> ProofChallenges => Set<ProofChallenge>();
    public DbSet<ProofAttempt> ProofAttempts => Set<ProofAttempt>();
    public DbSet<IdentityProof> IdentityProofs => Set<IdentityProof>();
    public DbSet<PhoneRegistrationConflict> PhoneRegistrationConflicts =>
        Set<PhoneRegistrationConflict>();
    public DbSet<AccessFlow> AccessFlows => Set<AccessFlow>();
    public DbSet<AccessFlowDataSubject> AccessFlowDataSubjects =>
        Set<AccessFlowDataSubject>();
    public DbSet<AccessFlowRevision> AccessFlowRevisions => Set<AccessFlowRevision>();
    public DbSet<AccessFlowRequest> AccessFlowRequests => Set<AccessFlowRequest>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AccessDbContext).Assembly);
    }
}
