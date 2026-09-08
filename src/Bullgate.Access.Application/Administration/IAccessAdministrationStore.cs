namespace Bullgate.Access.Application.Administration;

/// <summary>Access-owned queries and atomic administrative mutations.</summary>
public interface IAccessAdministrationStore
{
    Task<IReadOnlyList<AdminIdentity>> ListIdentitiesAsync(
        AdminIdentityQuery query, Guid? afterId, CancellationToken cancellationToken);
    Task<AdminIdentity?> ReadIdentityAsync(
        Guid realmId, Guid identityId, CancellationToken cancellationToken);
    Task<IReadOnlyList<AdminEnvironment>> ListEnvironmentsAsync(
        int pageSize, Guid? afterId, CancellationToken cancellationToken);
    Task<AdminOperationResult> MutateAsync(
        AdminCallContext context, AdminMutation mutation, CancellationToken cancellationToken);
}
