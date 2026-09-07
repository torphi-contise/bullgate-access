namespace Bullgate.Access.Application.Identities;

/// <summary>Reads an active identity email within authenticated realm scope.</summary>
public interface IIdentityEmailStore
{
    /// <summary>Finds the normalized e-mail for an active identity in the given realm.</summary>
    /// <returns>
    /// The e-mail, or <see langword="null"/> when the identity is absent, inactive,
    /// outside the realm, or has no e-mail identifier.
    /// </returns>
    /// <param name="realmId">Realm fixed by authenticated integration scope.</param>
    /// <param name="identityId">Caller-controlled durable identity selector.</param>
    /// <param name="cancellationToken">Cancels the scoped query.</param>
    Task<string?> FindAsync(
        Guid realmId,
        Guid identityId,
        CancellationToken cancellationToken);
}
