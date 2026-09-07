namespace Bullgate.Access.Domain.Topology;

/// <summary>Platform represented by a public application-client key.</summary>
public enum ApplicationClientPlatform
{
    /// <summary>Android package and optional SMS Retriever metadata.</summary>
    Android = 1,

    /// <summary>Apple bundle metadata.</summary>
    Ios = 2,

    /// <summary>Browser client with no native application id.</summary>
    Web = 3,
}

/// <summary>
/// Public, stable identity and metadata for one consumer application build family.
/// </summary>
/// <remarks>
/// The key selects public configuration inside an already authenticated environment.
/// It is not a credential. Native application ids are mandatory; Android alone may
/// carry an SMS Retriever app hash.
/// </remarks>
public sealed class ApplicationClient
{
    private ApplicationClient()
    {
    }

    /// <summary>Creates an active public build identity inside one app environment.</summary>
    public ApplicationClient(
        Guid id,
        Guid appEnvironmentId,
        string key,
        string name,
        ApplicationClientPlatform platform,
        string? applicationId,
        string? signingIdentity,
        string? smsRetrieverAppHash,
        DateTimeOffset createdAt)
    {
        Id = TopologyValue.Id(id, nameof(id));
        AppEnvironmentId = TopologyValue.Id(appEnvironmentId, nameof(appEnvironmentId));
        Key = TopologyValue.Key(key, nameof(key));
        Configure(
            name,
            platform,
            applicationId,
            signingIdentity,
            smsRetrieverAppHash);
        CreatedAt = TopologyValue.UtcTimestamp(createdAt, nameof(createdAt));
        IsActive = true;
    }

    /// <summary>Internal database identifier; clients use <see cref="Key"/>.</summary>
    public Guid Id { get; private set; }

    /// <summary>Environment in which the public key may select metadata.</summary>
    public Guid AppEnvironmentId { get; private set; }

    /// <summary>Stable public selector; never a credential.</summary>
    public string Key { get; private set; } = null!;

    /// <summary>Human-readable build-family name.</summary>
    public string Name { get; private set; } = null!;

    /// <summary>Client platform that determines native metadata rules.</summary>
    public ApplicationClientPlatform Platform { get; private set; }

    /// <summary>Android package or Apple bundle id; null for web clients.</summary>
    public string? ApplicationId { get; private set; }

    /// <summary>Optional signing certificate or application identity metadata.</summary>
    public string? SigningIdentity { get; private set; }

    /// <summary>Optional Android-only SMS Retriever application hash.</summary>
    public string? SmsRetrieverAppHash { get; private set; }

    /// <summary>Whether this selector remains available.</summary>
    public bool IsActive { get; private set; }

    /// <summary>UTC creation time of the stable client identity.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>
    /// Reconciles mutable public build metadata without changing the stable key, id, or
    /// environment scope.
    /// </summary>
    public void Configure(
        string name,
        ApplicationClientPlatform platform,
        string? applicationId,
        string? signingIdentity,
        string? smsRetrieverAppHash)
    {
        if (!Enum.IsDefined(platform))
        {
            throw new ArgumentOutOfRangeException(nameof(platform));
        }

        var validatedApplicationId = TopologyValue.OptionalApplicationId(
            applicationId,
            nameof(applicationId));
        var validatedAppHash = TopologyValue.SmsRetrieverAppHash(
            smsRetrieverAppHash,
            nameof(smsRetrieverAppHash));
        // Native identity is part of the trust/configuration contract. Web clients
        // have no package/bundle id, so requiring it there would invent a false value.
        if (platform is ApplicationClientPlatform.Android or ApplicationClientPlatform.Ios
            && validatedApplicationId is null)
        {
            throw new ArgumentException(
                "An application id is required for Android and iOS clients.",
                nameof(applicationId));
        }
        // SMS Retriever derives this hash from the Android package and signing
        // certificate. Accepting it for iOS or Web would suggest a capability those
        // platforms do not implement.
        if (validatedAppHash is not null && platform != ApplicationClientPlatform.Android)
        {
            throw new ArgumentException(
                "SMS Retriever app hash is supported only for Android application clients.",
                nameof(smsRetrieverAppHash));
        }

        Name = TopologyValue.Name(name, nameof(name));
        Platform = platform;
        ApplicationId = validatedApplicationId;
        SigningIdentity = TopologyValue.OptionalSigningIdentity(
            signingIdentity,
            nameof(signingIdentity));
        SmsRetrieverAppHash = validatedAppHash;
    }
}
