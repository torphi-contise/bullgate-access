namespace Bullgate.Access.Domain.Topology;

/// <summary>
/// Connects an application to a realm and owns the access policy and protected
/// provider configuration for one deployment environment.
/// </summary>
/// <remarks>
/// Policy fields remain queryable while the complete configuration document is
/// stored as AES-GCM nonce, ciphertext, and tag. Provider secrets must never be
/// exposed through public application-client configuration.
/// </remarks>
public sealed class AppEnvironment
{
    private AppEnvironment()
    {
    }

    /// <summary>
    /// Creates an active app-to-realm binding with queryable policy and no protected
    /// envelope until bootstrap stores one.
    /// </summary>
    public AppEnvironment(
        Guid id,
        Guid workspaceId,
        Guid appId,
        Guid realmId,
        string key,
        string name,
        AppAccessPolicy accessPolicy,
        DateTimeOffset createdAt,
        string? passwordRecoveryUrl = null)
    {
        Id = TopologyValue.Id(id, nameof(id));
        WorkspaceId = TopologyValue.Id(workspaceId, nameof(workspaceId));
        AppId = TopologyValue.Id(appId, nameof(appId));
        RealmId = TopologyValue.Id(realmId, nameof(realmId));
        Key = TopologyValue.Key(key, nameof(key));
        Name = TopologyValue.Name(name, nameof(name));
        Apply(accessPolicy);
        PasswordRecoveryUrl = TopologyValue.PasswordRecoveryUrl(
            passwordRecoveryUrl,
            nameof(passwordRecoveryUrl));
        CreatedAt = TopologyValue.UtcTimestamp(createdAt, nameof(createdAt));
        IsActive = true;
    }

    /// <summary>Durable internal environment identifier.</summary>
    public Guid Id { get; private set; }

    /// <summary>Owning workspace, duplicated for explicit scope queries.</summary>
    public Guid WorkspaceId { get; private set; }

    /// <summary>Application that owns this deployment environment.</summary>
    public Guid AppId { get; private set; }

    /// <summary>Identity partition used by this environment.</summary>
    public Guid RealmId { get; private set; }

    /// <summary>Stable natural key inside the owning application.</summary>
    public string Key { get; private set; } = null!;

    /// <summary>Human-readable environment name.</summary>
    public string Name { get; private set; } = null!;

    /// <summary>Queryable switch for e-mail identity operations.</summary>
    public bool EmailIdentifierEnabled { get; private set; }

    /// <summary>Whether registration must collect e-mail when e-mail is enabled.</summary>
    public bool EmailIdentifierRequired { get; private set; }

    /// <summary>Queryable e-mail-verification switch.</summary>
    public bool EmailVerificationEnabled { get; private set; }

    /// <summary>Selected e-mail verification adapter key, when enabled.</summary>
    public string? EmailVerificationProvider { get; private set; }

    /// <summary>Queryable switch for phone identity operations.</summary>
    public bool PhoneIdentifierEnabled { get; private set; }

    /// <summary>Whether registration must collect phone when phone is enabled.</summary>
    public bool PhoneIdentifierRequired { get; private set; }

    /// <summary>Queryable phone-possession verification switch.</summary>
    public bool PhoneVerificationEnabled { get; private set; }

    /// <summary>Selected phone verification adapter key, when enabled.</summary>
    public string? PhoneVerificationProvider { get; private set; }

    /// <summary>Whether password authentication is enabled in this environment.</summary>
    public bool PasswordAuthenticatorEnabled { get; private set; }

    /// <summary>Whether Google authentication is enabled in this environment.</summary>
    public bool GoogleAuthenticatorEnabled { get; private set; }

    /// <summary>Whether Apple authentication is enabled in this environment.</summary>
    public bool AppleAuthenticatorEnabled { get; private set; }

    /// <summary>Optional HTTPS base URL used to build e-mail recovery links.</summary>
    public string? PasswordRecoveryUrl { get; private set; }

    /// <summary>Explicit serializer/envelope version authenticated with ciphertext.</summary>
    public int ConfigurationFormatVersion { get; private set; }

    /// <summary>Per-write AES-GCM nonce; not secret but never reusable with the key.</summary>
    public byte[] ConfigurationNonce { get; private set; } = [];

    /// <summary>Encrypted complete environment configuration.</summary>
    public byte[] ConfigurationCiphertext { get; private set; } = [];

    /// <summary>AES-GCM authentication tag for ciphertext and associated scope data.</summary>
    public byte[] ConfigurationTag { get; private set; } = [];

    /// <summary>UTC time at which bootstrap last protected the complete document.</summary>
    public DateTimeOffset ConfigurationUpdatedAt { get; private set; }

    /// <summary>Whether this app-to-realm binding may currently be used.</summary>
    public bool IsActive { get; private set; }

    /// <summary>UTC creation time of the stable environment identity.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Reconstructs the typed access policy from persisted query fields.</summary>
    public AppAccessPolicy AccessPolicy => new(
        new IdentifierAccessPolicy(
            EmailIdentifierEnabled,
            EmailIdentifierRequired,
            new IdentifierVerificationPolicy(
                EmailVerificationEnabled,
                EmailVerificationProvider)),
        new IdentifierAccessPolicy(
            PhoneIdentifierEnabled,
            PhoneIdentifierRequired,
            new IdentifierVerificationPolicy(
                PhoneVerificationEnabled,
                PhoneVerificationProvider)),
        new AuthenticatorAccessPolicy(
            PasswordAuthenticatorEnabled,
            GoogleAuthenticatorEnabled,
            AppleAuthenticatorEnabled));

    /// <summary>Replaces the queryable access policy for this environment.</summary>
    public void ConfigureAccess(AppAccessPolicy accessPolicy) => Apply(accessPolicy);

    /// <summary>Sets the HTTPS destination used by email password recovery.</summary>
    public void ConfigurePasswordRecoveryUrl(string? passwordRecoveryUrl) =>
        PasswordRecoveryUrl = TopologyValue.PasswordRecoveryUrl(
            passwordRecoveryUrl,
            nameof(passwordRecoveryUrl));

    /// <summary>
    /// Stores an already encrypted configuration envelope after validating the
    /// AES-GCM structural sizes and UTC update timestamp.
    /// </summary>
    public void StoreProtectedConfiguration(
        int formatVersion,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag,
        DateTimeOffset updatedAt)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(formatVersion, 1);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(tag);
        if (nonce.Length != 12)
        {
            throw new ArgumentException("AES-GCM nonce must contain 12 bytes.", nameof(nonce));
        }
        if (ciphertext.Length == 0)
        {
            throw new ArgumentException("Configuration ciphertext cannot be empty.", nameof(ciphertext));
        }
        if (tag.Length != 16)
        {
            throw new ArgumentException("AES-GCM tag must contain 16 bytes.", nameof(tag));
        }

        // Clone every input so later mutation of the protector's buffers cannot change
        // the authenticated envelope already assigned to this domain entity.
        ConfigurationFormatVersion = formatVersion;
        ConfigurationNonce = nonce.ToArray();
        ConfigurationCiphertext = ciphertext.ToArray();
        ConfigurationTag = tag.ToArray();
        ConfigurationUpdatedAt = TopologyValue.UtcTimestamp(updatedAt, nameof(updatedAt));
    }

    private void Apply(AppAccessPolicy accessPolicy)
    {
        ArgumentNullException.ThrowIfNull(accessPolicy);
        EmailIdentifierEnabled = accessPolicy.Email.Enabled;
        EmailIdentifierRequired = accessPolicy.Email.Required;
        EmailVerificationEnabled = accessPolicy.Email.Verification.Enabled;
        EmailVerificationProvider = accessPolicy.Email.Verification.Provider;
        PhoneIdentifierEnabled = accessPolicy.Phone.Enabled;
        PhoneIdentifierRequired = accessPolicy.Phone.Required;
        PhoneVerificationEnabled = accessPolicy.Phone.Verification.Enabled;
        PhoneVerificationProvider = accessPolicy.Phone.Verification.Provider;
        PasswordAuthenticatorEnabled = accessPolicy.Authenticators.PasswordEnabled;
        GoogleAuthenticatorEnabled = accessPolicy.Authenticators.GoogleEnabled;
        AppleAuthenticatorEnabled = accessPolicy.Authenticators.AppleEnabled;
    }
}
