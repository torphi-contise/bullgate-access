namespace Bullgate.Access.Domain.Topology;

/// <summary>Stable provider keys referenced by identifier verification policy.</summary>
public static class VerificationProviderKey
{
    /// <summary>Twilio Verify provider key accepted by phone verification policy.</summary>
    public const string TwilioVerify = "twilio-verify";
}

/// <summary>
/// Declares whether an enabled identifier requires an external verification provider.
/// </summary>
public sealed record IdentifierVerificationPolicy
{
    /// <summary>Creates a consistent disabled or provider-backed verification rule.</summary>
    public IdentifierVerificationPolicy(bool enabled, string? provider)
    {
        // A provider on a disabled verification policy is almost certainly a
        // configuration mistake. Reject it instead of retaining an ignored secret or
        // implying that proof occurs when it does not.
        if (!enabled)
        {
            if (provider is not null)
            {
                throw new ArgumentException(
                    "A disabled verification cannot select a provider.",
                    nameof(provider));
            }

            Enabled = false;
            return;
        }

        Enabled = true;
        Provider = TopologyValue.Key(provider ?? string.Empty, nameof(provider));
    }

    /// <summary>Whether this identifier requires a possession-verification journey.</summary>
    public bool Enabled { get; }

    /// <summary>Stable provider adapter key, or null only when verification is disabled.</summary>
    public string? Provider { get; }

    /// <summary>Canonical provider-free disabled verification policy.</summary>
    public static IdentifierVerificationPolicy Disabled { get; } = new(false, null);
}

/// <summary>Enables an identifier and declares whether collection is required.</summary>
public sealed record IdentifierAccessPolicy
{
    /// <summary>Creates one internally consistent identifier collection policy.</summary>
    public IdentifierAccessPolicy(
        bool enabled,
        bool required,
        IdentifierVerificationPolicy verification)
    {
        ArgumentNullException.ThrowIfNull(verification);
        // Required collection or verification of a disabled identifier is an
        // impossible runtime state; fail during bootstrap rather than in a journey.
        if (!enabled && (required || verification.Enabled))
        {
            throw new ArgumentException(
                "A disabled identifier cannot be required or verified.",
                nameof(enabled));
        }

        Enabled = enabled;
        Required = required;
        Verification = verification;
    }

    /// <summary>Whether the identifier may participate in this environment.</summary>
    public bool Enabled { get; }

    /// <summary>Whether registration must collect the enabled identifier.</summary>
    public bool Required { get; }

    /// <summary>Possession-verification rule for the enabled identifier.</summary>
    public IdentifierVerificationPolicy Verification { get; }
}

/// <summary>Authenticator switches owned by one application environment.</summary>
public sealed record AuthenticatorAccessPolicy(
    bool PasswordEnabled,
    bool GoogleEnabled,
    bool AppleEnabled);

/// <summary>Position of the combined CPF and birth-date registration step.</summary>
public enum CpfCollectionPosition
{
    /// <summary>Collect civil data before collecting the phone.</summary>
    BeforePhone,
    /// <summary>Collect civil data after the required phone step.</summary>
    AfterPhone,
}

/// <summary>Complete queryable access policy for email, CPF, phone, and authenticators.</summary>
public sealed record AppAccessPolicy
{
    /// <summary>Combines identifier and authenticator policy for one environment.</summary>
    public AppAccessPolicy(
        IdentifierAccessPolicy email,
        IdentifierAccessPolicy phone,
        AuthenticatorAccessPolicy authenticators,
        IdentifierAccessPolicy? cpf = null,
        CpfCollectionPosition? cpfCollectionPosition = null)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(phone);
        ArgumentNullException.ThrowIfNull(authenticators);

        Email = email;
        Cpf = cpf ?? new IdentifierAccessPolicy(
            false,
            false,
            IdentifierVerificationPolicy.Disabled);
        if (Cpf.Enabled && !Cpf.Required)
        {
            throw new ArgumentException(
                "An enabled CPF identifier must be required.",
                nameof(cpf));
        }
        if (Cpf.Verification.Enabled)
        {
            throw new ArgumentException(
                "CPF ownership verification is not implemented.",
                nameof(cpf));
        }
        if (Cpf.Enabled && cpfCollectionPosition is null)
        {
            throw new ArgumentException(
                "Enabled CPF collection requires an explicit position.",
                nameof(cpfCollectionPosition));
        }
        if (cpfCollectionPosition is { } position && !Enum.IsDefined(position))
        {
            throw new ArgumentOutOfRangeException(nameof(cpfCollectionPosition));
        }
        if (cpfCollectionPosition == Topology.CpfCollectionPosition.AfterPhone
            && (!phone.Enabled || !phone.Required))
        {
            throw new ArgumentException(
                "CPF collection after phone requires phone to be enabled and required.",
                nameof(cpfCollectionPosition));
        }
        CpfCollectionPosition = cpfCollectionPosition;
        Phone = phone;
        Authenticators = authenticators;
    }

    /// <summary>E-mail collection and verification policy.</summary>
    public IdentifierAccessPolicy Email { get; }

    /// <summary>Required CPF and birth-date collection policy.</summary>
    public IdentifierAccessPolicy Cpf { get; }

    /// <summary>Explicit collection position, optional only when CPF is disabled.</summary>
    public CpfCollectionPosition? CpfCollectionPosition { get; }

    /// <summary>Phone collection and verification policy.</summary>
    public IdentifierAccessPolicy Phone { get; }

    /// <summary>Enabled password and social authentication methods.</summary>
    public AuthenticatorAccessPolicy Authenticators { get; }
}
