namespace Bullgate.Access.Domain.Identities;

/// <summary>Canonical storage limits for identity and credential values.</summary>
public static class IdentityLimits
{
    /// <summary>Maximum persisted identifier-scheme length.</summary>
    public const int IdentifierSchemeMaxLength = 32;
    /// <summary>Maximum persisted normalized e-mail or generic identifier length.</summary>
    public const int IdentifierValueMaxLength = 320;
    /// <summary>Maximum canonical E.164 phone length including the plus sign.</summary>
    public const int PhoneValueMaxLength = 16;
    /// <summary>Maximum encoded password-hasher output length.</summary>
    public const int PasswordHashMaxLength = 1024;
    /// <summary>Exact SHA-256 session-token hash length in bytes.</summary>
    public const int SessionTokenHashLength = 32;
    /// <summary>Exact SHA-256 password-reset-token hash length in bytes.</summary>
    public const int PasswordResetTokenHashLength = 32;
    /// <summary>Exact phone-recovery code-hash length in bytes.</summary>
    public const int PhonePasswordResetCodeHashLength = 32;
    /// <summary>Maximum persisted verification-method name length.</summary>
    public const int VerificationMethodMaxLength = 32;
    /// <summary>Maximum external provider correlation-reference length.</summary>
    public const int ProviderReferenceMaxLength = 128;
    /// <summary>Maximum persisted social-provider discriminator length.</summary>
    public const int SocialProviderMaxLength = 32;
    /// <summary>Maximum stable provider-subject length.</summary>
    public const int SocialSubjectMaxLength = 200;
}

/// <summary>Stable identifier scheme names used in persistence and API behavior.</summary>
public static class IdentifierScheme
{
    /// <summary>Canonical e-mail identifier discriminator.</summary>
    public const string Email = "email";
    /// <summary>Canonical Brazilian CPF identifier discriminator.</summary>
    public const string Cpf = "cpf";
    /// <summary>Canonical phone identifier discriminator.</summary>
    public const string Phone = "phone";
}
