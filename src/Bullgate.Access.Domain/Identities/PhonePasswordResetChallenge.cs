namespace Bullgate.Access.Domain.Identities;

/// <summary>Lifecycle of the separate phone password-recovery challenge.</summary>
public enum PhonePasswordResetChallengeStatus
{
    /// <summary>Reserved durably but not yet confirmed as delivered and usable.</summary>
    PendingDelivery,

    /// <summary>Delivery finalized, or bypassed, and eligible for code comparison.</summary>
    Active,

    /// <summary>Exclusively reserved by one valid-code confirmer during provider work.</summary>
    Confirming,

    /// <summary>Provider approval and reset-token issuance committed together.</summary>
    Completed,

    /// <summary>Replaced or made terminal after eligibility changed.</summary>
    Superseded,

    /// <summary>Maximum local code failures consumed.</summary>
    Exhausted,

    /// <summary>Reservation never became a usable delivered challenge.</summary>
    DeliveryFailed,
}

/// <summary>
/// Phone-possession challenge used specifically to issue a password reset token.
/// </summary>
/// <remarks>
/// This is intentionally separate from AccessFlow proof challenges because password
/// recovery has its own anti-enumeration, reservation, provider confirmation, and
/// token-issuance lifecycle.
/// </remarks>
public sealed class PhonePasswordResetChallenge
{
    private PhonePasswordResetChallenge()
    {
    }

    /// <summary>Creates a pending-delivery phone recovery reservation.</summary>
    /// <param name="id">Durable challenge identifier.</param>
    /// <param name="identityId">Identity owning the verified recovery phone.</param>
    /// <param name="appEnvironmentId">Environment that owns recovery policy.</param>
    /// <param name="phone">Canonical verified phone captured at reservation.</param>
    /// <param name="codeHash">Fixed-size hash of the clear local code.</param>
    /// <param name="maxAttempts">Positive number of allowed local mismatches.</param>
    /// <param name="createdAt">UTC reservation time.</param>
    /// <param name="expiresAt">UTC exclusive code-validity boundary.</param>
    /// <param name="resendAvailableAt">UTC earliest replacement-request time.</param>
    public PhonePasswordResetChallenge(
        Guid id,
        Guid identityId,
        Guid appEnvironmentId,
        string phone,
        byte[] codeHash,
        int maxAttempts,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        DateTimeOffset resendAvailableAt)
    {
        Id = RequireId(id, nameof(id));
        IdentityId = RequireId(identityId, nameof(identityId));
        AppEnvironmentId = RequireId(
            appEnvironmentId,
            nameof(appEnvironmentId));
        Phone = RequireText(
            phone,
            IdentityLimits.PhoneValueMaxLength,
            nameof(phone));

        ArgumentNullException.ThrowIfNull(codeHash);
        if (codeHash.Length != IdentityLimits.PhonePasswordResetCodeHashLength)
        {
            throw new ArgumentException(
                $"Code hash must contain "
                + $"{IdentityLimits.PhonePasswordResetCodeHashLength} bytes.",
                nameof(codeHash));
        }
        CodeHash = codeHash.ToArray();

        if (maxAttempts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAttempts));
        }
        MaxAttempts = maxAttempts;

        CreatedAt = RequireUtc(createdAt, nameof(createdAt));
        ExpiresAt = RequireUtc(expiresAt, nameof(expiresAt));
        ResendAvailableAt = RequireUtc(
            resendAvailableAt,
            nameof(resendAvailableAt));
        if (ExpiresAt <= CreatedAt || ResendAvailableAt < CreatedAt)
        {
            throw new ArgumentException("Challenge timestamps are invalid.");
        }

        Status = PhonePasswordResetChallengeStatus.PendingDelivery;
    }

    /// <summary>Durable challenge identifier; it is not proof authority.</summary>
    public Guid Id { get; private set; }

    /// <summary>Identity selected from verified phone ownership.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Environment boundary revalidated during every authoritative transition.</summary>
    public Guid AppEnvironmentId { get; private set; }

    /// <summary>Canonical phone whose ownership must remain verified.</summary>
    public string Phone { get; private set; } = null!;

    /// <summary>Non-reversible local code comparison material.</summary>
    public byte[] CodeHash { get; private set; } = null!;

    /// <summary>Opaque provider operation identifier used for approval or cancellation.</summary>
    public string? ProviderReference { get; private set; }

    /// <summary>UTC first provider-approval time, when approval completed.</summary>
    public DateTimeOffset? ProviderApprovedAt { get; private set; }

    /// <summary>Current durable lifecycle state.</summary>
    public PhonePasswordResetChallengeStatus Status { get; private set; }

    /// <summary>Number of committed local code mismatches.</summary>
    public int Attempts { get; private set; }

    /// <summary>Maximum committed local mismatches before exhaustion.</summary>
    public int MaxAttempts { get; private set; }

    /// <summary>UTC reservation time.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC exclusive code-validity boundary.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    /// <summary>UTC earliest time at which another request may reserve replacement.</summary>
    public DateTimeOffset ResendAvailableAt { get; private set; }

    /// <summary>UTC terminal-transition time, when the challenge is closed.</summary>
    public DateTimeOffset? CompletedAt { get; private set; }

    /// <summary>Determines whether local code comparison is currently allowed.</summary>
    /// <param name="now">Current UTC time.</param>
    /// <returns><see langword="true"/> only for active state strictly before expiry.</returns>
    public bool IsActive(DateTimeOffset now)
    {
        now = RequireUtc(now, nameof(now));
        return Status == PhonePasswordResetChallengeStatus.Active
            && now < ExpiresAt;
    }

    /// <summary>Promotes a delivered reservation to code-confirmable state.</summary>
    /// <remarks>A provider reference may be absent only for controlled development bypass.</remarks>
    /// <param name="providerReference">Opaque provider identifier used after local proof.</param>
    public void Activate(string? providerReference)
    {
        EnsureStatus(PhonePasswordResetChallengeStatus.PendingDelivery);
        ProviderReference = OptionalText(
            providerReference,
            IdentityLimits.ProviderReferenceMaxLength,
            nameof(providerReference));
        Status = PhonePasswordResetChallengeStatus.Active;
    }

    /// <summary>Closes a pending reservation that produced no usable delivery.</summary>
    /// <param name="failedAt">UTC terminal-transition time.</param>
    public void FailDelivery(DateTimeOffset failedAt)
    {
        EnsureStatus(PhonePasswordResetChallengeStatus.PendingDelivery);
        CompleteAs(
            PhonePasswordResetChallengeStatus.DeliveryFailed,
            failedAt,
            nameof(failedAt));
    }

    /// <summary>Closes an available challenge or an expired confirmation reservation.</summary>
    /// <param name="supersededAt">UTC terminal-transition time.</param>
    public void Supersede(DateTimeOffset supersededAt)
    {
        supersededAt = EnsureNotBeforeCreation(
            supersededAt,
            nameof(supersededAt));
        if (Status is not PhonePasswordResetChallengeStatus.PendingDelivery
            and not PhonePasswordResetChallengeStatus.Active
            && (Status != PhonePasswordResetChallengeStatus.Confirming
                || supersededAt < ExpiresAt))
        {
            throw new InvalidOperationException(
                "Only an available or expired confirming challenge can be superseded.");
        }

        CompleteAs(
            PhonePasswordResetChallengeStatus.Superseded,
            supersededAt,
            nameof(supersededAt));
    }

    /// <summary>Restores a provider-backed predecessor selected for replacement rollback.</summary>
    /// <remarks>The transactional store must establish that the predecessor is unexpired.</remarks>
    public void RestoreActive()
    {
        EnsureStatus(PhonePasswordResetChallengeStatus.Superseded);
        if (ProviderReference is null)
        {
            throw new InvalidOperationException(
                "Only a provider-backed challenge can be restored after supersession.");
        }

        Status = PhonePasswordResetChallengeStatus.Active;
        CompletedAt = null;
    }

    /// <summary>Commits one local mismatch and closes the challenge at its attempt limit.</summary>
    /// <param name="attemptedAt">UTC mismatch time while the challenge is active.</param>
    /// <returns><see langword="true"/> when this failure exhausted the challenge.</returns>
    public bool RecordFailure(DateTimeOffset attemptedAt)
    {
        EnsureActive(attemptedAt, nameof(attemptedAt));
        Attempts = checked(Attempts + 1);
        if (Attempts < MaxAttempts)
        {
            return false;
        }

        Status = PhonePasswordResetChallengeStatus.Exhausted;
        CompletedAt = attemptedAt;
        return true;
    }

    /// <summary>Reserves a locally matched code for one provider confirmer.</summary>
    /// <param name="confirmationStartedAt">UTC time at which exclusive confirmation began.</param>
    public void BeginConfirmation(DateTimeOffset confirmationStartedAt)
    {
        EnsureActive(confirmationStartedAt, nameof(confirmationStartedAt));
        Status = PhonePasswordResetChallengeStatus.Confirming;
    }

    /// <summary>Returns a still-valid failed provider attempt to active state.</summary>
    /// <param name="releasedAt">UTC provider-failure time validated by the store.</param>
    public void ReleaseConfirmation(DateTimeOffset releasedAt)
    {
        EnsureStatus(PhonePasswordResetChallengeStatus.Confirming);
        EnsureNotBeforeCreation(releasedAt, nameof(releasedAt));
        Status = PhonePasswordResetChallengeStatus.Active;
    }

    /// <summary>Records provider approval once without rewriting its first timestamp.</summary>
    /// <param name="approvedAt">UTC provider-approval time.</param>
    public void MarkProviderApproved(DateTimeOffset approvedAt)
    {
        EnsureStatus(PhonePasswordResetChallengeStatus.Confirming);
        approvedAt = EnsureNotBeforeCreation(approvedAt, nameof(approvedAt));
        ProviderApprovedAt ??= approvedAt;
    }

    /// <summary>Closes a provider-approved confirmation after reset authority is ready.</summary>
    /// <param name="completedAt">UTC time of the atomic local finalization.</param>
    public void Complete(DateTimeOffset completedAt)
    {
        EnsureStatus(PhonePasswordResetChallengeStatus.Confirming);
        if (ProviderApprovedAt is null)
        {
            throw new InvalidOperationException(
                "Provider approval is required before completing the challenge.");
        }

        completedAt = EnsureNotBeforeCreation(completedAt, nameof(completedAt));
        if (completedAt < ProviderApprovedAt)
        {
            throw new ArgumentException(
                "Completion cannot precede provider approval.",
                nameof(completedAt));
        }

        Status = PhonePasswordResetChallengeStatus.Completed;
        CompletedAt = completedAt;
    }

    private void EnsureActive(DateTimeOffset at, string parameterName)
    {
        at = EnsureNotBeforeCreation(at, parameterName);
        if (Status != PhonePasswordResetChallengeStatus.Active || at >= ExpiresAt)
        {
            throw new InvalidOperationException(
                "The phone password reset challenge is not active.");
        }
    }

    private void CompleteAs(
        PhonePasswordResetChallengeStatus status,
        DateTimeOffset completedAt,
        string parameterName)
    {
        CompletedAt = EnsureNotBeforeCreation(completedAt, parameterName);
        Status = status;
    }

    private void EnsureStatus(PhonePasswordResetChallengeStatus expected)
    {
        if (Status != expected)
        {
            throw new InvalidOperationException(
                $"Challenge status must be {expected}.");
        }
    }

    private DateTimeOffset EnsureNotBeforeCreation(
        DateTimeOffset value,
        string parameterName)
    {
        value = RequireUtc(value, parameterName);
        if (value < CreatedAt)
        {
            throw new ArgumentException(
                "Timestamp cannot precede challenge creation.",
                parameterName);
        }

        return value;
    }

    private static Guid RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Id cannot be empty.", parameterName);
        }

        return value;
    }

    private static string RequireText(
        string value,
        int maxLength,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > maxLength
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException("Value is invalid.", parameterName);
        }

        return value;
    }

    private static string? OptionalText(
        string? value,
        int maxLength,
        string parameterName)
    {
        return value is null
            ? null
            : RequireText(value, maxLength, parameterName);
    }

    private static DateTimeOffset RequireUtc(
        DateTimeOffset value,
        string parameterName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Timestamp must use the UTC offset.",
                parameterName);
        }

        return value;
    }
}
