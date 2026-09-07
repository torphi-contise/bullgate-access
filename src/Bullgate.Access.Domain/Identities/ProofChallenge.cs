namespace Bullgate.Access.Domain.Identities;

/// <summary>Kind of possession or identity proof requested by a challenge.</summary>
public enum ProofChallengeType
{
    /// <summary>Proof that the flow participant currently controls a phone destination.</summary>
    PhonePossession,
}

/// <summary>Delivery channel used to carry a proof challenge secret.</summary>
public enum ProofChallengeChannel
{
    /// <summary>A provider transports the generated secret by SMS.</summary>
    Sms,

    /// <summary>A provider transports the generated secret by e-mail.</summary>
    Email,
}

/// <summary>Lifecycle of a proof challenge and its bounded attempts.</summary>
public enum ProofChallengeStatus
{
    /// <summary>Database reservation exists, but provider delivery is not yet usable.</summary>
    PendingDelivery,

    /// <summary>The delivered challenge may accept attempts before its expiry.</summary>
    Active,

    /// <summary>One successful local comparison exclusively owns finalization.</summary>
    Confirming,

    /// <summary>The provider operation failed before the challenge became usable.</summary>
    DeliveryFailed,

    /// <summary>The challenge produced its one durable completed proof.</summary>
    Verified,

    /// <summary>A replacement or enclosing lifecycle transition closed the challenge.</summary>
    Superseded,

    /// <summary>The configured number of failed attempts was consumed.</summary>
    Exhausted,
}

/// <summary>
/// Expiring, rate-limited challenge that stores only the generated secret hash.
/// </summary>
/// <remarks>
/// A provider reference correlates delivery but does not replace the local hash as
/// proof authority for AccessFlow phone confirmation.
/// </remarks>
public sealed class ProofChallenge
{
    private ProofChallenge()
    {
    }

    /// <summary>Creates an immediately active challenge with a locally stored secret hash.</summary>
    /// <remarks>
    /// External-delivery orchestration normally uses <see cref="ReserveDelivery"/> so
    /// provider work is represented by <see cref="ProofChallengeStatus.PendingDelivery"/>
    /// before the challenge becomes active. This constructor represents the already
    /// usable form and still stores no clear secret.
    /// </remarks>
    /// <param name="id">Durable challenge id.</param>
    /// <param name="accessFlowId">Flow that owns the challenge.</param>
    /// <param name="identityId">Flow identity attempting the proof.</param>
    /// <param name="type">Fact that successful confirmation will establish.</param>
    /// <param name="channel">Transport used for the generated secret.</param>
    /// <param name="destinationScheme">Canonical identifier scheme for the destination.</param>
    /// <param name="destinationValue">Canonical destination value.</param>
    /// <param name="secretHash">Fixed-length hash of the generated secret.</param>
    /// <param name="providerReference">Optional provider correlation value, never proof authority.</param>
    /// <param name="maxAttempts">Positive number of failed comparisons permitted.</param>
    /// <param name="createdAt">UTC creation time.</param>
    /// <param name="expiresAt">UTC exclusive attempt and confirmation boundary.</param>
    /// <param name="resendAvailableAt">UTC time at which replacement delivery may be requested.</param>
    /// <exception cref="ArgumentException">
    /// An id, text value, hash, or timestamp relationship is invalid.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// An enum value is unknown or <paramref name="maxAttempts"/> is not positive.
    /// </exception>
    public ProofChallenge(
        Guid id,
        Guid accessFlowId,
        Guid identityId,
        ProofChallengeType type,
        ProofChallengeChannel channel,
        string destinationScheme,
        string destinationValue,
        byte[] secretHash,
        string? providerReference,
        int maxAttempts,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        DateTimeOffset resendAvailableAt)
    {
        Id = RequireId(id, nameof(id));
        AccessFlowId = RequireId(accessFlowId, nameof(accessFlowId));
        IdentityId = RequireId(identityId, nameof(identityId));
        if (!Enum.IsDefined(type))
        {
            throw new ArgumentOutOfRangeException(nameof(type));
        }
        if (!Enum.IsDefined(channel))
        {
            throw new ArgumentOutOfRangeException(nameof(channel));
        }

        Type = type;
        Channel = channel;
        DestinationScheme = RequireText(
            destinationScheme,
            IdentityLimits.IdentifierSchemeMaxLength,
            nameof(destinationScheme));
        DestinationValue = RequireText(
            destinationValue,
            IdentityLimits.IdentifierValueMaxLength,
            nameof(destinationValue));
        ArgumentNullException.ThrowIfNull(secretHash);
        if (secretHash.Length != IdentityLimits.SessionTokenHashLength)
        {
            throw new ArgumentException(
                $"Secret hash must contain {IdentityLimits.SessionTokenHashLength} bytes.",
                nameof(secretHash));
        }
        SecretHash = secretHash.ToArray();
        ProviderReference = OptionalText(
            providerReference,
            IdentityLimits.ProviderReferenceMaxLength,
            nameof(providerReference));
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

        Status = ProofChallengeStatus.Active;
    }

    /// <summary>Durable challenge selector; it is not a clear verification secret.</summary>
    public Guid Id { get; private set; }

    /// <summary>Flow whose scope, revision, and capability govern this challenge.</summary>
    public Guid AccessFlowId { get; private set; }

    /// <summary>Identity that must receive any proof materialized from this challenge.</summary>
    public Guid IdentityId { get; private set; }

    /// <summary>Fact that successful confirmation is intended to establish.</summary>
    public ProofChallengeType Type { get; private set; }

    /// <summary>Transport used to deliver the generated secret.</summary>
    public ProofChallengeChannel Channel { get; private set; }

    /// <summary>Canonical identifier scheme associated with <see cref="DestinationValue"/>.</summary>
    public string DestinationScheme { get; private set; } = null!;

    /// <summary>Canonical destination bound to this challenge and later revalidated.</summary>
    public string DestinationValue { get; private set; } = null!;

    /// <summary>Hash used for local constant-time comparison; clear secret is never persisted.</summary>
    public byte[] SecretHash { get; private set; } = null!;

    /// <summary>Optional external-delivery correlation value, not proof authority.</summary>
    public string? ProviderReference { get; private set; }

    /// <summary>Current lifecycle state controlling which transition may proceed.</summary>
    public ProofChallengeStatus Status { get; private set; }

    /// <summary>Committed failed-comparison count.</summary>
    public int Attempts { get; private set; }

    /// <summary>Maximum failed-comparison count before terminal exhaustion.</summary>
    public int MaxAttempts { get; private set; }

    /// <summary>UTC creation time and lower bound for terminal completion timestamps.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>UTC exclusive boundary for attempts and successful confirmation.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    /// <summary>UTC replacement-delivery cooldown boundary.</summary>
    public DateTimeOffset ResendAvailableAt { get; private set; }

    /// <summary>UTC terminal-transition time, or <see langword="null"/> while open.</summary>
    public DateTimeOffset? CompletedAt { get; private set; }

    /// <summary>Creates a durable reservation before calling an external provider.</summary>
    /// <remarks>
    /// The returned challenge is <see cref="ProofChallengeStatus.PendingDelivery"/>
    /// and has no provider reference. Provider success must be finalized with
    /// <see cref="Activate"/>; provider failure must use <see cref="FailDelivery"/>.
    /// </remarks>
    /// <param name="id">Durable challenge id.</param>
    /// <param name="accessFlowId">Flow that owns the challenge.</param>
    /// <param name="identityId">Flow identity attempting the proof.</param>
    /// <param name="type">Fact that successful confirmation will establish.</param>
    /// <param name="channel">Transport used for the generated secret.</param>
    /// <param name="destinationScheme">Canonical identifier scheme for the destination.</param>
    /// <param name="destinationValue">Canonical destination value.</param>
    /// <param name="secretHash">Fixed-length hash of the generated secret.</param>
    /// <param name="maxAttempts">Positive number of failed comparisons permitted.</param>
    /// <param name="createdAt">UTC reservation time.</param>
    /// <param name="expiresAt">UTC exclusive confirmation boundary.</param>
    /// <param name="resendAvailableAt">UTC replacement-delivery cooldown boundary.</param>
    /// <returns>A non-usable pending-delivery challenge containing only the secret hash.</returns>
    public static ProofChallenge ReserveDelivery(
        Guid id,
        Guid accessFlowId,
        Guid identityId,
        ProofChallengeType type,
        ProofChallengeChannel channel,
        string destinationScheme,
        string destinationValue,
        byte[] secretHash,
        int maxAttempts,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        DateTimeOffset resendAvailableAt)
    {
        var challenge = new ProofChallenge(
            id,
            accessFlowId,
            identityId,
            type,
            channel,
            destinationScheme,
            destinationValue,
            secretHash,
            null,
            maxAttempts,
            createdAt,
            expiresAt,
            resendAvailableAt);
        challenge.Status = ProofChallengeStatus.PendingDelivery;
        return challenge;
    }

    /// <summary>Marks a successfully delivered reservation as usable for attempts.</summary>
    /// <param name="providerReference">Optional provider correlation value.</param>
    /// <exception cref="InvalidOperationException">The challenge is not pending delivery.</exception>
    public void Activate(string? providerReference)
    {
        if (Status != ProofChallengeStatus.PendingDelivery)
        {
            throw new InvalidOperationException(
                "Only a pending delivery challenge can become active.");
        }

        ProviderReference = OptionalText(
            providerReference,
            IdentityLimits.ProviderReferenceMaxLength,
            nameof(providerReference));
        Status = ProofChallengeStatus.Active;
    }

    /// <summary>Closes a pending reservation whose provider delivery did not succeed.</summary>
    /// <remarks>
    /// Repeating this operation after the challenge left pending-delivery state is an
    /// idempotent no-op. It never invalidates an older active replacement candidate.
    /// </remarks>
    /// <param name="failedAt">UTC terminal time not earlier than creation.</param>
    public void FailDelivery(DateTimeOffset failedAt)
    {
        if (Status != ProofChallengeStatus.PendingDelivery)
        {
            return;
        }

        CompletedAt = RequireCompletionTime(failedAt, nameof(failedAt));
        Status = ProofChallengeStatus.DeliveryFailed;
    }

    /// <summary>Reserves exclusive finalization after a successful local comparison.</summary>
    /// <param name="confirmingAt">UTC time strictly before expiry.</param>
    /// <exception cref="InvalidOperationException">The challenge is not active or has expired.</exception>
    public void BeginConfirmation(DateTimeOffset confirmingAt)
    {
        EnsureActive(confirmingAt);
        Status = ProofChallengeStatus.Confirming;
    }

    /// <summary>Releases an unfinished confirmation reservation.</summary>
    /// <remarks>
    /// A still-live challenge returns to <see cref="ProofChallengeStatus.Active"/>. An
    /// expired challenge becomes <see cref="ProofChallengeStatus.Superseded"/> so an
    /// interrupted finalizer cannot reopen stale authority. Other states are no-ops.
    /// </remarks>
    /// <param name="releasedAt">UTC release time not earlier than creation.</param>
    public void ReleaseConfirmation(DateTimeOffset releasedAt)
    {
        if (Status != ProofChallengeStatus.Confirming)
        {
            return;
        }

        releasedAt = RequireCompletionTime(releasedAt, nameof(releasedAt));
        if (releasedAt >= ExpiresAt)
        {
            Status = ProofChallengeStatus.Superseded;
            CompletedAt = releasedAt;
            return;
        }

        Status = ProofChallengeStatus.Active;
    }

    /// <summary>Commits one failed secret comparison and enforces the configured limit.</summary>
    /// <param name="attemptedAt">UTC attempt time strictly before expiry.</param>
    /// <returns><see langword="true"/> when this failure exhausts the challenge.</returns>
    /// <exception cref="InvalidOperationException">The challenge is not active or has expired.</exception>
    public bool RecordFailure(DateTimeOffset attemptedAt)
    {
        EnsureActive(attemptedAt);
        Attempts = checked(Attempts + 1);
        if (Attempts >= MaxAttempts)
        {
            Status = ProofChallengeStatus.Exhausted;
            CompletedAt = attemptedAt;
            return true;
        }

        return false;
    }

    /// <summary>Completes an active challenge without a separate confirming reservation.</summary>
    /// <remarks>
    /// Multi-step AccessFlow confirmation uses <see cref="BeginConfirmation"/> followed
    /// by <see cref="Confirm"/>. This direct transition is for a transaction that can
    /// compare and materialize proof without crossing that reservation boundary.
    /// </remarks>
    /// <param name="verifiedAt">UTC verification time strictly before expiry.</param>
    public void Verify(DateTimeOffset verifiedAt)
    {
        EnsureActive(verifiedAt);
        Status = ProofChallengeStatus.Verified;
        CompletedAt = verifiedAt;
    }

    /// <summary>Completes the exact challenge currently reserved for confirmation.</summary>
    /// <param name="verifiedAt">UTC verification time strictly before expiry.</param>
    /// <exception cref="InvalidOperationException">The challenge is not confirming or has expired.</exception>
    public void Confirm(DateTimeOffset verifiedAt)
    {
        verifiedAt = RequireUtc(verifiedAt, nameof(verifiedAt));
        if (Status != ProofChallengeStatus.Confirming || verifiedAt >= ExpiresAt)
        {
            throw new InvalidOperationException("The proof challenge is not confirming.");
        }

        Status = ProofChallengeStatus.Verified;
        CompletedAt = verifiedAt;
    }

    /// <summary>Closes still-open challenge authority because another state superseded it.</summary>
    /// <remarks>Repeating supersession against a terminal challenge is an idempotent no-op.</remarks>
    /// <param name="supersededAt">UTC terminal time not earlier than creation.</param>
    public void Supersede(DateTimeOffset supersededAt)
    {
        if (Status is not (ProofChallengeStatus.Active
            or ProofChallengeStatus.PendingDelivery
            or ProofChallengeStatus.Confirming))
        {
            return;
        }

        supersededAt = RequireCompletionTime(
            supersededAt,
            nameof(supersededAt));

        Status = ProofChallengeStatus.Superseded;
        CompletedAt = supersededAt;
    }

    private void EnsureActive(DateTimeOffset at)
    {
        at = RequireUtc(at, nameof(at));
        if (Status != ProofChallengeStatus.Active || at >= ExpiresAt)
        {
            throw new InvalidOperationException("The proof challenge is not active.");
        }
    }

    private DateTimeOffset RequireCompletionTime(
        DateTimeOffset value,
        string parameterName)
    {
        value = RequireUtc(value, parameterName);
        if (value < CreatedAt)
        {
            throw new ArgumentException(
                "Completion cannot precede creation.",
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

    private static string RequireText(string value, int maxLength, string parameterName)
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
        if (value is null)
        {
            return null;
        }
        return RequireText(value, maxLength, parameterName);
    }

    private static DateTimeOffset RequireUtc(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Timestamp must use the UTC offset.", parameterName);
        }
        return value;
    }
}
