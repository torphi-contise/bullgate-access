using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.UnitTests;

public sealed class PhonePasswordResetChallengeTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 2, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Constructor_CopiesHashAndCreatesPendingChallenge()
    {
        var hash = Enumerable.Repeat(
                (byte)7,
                IdentityLimits.PhonePasswordResetCodeHashLength)
            .ToArray();

        var challenge = CreateChallenge(hash: hash);
        hash[0] = 9;

        Assert.Equal(PhonePasswordResetChallengeStatus.PendingDelivery, challenge.Status);
        Assert.Equal(7, challenge.CodeHash[0]);
        Assert.Equal(0, challenge.Attempts);
        Assert.Null(challenge.ProviderReference);
        Assert.Null(challenge.ProviderApprovedAt);
        Assert.Null(challenge.CompletedAt);
        Assert.False(challenge.IsActive(Now));
    }

    [Fact]
    public void Constructor_RejectsInvalidScopePhoneHashAndAttemptLimit()
    {
        Assert.Throws<ArgumentException>(() => CreateChallenge(id: Guid.Empty));
        Assert.Throws<ArgumentException>(() => CreateChallenge(identityId: Guid.Empty));
        Assert.Throws<ArgumentException>(() => CreateChallenge(appEnvironmentId: Guid.Empty));
        Assert.Throws<ArgumentException>(() => CreateChallenge(phone: string.Empty));
        Assert.Throws<ArgumentException>(() => CreateChallenge(phone: " +5511999999999"));
        Assert.Throws<ArgumentException>(
            () => CreateChallenge(
                phone: new string('1', IdentityLimits.PhoneValueMaxLength + 1)));
        Assert.Throws<ArgumentNullException>(
            () => new PhonePasswordResetChallenge(
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid(),
                "+5511999999999",
                null!,
                5,
                Now,
                Now.AddMinutes(10),
                Now.AddMinutes(2)));
        Assert.Throws<ArgumentException>(() => CreateChallenge(hash: new byte[31]));
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateChallenge(maxAttempts: 0));
    }

    [Fact]
    public void Constructor_RejectsNonUtcAndInvalidTimestampOrdering()
    {
        var nonUtc = Now.ToOffset(TimeSpan.FromHours(-3));

        Assert.Throws<ArgumentException>(() => CreateChallenge(createdAt: nonUtc));
        Assert.Throws<ArgumentException>(() => CreateChallenge(expiresAt: nonUtc));
        Assert.Throws<ArgumentException>(() => CreateChallenge(resendAvailableAt: nonUtc));
        Assert.Throws<ArgumentException>(() => CreateChallenge(expiresAt: Now));
        Assert.Throws<ArgumentException>(
            () => CreateChallenge(resendAvailableAt: Now.AddTicks(-1)));
    }

    [Fact]
    public void Activate_MakesChallengeActiveAndValidatesProviderReference()
    {
        var challenge = CreateChallenge();

        Assert.Throws<ArgumentException>(() => challenge.Activate(" provider-reference"));
        Assert.Equal(PhonePasswordResetChallengeStatus.PendingDelivery, challenge.Status);

        challenge.Activate("provider-reference");

        Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
        Assert.Equal("provider-reference", challenge.ProviderReference);
        Assert.True(challenge.IsActive(Now));
        Assert.False(challenge.IsActive(Now.AddMinutes(10)));
        Assert.Throws<ArgumentException>(
            () => challenge.IsActive(Now.ToOffset(TimeSpan.FromHours(-3))));
        Assert.Throws<InvalidOperationException>(() => challenge.Activate(null));
    }

    [Fact]
    public void Confirmation_CanBeApprovedAndCompletedOnce()
    {
        var challenge = CreateActiveChallenge();
        var approvedAt = Now.AddMinutes(2);
        var completedAt = Now.AddMinutes(3);

        challenge.BeginConfirmation(Now.AddMinutes(1));
        challenge.MarkProviderApproved(approvedAt);
        challenge.MarkProviderApproved(approvedAt.AddSeconds(1));
        challenge.Complete(completedAt);

        Assert.Equal(PhonePasswordResetChallengeStatus.Completed, challenge.Status);
        Assert.Equal(approvedAt, challenge.ProviderApprovedAt);
        Assert.Equal(completedAt, challenge.CompletedAt);
        Assert.False(challenge.IsActive(completedAt));
        Assert.Throws<InvalidOperationException>(() => challenge.Complete(completedAt));
    }

    [Fact]
    public void Complete_RequiresProviderApprovalAndCannotPrecedeIt()
    {
        var challenge = CreateActiveChallenge();
        challenge.BeginConfirmation(Now.AddMinutes(1));

        Assert.Throws<InvalidOperationException>(
            () => challenge.Complete(Now.AddMinutes(2)));

        challenge.MarkProviderApproved(Now.AddMinutes(3));

        Assert.Throws<ArgumentException>(
            () => challenge.Complete(Now.AddMinutes(2)));

        Assert.Equal(PhonePasswordResetChallengeStatus.Confirming, challenge.Status);
        Assert.Null(challenge.CompletedAt);
    }

    [Fact]
    public void Confirmation_CanBeReleasedForAnotherAttempt()
    {
        var challenge = CreateActiveChallenge();
        challenge.BeginConfirmation(Now.AddMinutes(1));

        Assert.Throws<ArgumentException>(
            () => challenge.ReleaseConfirmation(Now.AddTicks(-1)));

        challenge.ReleaseConfirmation(Now.AddMinutes(2));

        Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
        Assert.Null(challenge.CompletedAt);
        Assert.True(challenge.IsActive(Now.AddMinutes(2)));
        Assert.Throws<InvalidOperationException>(
            () => challenge.ReleaseConfirmation(Now.AddMinutes(3)));
    }

    [Fact]
    public void RecordFailure_ExhaustsChallengeAtConfiguredAttemptLimit()
    {
        var challenge = CreateActiveChallenge(maxAttempts: 3);

        Assert.False(challenge.RecordFailure(Now.AddMinutes(1)));
        Assert.False(challenge.RecordFailure(Now.AddMinutes(2)));
        Assert.True(challenge.RecordFailure(Now.AddMinutes(3)));

        Assert.Equal(3, challenge.Attempts);
        Assert.Equal(PhonePasswordResetChallengeStatus.Exhausted, challenge.Status);
        Assert.Equal(Now.AddMinutes(3), challenge.CompletedAt);
        Assert.Throws<InvalidOperationException>(
            () => challenge.RecordFailure(Now.AddMinutes(4)));
    }

    [Fact]
    public void ActiveOperations_RejectExpiredOrNonActiveChallenge()
    {
        var expired = CreateActiveChallenge();
        var pending = CreateChallenge();

        Assert.Throws<InvalidOperationException>(
            () => expired.BeginConfirmation(Now.AddMinutes(10)));
        Assert.Throws<InvalidOperationException>(
            () => expired.RecordFailure(Now.AddMinutes(10)));
        Assert.Throws<InvalidOperationException>(
            () => pending.BeginConfirmation(Now.AddMinutes(1)));
        Assert.Throws<InvalidOperationException>(
            () => pending.RecordFailure(Now.AddMinutes(1)));
        Assert.Throws<InvalidOperationException>(
            () => pending.MarkProviderApproved(Now.AddMinutes(1)));
    }

    [Fact]
    public void FailDelivery_CompletesPendingChallengeAndRejectsInvalidTimestamp()
    {
        var challenge = CreateChallenge();

        Assert.Throws<ArgumentException>(() => challenge.FailDelivery(Now.AddTicks(-1)));

        challenge.FailDelivery(Now.AddMinutes(1));

        Assert.Equal(PhonePasswordResetChallengeStatus.DeliveryFailed, challenge.Status);
        Assert.Equal(Now.AddMinutes(1), challenge.CompletedAt);
        Assert.Throws<InvalidOperationException>(
            () => challenge.FailDelivery(Now.AddMinutes(2)));
        Assert.Throws<InvalidOperationException>(() => challenge.Activate(null));
    }

    [Fact]
    public void ProviderBackedChallenge_CanBeSupersededAndRestored()
    {
        var challenge = CreateActiveChallenge();

        challenge.Supersede(Now.AddMinutes(1));

        Assert.Equal(PhonePasswordResetChallengeStatus.Superseded, challenge.Status);
        Assert.Equal(Now.AddMinutes(1), challenge.CompletedAt);

        challenge.RestoreActive();

        Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
        Assert.Equal("provider-reference", challenge.ProviderReference);
        Assert.Null(challenge.CompletedAt);
    }

    [Fact]
    public void SupersededChallenge_WithoutProviderReferenceCannotBeRestored()
    {
        var challenge = CreateChallenge();
        challenge.Supersede(Now.AddMinutes(1));

        Assert.Throws<InvalidOperationException>(challenge.RestoreActive);
        Assert.Equal(PhonePasswordResetChallengeStatus.Superseded, challenge.Status);
    }

    [Fact]
    public void ConfirmingChallenge_CanOnlyBeSupersededAfterExpiration()
    {
        var challenge = CreateActiveChallenge();
        challenge.BeginConfirmation(Now.AddMinutes(1));

        Assert.Throws<InvalidOperationException>(
            () => challenge.Supersede(Now.AddMinutes(9)));

        challenge.Supersede(Now.AddMinutes(10));

        Assert.Equal(PhonePasswordResetChallengeStatus.Superseded, challenge.Status);
        Assert.Equal(Now.AddMinutes(10), challenge.CompletedAt);
        Assert.Throws<InvalidOperationException>(
            () => challenge.Supersede(Now.AddMinutes(11)));
    }

    [Fact]
    public void ProviderApproval_RejectsInvalidStateAndTimestamp()
    {
        var challenge = CreateActiveChallenge();

        Assert.Throws<InvalidOperationException>(
            () => challenge.MarkProviderApproved(Now.AddMinutes(1)));

        challenge.BeginConfirmation(Now.AddMinutes(1));

        Assert.Throws<ArgumentException>(
            () => challenge.MarkProviderApproved(Now.AddTicks(-1)));
        Assert.Throws<ArgumentException>(
            () => challenge.MarkProviderApproved(
                Now.ToOffset(TimeSpan.FromHours(-3))));
        Assert.Null(challenge.ProviderApprovedAt);
    }

    private static PhonePasswordResetChallenge CreateActiveChallenge(
        int maxAttempts = 5)
    {
        var challenge = CreateChallenge(maxAttempts: maxAttempts);
        challenge.Activate("provider-reference");
        return challenge;
    }

    private static PhonePasswordResetChallenge CreateChallenge(
        Guid? id = null,
        Guid? identityId = null,
        Guid? appEnvironmentId = null,
        string phone = "+5511999999999",
        byte[]? hash = null,
        int maxAttempts = 5,
        DateTimeOffset? createdAt = null,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? resendAvailableAt = null) =>
        new(
            id ?? Guid.NewGuid(),
            identityId ?? Guid.NewGuid(),
            appEnvironmentId ?? Guid.NewGuid(),
            phone,
            hash ?? new byte[IdentityLimits.PhonePasswordResetCodeHashLength],
            maxAttempts,
            createdAt ?? Now,
            expiresAt ?? Now.AddMinutes(10),
            resendAvailableAt ?? Now.AddMinutes(2));
}
