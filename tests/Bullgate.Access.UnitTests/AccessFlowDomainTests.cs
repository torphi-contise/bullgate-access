using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;

namespace Bullgate.Access.UnitTests;

public sealed class AccessFlowDomainTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 1, 19, 0, 0, TimeSpan.Zero);

    [Fact]
    public void NewFlow_StartsAtRevisionOneAndCanCompleteOnce()
    {
        var flow = CreateFlow();

        Assert.Equal(AccessFlowStatus.Active, flow.Status);
        Assert.Equal(1, flow.CurrentRevision);

        var terminalRevision = flow.Complete(1, Now.AddMinutes(2));

        Assert.Equal(2, terminalRevision);
        Assert.Equal(AccessFlowStatus.Completed, flow.Status);
        Assert.Equal(Now.AddMinutes(2), flow.CompletedAt);
        Assert.Throws<InvalidOperationException>(
            () => flow.Complete(2, Now.AddMinutes(3)));
    }

    [Fact]
    public void Flow_RejectsAStaleRevision()
    {
        var flow = CreateFlow();

        Assert.Throws<InvalidOperationException>(
            () => flow.Cancel(2, Now.AddMinutes(1)));
    }

    [Fact]
    public void Intent_ControlsWhetherARegistrationContextIsAllowed()
    {
        var managed = new AccessFlow(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            null,
            Guid.NewGuid(),
            1,
            AccessFlowIntent.ManagePhone,
            Now,
            Now.AddMinutes(30));

        Assert.Null(managed.RegistrationContextId);
        Assert.Throws<ArgumentException>(() => new AccessFlow(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            null,
            Guid.NewGuid(),
            1,
            AccessFlowIntent.ContinueRegistration,
            Now,
            Now.AddMinutes(30)));
        Assert.Throws<ArgumentException>(() => new AccessFlow(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            1,
            AccessFlowIntent.ManagePhone,
            Now,
            Now.AddMinutes(30)));
    }

    [Fact]
    public void Revision_RequiresAJsonObjectSnapshot()
    {
        Assert.Throws<ArgumentException>(
            () => new AccessFlowRevision(Guid.NewGuid(), 1, "[]", Now));
        Assert.Throws<ArgumentException>(
            () => new AccessFlowRevision(Guid.NewGuid(), 1, "not-json", Now));

        var revision = new AccessFlowRevision(
            Guid.NewGuid(),
            1,
            "{\"status\":\"active\"}",
            Now);

        Assert.Equal(1, revision.Revision);
    }

    [Fact]
    public void Request_CopiesThePayloadHash()
    {
        var payloadHash = Enumerable.Repeat((byte)7, AccessFlowLimits.PayloadHashLength)
            .ToArray();
        var request = new AccessFlowRequest(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            AccessFlowRequestKind.Start,
            payloadHash,
            1,
            Now);

        payloadHash[0] = 9;

        Assert.Equal(7, request.PayloadHash[0]);
    }

    [Fact]
    public void ExternalRequest_ReservesThenCommitsOrFailsExactlyOnce()
    {
        var request = AccessFlowRequest.ReserveExternal(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Enumerable.Repeat((byte)3, AccessFlowLimits.PayloadHashLength).ToArray(),
            Now);

        Assert.Equal(AccessFlowRequestStatus.PendingExternal, request.Status);
        Assert.Null(request.ResultRevision);

        request.Commit(2);

        Assert.Equal(AccessFlowRequestStatus.Committed, request.Status);
        Assert.Equal(2, request.ResultRevision);
        request.FailExternal();
        Assert.Equal(AccessFlowRequestStatus.Committed, request.Status);

        var failed = AccessFlowRequest.ReserveExternal(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Enumerable.Repeat((byte)5, AccessFlowLimits.PayloadHashLength).ToArray(),
            Now);
        failed.FailExternal();

        Assert.Equal(AccessFlowRequestStatus.ExternalFailed, failed.Status);
        Assert.Throws<InvalidOperationException>(() => failed.Commit(2));
    }

    [Fact]
    public void PhoneChallenge_UsesDeliveryAndConfirmationReservations()
    {
        var challenge = ProofChallenge.ReserveDelivery(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            ProofChallengeType.PhonePossession,
            ProofChallengeChannel.Sms,
            IdentifierScheme.Phone,
            "+5511999990001",
            Enumerable.Repeat((byte)7, IdentityLimits.SessionTokenHashLength).ToArray(),
            5,
            Now,
            Now.AddMinutes(10),
            Now.AddMinutes(1));

        Assert.Equal(ProofChallengeStatus.PendingDelivery, challenge.Status);
        challenge.Activate("VE0001");
        challenge.BeginConfirmation(Now.AddMinutes(2));
        Assert.Equal(ProofChallengeStatus.Confirming, challenge.Status);

        challenge.ReleaseConfirmation(Now.AddMinutes(3));
        Assert.Equal(ProofChallengeStatus.Active, challenge.Status);
        challenge.BeginConfirmation(Now.AddMinutes(4));
        challenge.Confirm(Now.AddMinutes(5));

        Assert.Equal(ProofChallengeStatus.Verified, challenge.Status);
        Assert.Equal(Now.AddMinutes(5), challenge.CompletedAt);
    }

    private static AccessFlow CreateFlow() =>
        new(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            1,
            AccessFlowIntent.ContinueRegistration,
            Now,
            Now.AddMinutes(30));
}
