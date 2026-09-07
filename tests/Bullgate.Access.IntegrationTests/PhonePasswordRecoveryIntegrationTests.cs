using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bullgate.Access.Application.Bootstrap;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Bullgate.Access.IntegrationTests;

public sealed class PhonePasswordRecoveryIntegrationTests(PostgreSqlFixture database)
    : IClassFixture<PostgreSqlFixture>, IAsyncLifetime
{
    private const string Phone = "+5511987654321";
    private const string SmsRetrieverAppHash = "92TvTC0UfaA";
    private const string ApplicationClientKey = "android-debug";
    private readonly AdjustableTimeProvider clock = new(
        new DateTimeOffset(2026, 9, 2, 18, 0, 0, TimeSpan.Zero));
    private AccessApiFactory api = null!;
    private HttpClient client = null!;
    private HttpClient secondaryClient = null!;
    private Guid appEnvironmentId;
    private Guid secondaryAppEnvironmentId;
    private Guid realmId;
    private Guid otherRealmId;

    public async Task InitializeAsync()
    {
        api = new AccessApiFactory(database.ConnectionString, clock);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await dbContext.Database.EnsureCreatedAsync();
        }

        var suffix = Guid.NewGuid().ToString("N");
        BootstrapTopologyResult bootstrap;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider
                .GetRequiredService<BootstrapTopologyHandler>();
            bootstrap = await handler.HandleAsync(CreateBootstrapCommand(suffix));
        }

        var appPath = $"phone-recovery-{suffix}/baybo-{suffix}";
        appEnvironmentId = FindResource(
            bootstrap,
            "environment",
            $"{appPath}/tests");
        secondaryAppEnvironmentId = FindResource(
            bootstrap,
            "environment",
            $"{appPath}/secondary");
        realmId = FindResource(
            bootstrap,
            "realm",
            $"{appPath}/realms/realm-{suffix}");
        otherRealmId = FindResource(
            bootstrap,
            "realm",
            $"{appPath}/realms/other-realm-{suffix}");
        client = CreateClient(bootstrap.IssuedCredentials.Single(
            credential => credential.IntegrationClientPath
                == $"{appPath}/tests/integration-clients/api").Token);
        secondaryClient = CreateClient(bootstrap.IssuedCredentials.Single(
            credential => credential.IntegrationClientPath
                == $"{appPath}/secondary/integration-clients/api").Token);
    }

    public async Task DisposeAsync()
    {
        secondaryClient.Dispose();
        client.Dispose();
        await api.DisposeAsync();
    }

    [Fact]
    public async Task Request_VerifiedPhone_SendsSixDigitPasswordResetCode_WithAppHash_AndStoresOnlyItsHash()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);

        using var response = await RequestAsync(Phone);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()))
        {
            Assert.Equal(
                clock.GetUtcNow().AddMinutes(10),
                body.RootElement.GetProperty("expiresAt").GetDateTimeOffset());
            Assert.Equal(
                clock.GetUtcNow().AddSeconds(120),
                body.RootElement.GetProperty("resendAvailableAt").GetDateTimeOffset());
        }

        var delivery = Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Equal(Phone, delivery.Phone);
        Assert.Equal(6, delivery.Code.Length);
        Assert.All(delivery.Code, character => Assert.True(char.IsAsciiDigit(character)));
        Assert.Equal(SmsRetrieverAppHash, delivery.SmsRetrieverAppHash);
        Assert.Equal(PhoneVerificationPurpose.PasswordReset, delivery.Purpose);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenge = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
        Assert.Equal(
            SHA256.HashData(Encoding.ASCII.GetBytes(delivery.Code)),
            challenge.CodeHash);
        Assert.Equal(IdentityLimits.PhonePasswordResetCodeHashLength, challenge.CodeHash.Length);
        Assert.NotNull(challenge.ProviderReference);
        Assert.False(await dbContext.PasswordResetTokens
            .AnyAsync(token => token.IdentityId == identityId));
    }

    [Fact]
    public async Task Request_UnknownUnverifiedInactiveAndOtherRealmPhones_IsNeutralWithoutDelivery()
    {
        const string unknownPhone = "+5511900000001";
        const string unverifiedPhone = "+5511900000002";
        const string inactivePhone = "+5511900000003";
        const string otherRealmPhone = "+5511900000004";
        _ = await RegisterWithPhoneAsync(unverifiedPhone, verified: false);
        _ = await RegisterWithPhoneAsync(inactivePhone, active: false);
        await AddIdentityAsync(otherRealmId, otherRealmPhone, verified: true);

        foreach (var phone in new[]
                 {
                     unknownPhone,
                     unverifiedPhone,
                     inactivePhone,
                     otherRealmPhone,
                 })
        {
            using var response = await RequestAsync(phone);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(
                clock.GetUtcNow().AddMinutes(10),
                body.RootElement.GetProperty("expiresAt").GetDateTimeOffset());
            Assert.Equal(
                clock.GetUtcNow().AddSeconds(120),
                body.RootElement.GetProperty("resendAvailableAt").GetDateTimeOffset());
        }

        Assert.Empty(api.PhoneSender.DeliveryAttempts);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.PhonePasswordResetChallenges.AnyAsync(
            challenge => challenge.AppEnvironmentId == appEnvironmentId));
    }

    [Fact]
    public async Task Request_EnforcesCooldown_ThenSupersedesAndCancelsThePreviousCode()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);

        using (var first = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }
        var firstDelivery = Assert.Single(api.PhoneSender.DeliveryAttempts);

        using (var duringCooldown = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, duringCooldown.StatusCode);
        }
        Assert.Single(api.PhoneSender.DeliveryAttempts);

        clock.Advance(TimeSpan.FromSeconds(121));
        using (var resend = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, resend.StatusCode);
        }

        var deliveries = api.PhoneSender.DeliveryAttempts.ToArray();
        Assert.Equal(2, deliveries.Length);
        Assert.Single(api.PhoneSender.CancellationAttempts);

        var supersededCode = firstDelivery.Code == deliveries[1].Code
            ? DifferentCode(deliveries[1].Code)
            : firstDelivery.Code;
        using (var oldCode = await ConfirmAsync(Phone, supersededCode))
        {
            await AssertErrorAsync(
                oldCode,
                HttpStatusCode.BadRequest,
                "invalid-code",
                "code");
        }
        using (var currentCode = await ConfirmAsync(Phone, deliveries[1].Code))
        {
            Assert.Equal(HttpStatusCode.OK, currentCode.StatusCode);
        }

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenges = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .Where(challenge => challenge.IdentityId == identityId)
            .OrderBy(challenge => challenge.CreatedAt)
            .ToArrayAsync();
        Assert.Equal(2, challenges.Length);
        Assert.Equal(PhonePasswordResetChallengeStatus.Superseded, challenges[0].Status);
        Assert.Equal(PhonePasswordResetChallengeStatus.Completed, challenges[1].Status);
        Assert.Equal(1, challenges[1].Attempts);
    }

    [Fact]
    public async Task Request_AllowsFiveWithinTheHour_AndSixthIsNeutralWithoutSending()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);

        for (var index = 0; index < 6; index++)
        {
            using var response = await RequestAsync(Phone);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            if (index < 5)
            {
                clock.Advance(TimeSpan.FromSeconds(121));
            }
        }

        Assert.Equal(5, api.PhoneSender.DeliveryAttempts.Count);
        Assert.Equal(4, api.PhoneSender.CancellationAttempts.Count);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(
            5,
            await dbContext.PhonePasswordResetChallenges.CountAsync(
                challenge => challenge.IdentityId == identityId));
        Assert.Equal(
            1,
            await dbContext.PhonePasswordResetChallenges.CountAsync(
                challenge => challenge.IdentityId == identityId
                    && challenge.Status == PhonePasswordResetChallengeStatus.Active));
    }

    [Fact]
    public async Task Endpoints_ValidatePhoneCodeAndApplicationClient_AndRejectExpiredCode()
    {
        using (var missingPhone = await RequestAsync(null))
        {
            await AssertErrorAsync(
                missingPhone,
                HttpStatusCode.BadRequest,
                "missing-fields",
                "phone");
        }
        using (var invalidPhone = await RequestAsync("5511987654321"))
        {
            await AssertErrorAsync(
                invalidPhone,
                HttpStatusCode.BadRequest,
                "invalid-phone",
                "phone");
        }
        using (var invalidApplicationClient = await RequestAsync(Phone, "unknown-client"))
        {
            await AssertErrorAsync(
                invalidApplicationClient,
                HttpStatusCode.BadRequest,
                "application-client-invalid",
                "applicationClientKey");
        }
        using (var missingCode = await ConfirmAsync(Phone, null))
        {
            await AssertErrorAsync(
                missingCode,
                HttpStatusCode.BadRequest,
                "missing-fields",
                "code");
        }
        using (var malformedCode = await ConfirmAsync(Phone, "12a456"))
        {
            await AssertErrorAsync(
                malformedCode,
                HttpStatusCode.BadRequest,
                "invalid-code",
                "code");
        }

        _ = await RegisterWithPhoneAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        clock.Advance(TimeSpan.FromMinutes(10));

        using var expired = await ConfirmAsync(Phone, code);
        await AssertErrorAsync(
            expired,
            HttpStatusCode.BadRequest,
            "invalid-code",
            "code");
        Assert.Empty(api.PhoneSender.ApprovalAttempts);
    }

    [Fact]
    public async Task Confirm_FifthWrongCodeExhaustsAndCancelsTheChallenge()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var correctCode = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        var wrongCode = DifferentCode(correctCode);

        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var rejected = await ConfirmAsync(Phone, wrongCode);
            await AssertErrorAsync(
                rejected,
                HttpStatusCode.BadRequest,
                "invalid-code",
                "code");
        }

        using (var exhausted = await ConfirmAsync(Phone, correctCode))
        {
            await AssertErrorAsync(
                exhausted,
                HttpStatusCode.BadRequest,
                "invalid-code",
                "code");
        }
        Assert.Single(api.PhoneSender.CancellationAttempts);
        Assert.Empty(api.PhoneSender.ApprovalAttempts);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenge = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(5, challenge.Attempts);
        Assert.Equal(PhonePasswordResetChallengeStatus.Exhausted, challenge.Status);
        Assert.NotNull(challenge.CompletedAt);
        Assert.False(await dbContext.PasswordResetTokens
            .AnyAsync(token => token.IdentityId == identityId));
    }

    [Fact]
    public async Task Confirm_ProviderApprovalFailureLeavesTheSameCodeRetryable()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        api.PhoneSender.RejectApproval = true;

        using (var unavailable = await ConfirmAsync(Phone, code))
        {
            await AssertErrorAsync(
                unavailable,
                HttpStatusCode.ServiceUnavailable,
                "verification-delivery-unavailable");
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var retryable = await dbContext.PhonePasswordResetChallenges
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.Equal(PhonePasswordResetChallengeStatus.Active, retryable.Status);
            Assert.Null(retryable.ProviderApprovedAt);
            Assert.False(await dbContext.PasswordResetTokens
                .AnyAsync(token => token.IdentityId == identityId));
        }

        api.PhoneSender.RejectApproval = false;
        using (var retried = await ConfirmAsync(Phone, code))
        {
            Assert.Equal(HttpStatusCode.OK, retried.StatusCode);
        }

        Assert.Equal(2, api.PhoneSender.ApprovalAttempts.Count);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var completed = await dbContext.PhonePasswordResetChallenges
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.Equal(PhonePasswordResetChallengeStatus.Completed, completed.Status);
            Assert.NotNull(completed.ProviderApprovedAt);
            Assert.Single(await dbContext.PasswordResetTokens
                .Where(token => token.IdentityId == identityId)
                .ToArrayAsync());
        }
    }

    [Fact]
    public async Task Confirm_IssuesCommonResetToken_ThatResetsPasswordThroughTheSharedEndpoint()
    {
        var registration = await RegisterWithPhoneAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;

        string token;
        using (var confirmed = await ConfirmAsync(Phone, code))
        {
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
            using var body = JsonDocument.Parse(await confirmed.Content.ReadAsStringAsync());
            token = body.RootElement.GetProperty("token").GetString()!;
            Assert.Equal(43, token.Length);
            Assert.Equal(
                clock.GetUtcNow().AddMinutes(60),
                body.RootElement.GetProperty("expiresAt").GetDateTimeOffset());
        }

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var challenge = await dbContext.PhonePasswordResetChallenges
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == registration.IdentityId);
            Assert.Equal(PhonePasswordResetChallengeStatus.Completed, challenge.Status);
            Assert.NotNull(challenge.ProviderApprovedAt);
            var resetToken = await dbContext.PasswordResetTokens
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == registration.IdentityId);
            Assert.Equal(appEnvironmentId, resetToken.AppEnvironmentId);
            Assert.True(resetToken.IsActive(clock.GetUtcNow()));
        }

        using (var reset = await client.PostAsJsonAsync(
                   "/v1/auth/password/recovery/reset",
                   new { token, newPassword = "replacement-password" }))
        {
            Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
        }
        using (var oldLogin = await client.PostAsJsonAsync(
                   "/v1/auth/login",
                   new { email = registration.Email, password = "original-password" }))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, oldLogin.StatusCode);
        }
        using (var newLogin = await client.PostAsJsonAsync(
                   "/v1/auth/login",
                   new { email = registration.Email, password = "replacement-password" }))
        {
            Assert.Equal(HttpStatusCode.OK, newLogin.StatusCode);
        }
    }

    [Fact]
    public async Task Request_DeliveryFailureReturnsUnavailableAndMarksTheReservationFailed()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        api.PhoneSender.RejectDelivery = true;

        using var failed = await RequestAsync(Phone);
        await AssertErrorAsync(
            failed,
            HttpStatusCode.ServiceUnavailable,
            "verification-delivery-unavailable");
        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Empty(api.PhoneSender.CancellationAttempts);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenge = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(PhonePasswordResetChallengeStatus.DeliveryFailed, challenge.Status);
        Assert.NotNull(challenge.CompletedAt);
        Assert.False(await dbContext.PasswordResetTokens
            .AnyAsync(token => token.IdentityId == identityId));
    }

    [Fact]
    public async Task Request_CancellationFailureRestoresThePreviousCodeAndDoesNotSendANewOne()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var oldCode = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        clock.Advance(TimeSpan.FromSeconds(121));
        api.PhoneSender.RejectCancellation = true;

        using (var failedResend = await RequestAsync(Phone))
        {
            await AssertErrorAsync(
                failedResend,
                HttpStatusCode.ServiceUnavailable,
                "verification-delivery-unavailable");
        }

        Assert.Single(api.PhoneSender.DeliveryAttempts);
        Assert.Single(api.PhoneSender.CancellationAttempts);
        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var challenges = await dbContext.PhonePasswordResetChallenges
                .AsNoTracking()
                .Where(challenge => challenge.IdentityId == identityId)
                .OrderBy(challenge => challenge.CreatedAt)
                .ToArrayAsync();
            var restored = Assert.Single(challenges);
            Assert.Equal(PhonePasswordResetChallengeStatus.Active, restored.Status);
        }

        api.PhoneSender.RejectCancellation = false;
        using var confirmed = await ConfirmAsync(Phone, oldCode);
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
    }

    [Fact]
    public async Task Request_ConcurrentCallsSendExactlyOneSms()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);

        var responses = await Task.WhenAll(
            RequestAsync(Phone),
            RequestAsync(Phone));
        try
        {
            Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        Assert.Single(api.PhoneSender.DeliveryAttempts);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenge = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
    }

    [Fact]
    public async Task Confirm_ConcurrentCallsProduceExactlyOneResetToken()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;

        var responses = await Task.WhenAll(
            ConfirmAsync(Phone, code),
            ConfirmAsync(Phone, code));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
            Assert.Single(
                responses,
                response => response.StatusCode == HttpStatusCode.BadRequest);
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        Assert.Single(api.PhoneSender.ApprovalAttempts);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Single(await dbContext.PasswordResetTokens
            .Where(token => token.IdentityId == identityId)
            .ToArrayAsync());
        var challenge = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(PhonePasswordResetChallengeStatus.Completed, challenge.Status);
    }

    [Fact]
    public async Task Confirm_CodeAndTokenAreScopedToTheIssuingAppEnvironment()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;

        using (var wrongEnvironment = await ConfirmAsync(
                   Phone,
                   code,
                   secondaryClient))
        {
            await AssertErrorAsync(
                wrongEnvironment,
                HttpStatusCode.BadRequest,
                "invalid-code",
                "code");
        }
        using (var issuingEnvironment = await ConfirmAsync(Phone, code))
        {
            Assert.Equal(HttpStatusCode.OK, issuingEnvironment.StatusCode);
        }

        Assert.Single(api.PhoneSender.ApprovalAttempts);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var resetToken = await dbContext.PasswordResetTokens
            .AsNoTracking()
            .SingleAsync(token => token.IdentityId == identityId);
        Assert.Equal(appEnvironmentId, resetToken.AppEnvironmentId);
        Assert.NotEqual(secondaryAppEnvironmentId, resetToken.AppEnvironmentId);
    }

    [Fact]
    public async Task Confirm_PausedInProviderApproval_CannotIssueTokenAfterExpiredChallengeLosesToResend()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var originalCode = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        var approvalGate = new AsyncOperationGate();
        api.PhoneSender.ApprovalGate = approvalGate;
        var confirmation = ConfirmAsync(Phone, originalCode);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await approvalGate.WaitUntilEnteredAsync(timeout.Token);
        clock.Advance(TimeSpan.FromMinutes(10).Add(TimeSpan.FromSeconds(1)));

        HttpResponseMessage? resend = null;
        try
        {
            resend = await RequestAsync(
                Phone,
                cancellationToken: timeout.Token);
            Assert.Equal(HttpStatusCode.OK, resend.StatusCode);
            Assert.Equal(2, api.PhoneSender.DeliveryAttempts.Count);
        }
        finally
        {
            resend?.Dispose();
            approvalGate.Release();
        }

        using (var staleConfirmation = await confirmation)
        {
            await AssertErrorAsync(
                staleConfirmation,
                HttpStatusCode.BadRequest,
                "invalid-code",
                "code");
        }

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await dbContext.PasswordResetTokens
            .AnyAsync(token => token.IdentityId == identityId));
        var challenges = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .Where(challenge => challenge.IdentityId == identityId)
            .OrderBy(challenge => challenge.CreatedAt)
            .ToArrayAsync();
        Assert.Equal(2, challenges.Length);
        Assert.Equal(PhonePasswordResetChallengeStatus.Superseded, challenges[0].Status);
        Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenges[1].Status);
    }

    [Fact]
    public async Task Request_CanceledInsideProviderSend_ClosesPendingDeliveryChallenge()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        var sendGate = new AsyncOperationGate();
        api.PhoneSender.SendGate = sendGate;
        using var cancellation = new CancellationTokenSource();
        var request = RequestAsync(
            Phone,
            cancellationToken: cancellation.Token);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await sendGate.WaitUntilEnteredAsync(timeout.Token);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => _ = await request);

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var challenge = await dbContext.PhonePasswordResetChallenges
            .AsNoTracking()
            .SingleAsync(item => item.IdentityId == identityId);
        Assert.Equal(
            PhonePasswordResetChallengeStatus.DeliveryFailed,
            challenge.Status);
        Assert.NotNull(challenge.CompletedAt);
        Assert.NotEqual(
            PhonePasswordResetChallengeStatus.PendingDelivery,
            challenge.Status);
        Assert.False(await dbContext.PasswordResetTokens
            .AnyAsync(token => token.IdentityId == identityId));
    }

    [Fact]
    public async Task Confirm_CanceledInsideProviderApproval_ReleasesChallengeForRetry()
    {
        var identityId = await RegisterPhoneOwnerAsync(Phone);
        using (var requested = await RequestAsync(Phone))
        {
            Assert.Equal(HttpStatusCode.OK, requested.StatusCode);
        }
        var code = Assert.Single(api.PhoneSender.DeliveryAttempts).Code;
        var approvalGate = new AsyncOperationGate();
        api.PhoneSender.ApprovalGate = approvalGate;
        using var cancellation = new CancellationTokenSource();
        var confirmation = ConfirmAsync(
            Phone,
            code,
            cancellationToken: cancellation.Token);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await approvalGate.WaitUntilEnteredAsync(timeout.Token);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => _ = await confirmation);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var challenge = await dbContext.PhonePasswordResetChallenges
                .AsNoTracking()
                .SingleAsync(item => item.IdentityId == identityId);
            Assert.Equal(PhonePasswordResetChallengeStatus.Active, challenge.Status);
            Assert.NotEqual(
                PhonePasswordResetChallengeStatus.Confirming,
                challenge.Status);
            Assert.False(await dbContext.PasswordResetTokens
                .AnyAsync(token => token.IdentityId == identityId));
        }

        api.PhoneSender.ApprovalGate = null;
        using var retry = await ConfirmAsync(Phone, code);
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
    }

    private HttpClient CreateClient(string credential)
    {
        var httpClient = api.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", credential);
        return httpClient;
    }

    private Task<HttpResponseMessage> RequestAsync(
        string? phone,
        string applicationClientKey = ApplicationClientKey,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default) =>
        (httpClient ?? client).PostAsJsonAsync(
            "/v1/auth/password/recovery/phone",
            new { phone, applicationClientKey },
            cancellationToken);

    private Task<HttpResponseMessage> ConfirmAsync(
        string? phone,
        string? code,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default) =>
        (httpClient ?? client).PostAsJsonAsync(
            "/v1/auth/password/recovery/phone/confirm",
            new { phone, code },
            cancellationToken);

    private async Task<RegisteredIdentity> RegisterWithPhoneAsync(
        string phone,
        bool verified = true,
        bool active = true)
    {
        var email = $"phone-recovery-{Guid.NewGuid():N}@example.com";
        using var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new { email, password = "original-password" });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var body = JsonDocument.Parse(await registration.Content.ReadAsStringAsync());
        var identityId = body.RootElement.GetProperty("identityId").GetGuid();

        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
            Guid.CreateVersion7(clock.GetUtcNow()),
            identityId,
            realmId,
            IdentifierScheme.Phone,
            phone,
            clock.GetUtcNow(),
            verified ? clock.GetUtcNow() : null,
            verified ? "sms" : null));
        if (!active)
        {
            var identity = await dbContext.Identities.SingleAsync(
                item => item.Id == identityId);
            identity.Abandon();
        }
        await dbContext.SaveChangesAsync();
        return new RegisteredIdentity(identityId, email);
    }

    private async Task<Guid> RegisterPhoneOwnerAsync(
        string phone,
        bool verified = true,
        bool active = true) =>
        (await RegisterWithPhoneAsync(phone, verified, active)).IdentityId;

    private async Task AddIdentityAsync(
        Guid identityRealmId,
        string phone,
        bool verified)
    {
        var now = clock.GetUtcNow();
        var identityId = Guid.CreateVersion7(now);
        await using var scope = api.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        dbContext.Identities.Add(new Identity(identityId, identityRealmId, now));
        dbContext.IdentityIdentifiers.Add(new IdentityIdentifier(
            Guid.CreateVersion7(now),
            identityId,
            identityRealmId,
            IdentifierScheme.Phone,
            phone,
            now,
            verified ? now : null,
            verified ? "sms" : null));
        await dbContext.SaveChangesAsync();
    }

    private static async Task AssertErrorAsync(
        HttpResponseMessage response,
        HttpStatusCode status,
        string error,
        string? field = null)
    {
        Assert.Equal(status, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(error, body.RootElement.GetProperty("error").GetString());
        if (field is not null)
        {
            Assert.Equal(field, body.RootElement.GetProperty("field").GetString());
        }
    }

    private static Guid FindResource(
        BootstrapTopologyResult bootstrap,
        string type,
        string path) =>
        bootstrap.Resources.Single(resource => resource.Type == type && resource.Path == path).Id;

    private static string DifferentCode(string code) =>
        code == "000000" ? "999999" : "000000";

    private static BootstrapTopologyCommand CreateBootstrapCommand(string suffix)
    {
        var accessPolicy = TestAccessPolicies.Create();
        return new BootstrapTopologyCommand(
            $"phone-recovery-{suffix}",
            "Phone recovery tests",
            [
                new BootstrapAppDefinition(
                    $"baybo-{suffix}",
                    "BAYBO",
                    [
                        new BootstrapRealmDefinition(
                            $"realm-{suffix}",
                            "BAYBO tests"),
                        new BootstrapRealmDefinition(
                            $"other-realm-{suffix}",
                            "Other realm tests"),
                    ],
                    [
                        new BootstrapEnvironmentDefinition(
                            "tests",
                            "Tests",
                            $"realm-{suffix}",
                            accessPolicy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(accessPolicy),
                            TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "api",
                                    "API",
                                    [AccessPermission.ExecuteFlows]),
                            ],
                            [
                                new BootstrapApplicationClientDefinition(
                                    "android-debug",
                                    "Android debug",
                                    ApplicationClientPlatform.Android,
                                    "app.baybo",
                                    "sha256:fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
                                    SmsRetrieverAppHash,
                                    JsonSerializer.SerializeToElement(new { })),
                            ]),
                        new BootstrapEnvironmentDefinition(
                            "secondary",
                            "Secondary",
                            $"realm-{suffix}",
                            accessPolicy,
                            TestEnvironmentConfigurations.VerificationPolicy,
                            TestEnvironmentConfigurations.RecoveryPolicy(),
                            TestEnvironmentConfigurations.Providers(accessPolicy),
                            TestEnvironmentConfigurations.DevelopmentBypass(accessPolicy),
                            [
                                new BootstrapIntegrationClientDefinition(
                                    "api",
                                    "API",
                                    [AccessPermission.ExecuteFlows]),
                            ],
                            [
                                new BootstrapApplicationClientDefinition(
                                    "android-debug",
                                    "Android debug",
                                    ApplicationClientPlatform.Android,
                                    "app.baybo.secondary",
                                    "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
                                    SmsRetrieverAppHash,
                                    JsonSerializer.SerializeToElement(new { })),
                            ]),
                    ]),
            ]);
    }

    private sealed record RegisteredIdentity(Guid IdentityId, string Email);
}
