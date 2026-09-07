using System.Collections.Concurrent;
using Bullgate.Access.Application.Flows;
using Bullgate.Access.Application.Recovery;
using Bullgate.Access.Application.Social;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Bullgate.Access.IntegrationTests;

public sealed class AccessApiFactory : WebApplicationFactory<Program>
{
    private readonly string? connectionString;
    private readonly TimeProvider? timeProvider;

    internal RecordingPhoneVerificationSender PhoneSender { get; } = new();
    internal TestGoogleIdentityValidator GoogleValidator { get; } = new();
    internal TestAppleIdentityValidator AppleValidator { get; } = new();
    internal RecordingPasswordRecoveryEmailSender PasswordRecoveryEmailSender { get; } = new();

    public AccessApiFactory()
    {
    }

    internal AccessApiFactory(
        string connectionString,
        TimeProvider? timeProvider = null)
    {
        this.connectionString = connectionString;
        this.timeProvider = timeProvider;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting(
            "ConnectionStrings:AccessDatabase",
            connectionString
            ?? "Host=localhost;Port=5432;Database=bullgate_access_tests;Username=test;Password=test");
        builder.UseSetting(
            "Bullgate:MasterKey",
            "QnVsbGdhdGUtZGV2ZWxvcG1lbnQtbWFzdGVyLWtleSE=");
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IPhoneVerificationSender>();
            services.RemoveAll<IGoogleIdentityValidator>();
            services.RemoveAll<IAppleIdentityValidator>();
            services.RemoveAll<IPasswordRecoveryEmailSender>();
            if (timeProvider is not null)
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton(timeProvider);
            }
            services.AddSingleton<IPhoneVerificationSender>(PhoneSender);
            services.AddSingleton<IGoogleIdentityValidator>(GoogleValidator);
            services.AddSingleton<IAppleIdentityValidator>(AppleValidator);
            services.AddSingleton<IPasswordRecoveryEmailSender>(
                PasswordRecoveryEmailSender);
        });
    }
}

internal sealed class RecordingPasswordRecoveryEmailSender
    : IPasswordRecoveryEmailSender
{
    public bool IsAvailable { get; set; } = true;

    public bool DeliverySucceeds { get; set; } = true;

    public AsyncOperationGate? SendGate { get; set; }

    public ConcurrentQueue<PasswordRecoveryEmailDelivery> DeliveryAttempts { get; } = new();

    public Task<bool> IsAvailableAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        Task.FromResult(IsAvailable);

    public async Task<bool> TrySendAsync(
        Guid appEnvironmentId,
        PasswordRecoveryEmailDelivery delivery,
        CancellationToken cancellationToken)
    {
        DeliveryAttempts.Enqueue(delivery);
        if (SendGate is not null)
        {
            await SendGate.WaitAsync(cancellationToken);
        }

        return DeliverySucceeds;
    }
}

internal sealed class TestGoogleIdentityValidator : IGoogleIdentityValidator
{
    public SocialIdentityAssertion? Assertion { get; set; } =
        new("google@example.test", "google-subject", "Google User");

    public Task<SocialIdentityAssertion?> ValidateIdTokenAsync(
        Guid appEnvironmentId,
        string idToken,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(string.Equals(idToken, "invalid", StringComparison.Ordinal)
            ? null
            : Assertion);

    public Task<SocialIdentityAssertion?> ValidateAccessTokenAsync(
        Guid appEnvironmentId,
        string accessToken,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(string.Equals(accessToken, "invalid", StringComparison.Ordinal)
            ? null
            : Assertion);
}

internal sealed class TestAppleIdentityValidator : IAppleIdentityValidator
{
    public SocialIdentityAssertion? Assertion { get; set; } =
        new("apple@example.test", "apple-subject", null);

    public Task<SocialIdentityAssertion?> ValidateAsync(
        Guid appEnvironmentId,
        string identityToken,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(string.Equals(identityToken, "invalid", StringComparison.Ordinal)
            ? null
            : Assertion);
}

internal sealed class RecordingPhoneVerificationSender : IPhoneVerificationSender
{
    private readonly ConcurrentDictionary<string, byte> references = new();
    private int referenceSequence;

    public string? LastCode { get; private set; }

    public bool RejectApproval { get; set; }

    public bool RejectCancellation { get; set; }

    public bool RejectDelivery { get; set; }

    public bool IsAvailable { get; set; } = true;

    public AsyncOperationGate? SendGate { get; set; }

    public AsyncOperationGate? ApprovalGate { get; set; }

    public ConcurrentQueue<PhoneVerificationDelivery> DeliveryAttempts { get; } = new();

    public ConcurrentQueue<string?> ApprovalAttempts { get; } = new();

    public ConcurrentQueue<string?> CancellationAttempts { get; } = new();

    public Task<bool> IsAvailableAsync(
        Guid appEnvironmentId,
        CancellationToken cancellationToken) =>
        Task.FromResult(IsAvailable);

    public async Task<string?> SendAsync(
        Guid appEnvironmentId,
        PhoneVerificationDelivery delivery,
        CancellationToken cancellationToken)
    {
        LastCode = delivery.Code;
        DeliveryAttempts.Enqueue(delivery);
        if (SendGate is not null)
        {
            await SendGate.WaitAsync(cancellationToken);
        }
        if (RejectDelivery)
        {
            throw new InvalidOperationException("Provider rejected delivery in test.");
        }

        var reference = $"VE{Interlocked.Increment(ref referenceSequence):D32}";
        references.TryAdd(reference, 0);
        return reference;
    }

    public async Task ApproveAsync(
        Guid appEnvironmentId,
        string? providerReference,
        CancellationToken cancellationToken)
    {
        ApprovalAttempts.Enqueue(providerReference);
        if (providerReference is null || !references.ContainsKey(providerReference))
        {
            throw new InvalidOperationException(
                "Unexpected verification reference in test.");
        }

        if (ApprovalGate is not null)
        {
            await ApprovalGate.WaitAsync(cancellationToken);
        }
        if (RejectApproval)
        {
            throw new InvalidOperationException("Provider rejected approval in test.");
        }
    }

    public Task CancelAsync(
        Guid appEnvironmentId,
        string? providerReference,
        CancellationToken cancellationToken)
    {
        CancellationAttempts.Enqueue(providerReference);
        if (providerReference is null || !references.ContainsKey(providerReference))
        {
            throw new InvalidOperationException(
                "Unexpected verification reference in test.");
        }

        return RejectCancellation
            ? Task.FromException(
                new InvalidOperationException("Provider rejected cancellation in test."))
            : Task.CompletedTask;
    }
}

internal sealed class AsyncOperationGate
{
    private readonly TaskCompletionSource entered = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource released = new(
        TaskCreationOptions.RunContinuationsAsynchronously);

    public async Task WaitUntilEnteredAsync(CancellationToken cancellationToken = default) =>
        await entered.Task.WaitAsync(cancellationToken);

    public void Release() => released.TrySetResult();

    internal async Task WaitAsync(CancellationToken cancellationToken)
    {
        entered.TrySetResult();
        await released.Task.WaitAsync(cancellationToken);
    }
}

internal sealed class AdjustableTimeProvider(DateTimeOffset initialUtc)
    : TimeProvider
{
    private long utcTicks = RequireUtc(initialUtc).Ticks;

    public override DateTimeOffset GetUtcNow() =>
        new(Interlocked.Read(ref utcTicks), TimeSpan.Zero);

    public void Advance(TimeSpan amount)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(amount, TimeSpan.Zero);

        Interlocked.Add(ref utcTicks, amount.Ticks);
    }

    private static DateTimeOffset RequireUtc(DateTimeOffset value)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Time must use the UTC offset.", nameof(value));
        }

        return value;
    }
}
