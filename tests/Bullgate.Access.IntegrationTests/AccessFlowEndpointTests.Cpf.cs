using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Bullgate.Access.Domain.Flows;
using Bullgate.Access.Domain.Identities;
using Bullgate.Access.Domain.Topology;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Bullgate.Access.IntegrationTests;

public sealed partial class AccessFlowEndpointTests
{
    [Fact]
    public async Task RequiredCpfAndBirthDate_CompleteRegistrationTogether()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true,
            cpfCollectionPosition: CpfCollectionPosition.BeforePhone,
            phoneEnabled: false,
            phoneVerificationEnabled: false));
        var registration = await RegisterAndStartFlowAsync(
            $"cpf-only-{Guid.NewGuid():N}@example.test",
            ProtocolVersions1And2);

        Assert.Equal(
            "collectCpf",
            registration.Flow.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(2, registration.Flow.GetProperty("protocolVersion").GetInt32());
        Assert.Equal(["submitCpf"], ActionTypes(registration.Flow));

        var completed = await ExecuteActionAsync(
            registration,
            registration.Flow,
            "submitCpf",
            new { cpf = "529.982.247-25", birthDate = "1990-05-21" });
        var snapshot = completed.GetProperty("snapshot");

        Assert.Equal("completed", snapshot.GetProperty("status").GetString());
        Assert.Equal(
            "civilDataCollected",
            snapshot.GetProperty("result").GetProperty("outcome").GetString());
        Assert.Equal(
            "product",
            completed.GetProperty("issuedSession").GetProperty("purpose").GetString());

        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var identity = await db.Identities.AsNoTracking().SingleAsync(
            item => item.Id == registration.IdentityId);
        var cpf = await db.IdentityIdentifiers.AsNoTracking().SingleAsync(
            item => item.IdentityId == registration.IdentityId
                && item.Scheme == IdentifierScheme.Cpf);
        var context = await db.RegistrationContexts.AsNoTracking().SingleAsync(
            item => item.IdentityId == registration.IdentityId);

        Assert.Equal(new DateOnly(1990, 5, 21), identity.BirthDate);
        Assert.Equal("52998224725", cpf.NormalizedValue);
        Assert.Null(cpf.VerifiedAt);
        Assert.Equal(RegistrationContextStatus.Completed, context.Status);
    }

    [Fact]
    public async Task RequiredCpfAndBirthDate_RejectAClientWithoutProtocolVersion2()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true,
            cpfCollectionPosition: CpfCollectionPosition.BeforePhone,
            phoneEnabled: false,
            phoneVerificationEnabled: false));
        var registration = await client.PostAsJsonAsync(
            "/v1/auth/register",
            new
            {
                email = $"cpf-v1-{Guid.NewGuid():N}@example.test",
                password = "password-123",
            });
        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var registrationBody = JsonDocument.Parse(
            await registration.Content.ReadAsStringAsync());

        var started = await client.PostAsJsonAsync(
            "/v1/access/flows",
            new
            {
                requestId = Guid.NewGuid(),
                protocolVersions = ProtocolVersion1,
                intent = "continueRegistration",
                applicationClientKey = ApplicationClientKey,
                sessionToken = registrationBody.RootElement
                    .GetProperty("sessionToken")
                    .GetString(),
            });

        Assert.Equal(HttpStatusCode.Conflict, started.StatusCode);
        using var startedBody = JsonDocument.Parse(await started.Content.ReadAsStringAsync());
        Assert.Equal(
            "protocol-version-unsupported",
            startedBody.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task RequiredCpfAndBirthDate_AreStoredBeforeRequiredPhoneCollection()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true,
            cpfCollectionPosition: CpfCollectionPosition.BeforePhone,
            phoneRequired: true,
            phoneVerificationEnabled: false));
        var registration = await RegisterAndStartFlowAsync(
            $"cpf-phone-{Guid.NewGuid():N}@example.test",
            ProtocolVersions1And2);

        var civilData = await ExecuteActionAsync(
            registration,
            registration.Flow,
            "submitCpf",
            new { cpf = "11144477735", birthDate = "1988-10-07" });
        var collectPhone = civilData.GetProperty("snapshot");

        Assert.Equal("active", collectPhone.GetProperty("status").GetString());
        Assert.Equal(
            "collectPhone",
            collectPhone.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(["submitPhone"], ActionTypes(collectPhone));

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var identity = await db.Identities.AsNoTracking().SingleAsync(
                item => item.Id == registration.IdentityId);
            var cpf = await db.IdentityIdentifiers.AsNoTracking().SingleAsync(
                item => item.IdentityId == registration.IdentityId
                    && item.Scheme == IdentifierScheme.Cpf);
            var flow = await db.AccessFlows.AsNoTracking().SingleAsync(
                item => item.Id == registration.FlowId);

            Assert.Equal(new DateOnly(1988, 10, 7), identity.BirthDate);
            Assert.Equal("11144477735", cpf.NormalizedValue);
            Assert.Equal(AccessFlowStatus.Active, flow.Status);
            Assert.Equal(2, flow.CurrentRevision);
        }

        var completed = await ExecuteActionAsync(
            registration,
            collectPhone,
            "submitPhone",
            new { phone = "+5511976695464" });
        Assert.Equal(
            "completed",
            completed.GetProperty("snapshot").GetProperty("status").GetString());
    }

    [Fact]
    public async Task InvalidCpfOrBirthDate_StaysOnCivilDataStepWithoutPersistingEither()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true,
            cpfCollectionPosition: CpfCollectionPosition.BeforePhone,
            phoneEnabled: false,
            phoneVerificationEnabled: false));
        var registration = await RegisterAndStartFlowAsync(
            $"invalid-cpf-{Guid.NewGuid():N}@example.test",
            ProtocolVersions1And2);

        var invalidCpf = await ExecuteActionAsync(
            registration,
            registration.Flow,
            "submitCpf",
            new { cpf = "52998224724", birthDate = "1990-05-21" });
        var afterInvalidCpf = invalidCpf.GetProperty("snapshot");
        AssertCivilDataFeedback(afterInvalidCpf, "invalid-cpf", "cpf");

        var invalidBirthDate = await ExecuteActionAsync(
            registration,
            afterInvalidCpf,
            "submitCpf",
            new { cpf = "52998224725", birthDate = "2990-05-21" });
        AssertCivilDataFeedback(
            invalidBirthDate.GetProperty("snapshot"),
            "invalid-birth-date",
            "birthDate");

        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var identity = await db.Identities.AsNoTracking().SingleAsync(
            item => item.Id == registration.IdentityId);
        Assert.Null(identity.BirthDate);
        Assert.False(await db.IdentityIdentifiers.AsNoTracking().AnyAsync(
            item => item.IdentityId == registration.IdentityId
                && item.Scheme == IdentifierScheme.Cpf));
    }

    [Fact]
    public async Task CpfAlreadyOwnedInTheRealm_IsRejectedForAnotherIdentity()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true,
            cpfCollectionPosition: CpfCollectionPosition.BeforePhone,
            phoneEnabled: false,
            phoneVerificationEnabled: false));
        var previous = await RegisterAndStartFlowAsync(
            $"cpf-owner-{Guid.NewGuid():N}@example.test",
            ProtocolVersions1And2);
        var previousCompleted = await ExecuteActionAsync(
            previous,
            previous.Flow,
            "submitCpf",
            new { cpf = "52998224725", birthDate = "1990-05-21" });
        Assert.Equal(
            "completed",
            previousCompleted.GetProperty("snapshot").GetProperty("status").GetString());

        var current = await RegisterAndStartFlowAsync(
            $"cpf-conflict-{Guid.NewGuid():N}@example.test",
            ProtocolVersions1And2);
        var rejected = await ExecuteActionAsync(
            current,
            current.Flow,
            "submitCpf",
            new { cpf = "529.982.247-25", birthDate = "1995-03-09" });
        AssertCivilDataFeedback(
            rejected.GetProperty("snapshot"),
            "cpf-already-in-use",
            "cpf");

        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(
            previous.IdentityId,
            await db.IdentityIdentifiers.AsNoTracking()
                .Where(item => item.Scheme == IdentifierScheme.Cpf
                    && item.NormalizedValue == "52998224725")
                .Select(item => item.IdentityId)
                .SingleAsync());
        Assert.False(await db.IdentityIdentifiers.AsNoTracking().AnyAsync(
            item => item.IdentityId == current.IdentityId
                && item.Scheme == IdentifierScheme.Cpf));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CpfAfterPhone_KeepsRegistrationPendingUntilBothCivilFieldsAreCollected(
        bool verifyPhone)
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true,
            cpfCollectionPosition: CpfCollectionPosition.AfterPhone,
            phoneRequired: true,
            phoneVerificationEnabled: verifyPhone));
        var current = await RegisterAndStartFlowAsync(
            $"cpf-after-{Guid.NewGuid():N}@example.test", ProtocolVersions1And2);
        Assert.Equal("collectPhone", current.Flow.GetProperty("step").GetProperty("type").GetString());
        Assert.DoesNotContain("skipRegistration", ActionTypes(current.Flow));
        Assert.Equal(2, current.Flow.GetProperty("protocolVersion").GetInt32());

        var phoneStep = verifyPhone
            ? await RequestPhoneAsync(current.Flow, current.Capability)
            : current.Flow;
        var phoneAction = verifyPhone ? "confirmPhoneVerification" : "submitPhone";
        object phoneInput = verifyPhone ? new { code = "123456" } : new { phone = "+15555550123" };
        var phoneRequestId = Guid.NewGuid();
        var phoneResult = await ExecuteActionAsync(
            current, phoneStep, phoneAction, phoneInput, phoneRequestId);
        var collectCpf = phoneResult.GetProperty("snapshot");
        Assert.Equal("collectCpf", collectCpf.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(["submitCpf"], ActionTypes(collectCpf));
        AssertNoIssuedSession(phoneResult);
        await AssertCivilDataPendingAsync(current, verifyPhone);

        var cpfRequestId = Guid.NewGuid();
        var civilInput = new { cpf = "52998224725", birthDate = "1990-05-21" };
        var completed = await ExecuteActionAsync(current, collectCpf, "submitCpf", civilInput, cpfRequestId);
        Assert.Equal("completed", completed.GetProperty("snapshot").GetProperty("status").GetString());
        Assert.Equal("product", completed.GetProperty("issuedSession").GetProperty("purpose").GetString());

        var phoneReplay = await ExecuteActionAsync(current, phoneStep, phoneAction, phoneInput, phoneRequestId);
        Assert.Equal(collectCpf.GetRawText(), phoneReplay.GetProperty("snapshot").GetRawText());
        AssertNoIssuedSession(phoneReplay);
        var cpfReplay = await ExecuteActionAsync(current, collectCpf, "submitCpf", civilInput, cpfRequestId);
        Assert.Equal(completed.GetProperty("issuedSession").GetRawText(), cpfReplay.GetProperty("issuedSession").GetRawText());

        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(new DateOnly(1990, 5, 21), (await db.Identities.SingleAsync(i => i.Id == current.IdentityId)).BirthDate);
        Assert.True(await db.IdentityIdentifiers.AnyAsync(i => i.IdentityId == current.IdentityId && i.Scheme == IdentifierScheme.Cpf));
        Assert.Equal(RegistrationContextStatus.Completed, (await db.RegistrationContexts.SingleAsync(c => c.IdentityId == current.IdentityId)).Status);
        Assert.Single(await db.IdentitySessions.Where(s => s.IdentityId == current.IdentityId && s.Purpose == IdentitySessionPurpose.Product).ToListAsync());
    }

    [Fact]
    public async Task CpfAfterPhone_ExistingEmailConflictResolutionContinuesToCivilData()
    {
        var previousEmail = $"previous-cpf-{Guid.NewGuid():N}@example.test";
        var previous = await RegisterAndStartFlowAsync(previousEmail);
        var verification = await RequestPhoneAsync(previous.Flow, previous.Capability);
        var previousCompleted = await ConfirmPhoneAsync(verification, previous.Capability, "123456");
        Assert.Equal("completed", previousCompleted.GetProperty("status").GetString());

        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true,
            cpfCollectionPosition: CpfCollectionPosition.AfterPhone,
            phoneRequired: true));
        var current = await RegisterAndStartFlowAsync(
            $"current-cpf-{Guid.NewGuid():N}@example.test", ProtocolVersions1And2);
        var currentVerification = await RequestPhoneAsync(current.Flow, current.Capability);
        var conflict = await ConfirmPhoneAsync(currentVerification, current.Capability, "123456");
        Assert.Equal("resolvePhoneConflict", conflict.GetProperty("step").GetProperty("type").GetString());
        Assert.DoesNotContain("submitCpf", ActionTypes(conflict));

        var wrongEmail = await ExecuteActionAsync(current, conflict, "transferPhoneToCurrentIdentity", new { previousEmail = "wrong@example.test" });
        Assert.Equal("phone-conflict-email-mismatch", wrongEmail.GetProperty("snapshot").GetProperty("feedback").GetProperty("code").GetString());
        var transferred = await ExecuteActionAsync(current, wrongEmail.GetProperty("snapshot"), "transferPhoneToCurrentIdentity", new { previousEmail });
        var collectCpf = transferred.GetProperty("snapshot");
        Assert.Equal("collectCpf", collectCpf.GetProperty("step").GetProperty("type").GetString());
        AssertNoIssuedSession(transferred);
        await AssertCivilDataPendingAsync(current, true);

        await using (var scope = api.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            Assert.False(await db.IdentityIdentifiers.AnyAsync(i => i.IdentityId == previous.IdentityId && i.Scheme == IdentifierScheme.Phone));
            Assert.False(await db.PhoneRegistrationConflicts.AnyAsync(c => c.AccessFlowId == current.FlowId));
        }

        var completed = await ExecuteActionAsync(current, collectCpf, "submitCpf", new { cpf = "52998224725", birthDate = "1990-05-21" });
        Assert.Equal("completed", completed.GetProperty("snapshot").GetProperty("status").GetString());
        Assert.Equal(current.IdentityId, completed.GetProperty("issuedSession").GetProperty("identityId").GetGuid());
    }

    [Fact]
    public async Task CpfBeforePhone_OptionalPhoneCanOnlyBeSkippedAfterCivilData()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true, cpfCollectionPosition: CpfCollectionPosition.BeforePhone));
        var current = await RegisterAndStartFlowAsync(
            $"cpf-before-skip-{Guid.NewGuid():N}@example.test", ProtocolVersions1And2);
        Assert.Equal(["submitCpf"], ActionTypes(current.Flow));
        var civilData = await ExecuteActionAsync(current, current.Flow, "submitCpf", new { cpf = "52998224725", birthDate = "1990-05-21" });
        var phone = civilData.GetProperty("snapshot");
        Assert.Contains("skipRegistration", ActionTypes(phone));
        AssertNoIssuedSession(civilData);
        var completed = await ExecuteActionAsync(current, phone, "skipRegistration");
        Assert.Equal("completed", completed.GetProperty("snapshot").GetProperty("status").GetString());
    }

    [Fact]
    public async Task CpfAfterPhone_DatabaseConstraintRequiresEnabledRequiredPhone()
    {
        await ConfigurePolicyAsync(TestAccessPolicies.Create(
            cpfEnabled: true, cpfCollectionPosition: CpfCollectionPosition.AfterPhone, phoneRequired: true));
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var environment = await db.AppEnvironments.AsNoTracking().SingleAsync();
        Assert.Equal(CpfCollectionPosition.AfterPhone, environment.AccessPolicy.CpfCollectionPosition);

        var optionalPhone = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE app_environments SET phone_identifier_required = false WHERE id = {environment.Id}"));
        Assert.Equal(PostgresErrorCodes.CheckViolation, optionalPhone.SqlState);
        Assert.Equal("ck_app_environments_cpf_after_required_phone", optionalPhone.ConstraintName);
        var disabledPhone = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE app_environments SET phone_identifier_enabled = false WHERE id = {environment.Id}"));
        Assert.Equal(PostgresErrorCodes.CheckViolation, disabledPhone.SqlState);
        Assert.Equal("ck_app_environments_cpf_after_required_phone", disabledPhone.ConstraintName);
    }

    private async Task AssertCivilDataPendingAsync(StartedRegistration current, bool verifiedPhone)
    {
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var phone = await db.IdentityIdentifiers.SingleAsync(i => i.IdentityId == current.IdentityId && i.Scheme == IdentifierScheme.Phone);
        Assert.Equal(verifiedPhone, phone.VerifiedAt.HasValue);
        Assert.Equal(AccessFlowStatus.Active, (await db.AccessFlows.SingleAsync(f => f.Id == current.FlowId)).Status);
        Assert.NotEqual(RegistrationContextStatus.Completed, (await db.RegistrationContexts.SingleAsync(c => c.IdentityId == current.IdentityId)).Status);
        Assert.Null((await db.Identities.SingleAsync(i => i.Id == current.IdentityId)).BirthDate);
        Assert.False(await db.IdentityIdentifiers.AnyAsync(i => i.IdentityId == current.IdentityId && i.Scheme == IdentifierScheme.Cpf));
        Assert.False(await db.IdentitySessions.AnyAsync(s => s.IdentityId == current.IdentityId && s.Purpose == IdentitySessionPurpose.Product));
        Assert.True(await db.IdentitySessions.AnyAsync(s => s.IdentityId == current.IdentityId && s.Purpose == IdentitySessionPurpose.Registration && s.RevokedAt == null));
    }

    private static void AssertNoIssuedSession(JsonElement response) =>
        Assert.True(!response.TryGetProperty("issuedSession", out var issued) || issued.ValueKind == JsonValueKind.Null);

    private static void AssertCivilDataFeedback(
        JsonElement snapshot,
        string code,
        string field)
    {
        Assert.Equal("active", snapshot.GetProperty("status").GetString());
        Assert.Equal(
            "collectCpf",
            snapshot.GetProperty("step").GetProperty("type").GetString());
        Assert.Equal(code, snapshot.GetProperty("feedback").GetProperty("code").GetString());
        Assert.Equal(field, snapshot.GetProperty("feedback").GetProperty("field").GetString());
        Assert.Equal(["submitCpf"], ActionTypes(snapshot));
    }
}
