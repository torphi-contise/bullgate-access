using Bullgate.Access.Api.Authentication;
using Bullgate.Access.Api.Endpoints;
using Bullgate.Access.Application;
using Bullgate.Access.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddHealthChecks();
builder.Services.AddAccessApplication();
builder.Services.AddAccessInfrastructure(builder.Configuration);
builder.Services.AddAccessFlowTokenProtection();
builder.Services.AddIntegrationClientAuthentication();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseAuthentication();
app.UseAuthorization();

// Endpoint groups declare their required integration-client permission individually.
// Keep authentication and authorization ahead of every application route; liveness is
// intentionally process-only and does not claim that PostgreSQL or providers are ready.
app.MapHealthChecks("/health/live");
app.MapEmailPasswordAccessEndpoints();
app.MapIdentityEmailEndpoints();
app.MapIdentityPhoneEndpoints();
app.MapCurrentIdentityEndpoints();
app.MapPhonePasswordRecoveryEndpoints();
app.MapSocialAccessEndpoints();
app.MapAccessFlowEndpoints();
app.MapApplicationClientConfigurationEndpoints();

app.Run();

/// <summary>Exposes the top-level API host type to integration-test infrastructure.</summary>
public partial class Program;
