using Bullgate.Access.Infrastructure;
using Bullgate.Access.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
var migrationsAssembly = typeof(Program).Assembly.GetName().Name
    ?? throw new InvalidOperationException("Could not resolve the migrations assembly name.");

builder.Services.AddAccessInfrastructure(builder.Configuration, migrationsAssembly);

using var host = builder.Build();
await using var scope = host.Services.CreateAsyncScope();
var dbContext = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
var historyRepository = dbContext.GetService<IHistoryRepository>();

await historyRepository.CreateIfNotExistsAsync();
await dbContext.Database.MigrateAsync();

Console.WriteLine("Bullgate Access database is up to date.");
