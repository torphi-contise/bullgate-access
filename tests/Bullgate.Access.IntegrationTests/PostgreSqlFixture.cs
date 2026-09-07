using Testcontainers.PostgreSql;

namespace Bullgate.Access.IntegrationTests;

public sealed class PostgreSqlFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18.6-alpine")
        .WithDatabase("bullgate_access_tests")
        .WithUsername("bullgate_access")
        .WithPassword("bullgate_access_tests")
        .Build();

    public string ConnectionString => container.GetConnectionString();

    public Task InitializeAsync() => container.StartAsync();

    public Task DisposeAsync() => container.DisposeAsync().AsTask();
}
