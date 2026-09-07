using System.Net;

namespace Bullgate.Access.IntegrationTests;

public sealed class HealthEndpointTests(AccessApiFactory factory)
    : IClassFixture<AccessApiFactory>
{
    [Fact]
    public async Task LiveHealth_ReturnsHealthy()
    {
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/health/live");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
    }
}
