using System.Reflection;
using Bullgate.Access.Application;
using Bullgate.Access.Domain;

namespace Bullgate.Access.UnitTests;

public sealed class DependencyDirectionTests
{
    [Fact]
    public void Domain_DoesNotReferenceOtherBullgateProjects()
    {
        var references = GetBullgateReferences(typeof(DomainAssemblyMarker).Assembly);

        Assert.Empty(references);
    }

    [Fact]
    public void Application_DoesNotReferenceOuterLayers()
    {
        var references = GetBullgateReferences(typeof(ApplicationAssemblyMarker).Assembly);

        Assert.DoesNotContain("Bullgate.Access.Api", references);
        Assert.DoesNotContain("Bullgate.Access.Infrastructure", references);
        Assert.DoesNotContain("Bullgate.Access.Migrations", references);
    }

    private static string[] GetBullgateReferences(Assembly assembly) =>
        assembly
            .GetReferencedAssemblies()
            .Select(reference => reference.Name)
            .Where(name => name is not null && name.StartsWith("Bullgate.", StringComparison.Ordinal))
            .Cast<string>()
            .Order(StringComparer.Ordinal)
            .ToArray();
}
