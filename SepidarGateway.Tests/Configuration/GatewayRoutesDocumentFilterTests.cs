using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using SepidarGateway.Configuration;
using SepidarGateway.Swagger;

namespace SepidarGateway.Tests.Configuration;

public class GatewayRoutesDocumentFilterTests
{
    [Fact]
    public void Apply_BuildsPathItemsForConfiguredRoutes()
    {
        var options = Options.Create(new GatewayOptions
        {
            Ocelot = new OcelotRootOptions
            {
                Routes =
                [
                    new RouteOptions
                    {
                        UpstreamPathTemplate = "/api/Customers/{customerId}",
                        DownstreamPathTemplate = "/api/Customers/{customerId}",
                        UpstreamHttpMethod = ["GET", "PUT"]
                    },
                    new RouteOptions
                    {
                        UpstreamPathTemplate = "/api/Orders",
                        DownstreamPathTemplate = "/api/Orders",
                        UpstreamHttpMethod = ["POST"]
                    }
                ]
            }
        });

        var document = new OpenApiDocument
        {
            Paths = new OpenApiPaths(),
            Info = new OpenApiInfo { Title = "Test", Version = "v1" }
        };

        var filter = new GatewayRoutesDocumentFilter(options);

        filter.Apply(document, null!);

        document.Paths.Should().ContainKey("/api/Customers/{customerId}");
        document.Paths.Should().ContainKey("/api/Orders");

        var customerOperations = document.Paths["/api/Customers/{customerId}"].Operations;
        customerOperations.Should().ContainKey(OperationType.Get);
        customerOperations.Should().ContainKey(OperationType.Put);

        var getOperation = customerOperations[OperationType.Get];
        getOperation.Parameters.Should().ContainSingle(p => p.Name == "customerId" && p.In == ParameterLocation.Path);
        getOperation.Security.Should().ContainSingle();
        var securitySchemeIds = getOperation.Security.First().Keys
            .Where(s => s.Reference != null)
            .Select(s => s.Reference!.Id)
            .ToList();

        securitySchemeIds.Should().Contain(SwaggerConstants.ApiKeyScheme);
    }

    [Fact]
    public void Apply_SkipsInvalidRoutesAndAvoidsDuplicateOperations()
    {
        var options = Options.Create(new GatewayOptions
        {
            Ocelot = new OcelotRootOptions
            {
                Routes =
                [
                    new RouteOptions
                    {
                        UpstreamPathTemplate = "/api/Invoices",
                        DownstreamPathTemplate = "/api/Invoices",
                        UpstreamHttpMethod = ["GET", "GET", "INVALID"]
                    }
                ]
            }
        });

        var document = new OpenApiDocument
        {
            Paths = new OpenApiPaths(),
            Info = new OpenApiInfo { Title = "Test", Version = "v1" }
        };

        var filter = new GatewayRoutesDocumentFilter(options);

        filter.Apply(document, null!);

        document.Paths.Should().ContainKey("/api/Invoices");
        var operations = document.Paths["/api/Invoices"].Operations;
        operations.Should().ContainSingle(pair => pair.Key == OperationType.Get);
    }
}
