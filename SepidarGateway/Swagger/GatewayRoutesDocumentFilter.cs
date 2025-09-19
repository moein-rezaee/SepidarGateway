using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using SepidarGateway.Configuration;
using Swashbuckle.AspNetCore.SwaggerGen;
using RouteConfig = SepidarGateway.Configuration.RouteOptions;

namespace SepidarGateway.Swagger;

public class GatewayRoutesDocumentFilter : IDocumentFilter
{
    private static readonly Regex PathParameterRegex = new("\\{(?<name>[^}]+)\\}", RegexOptions.Compiled);

    private static readonly OpenApiSecurityScheme TenantSecurityReference = new()
    {
        Reference = new OpenApiReference
        {
            Id = SwaggerConstants.TenantIdScheme,
            Type = ReferenceType.SecurityScheme
        }
    };

    private static readonly OpenApiSecurityScheme ApiKeySecurityReference = new()
    {
        Reference = new OpenApiReference
        {
            Id = SwaggerConstants.ApiKeyScheme,
            Type = ReferenceType.SecurityScheme
        }
    };

    private readonly GatewayOptions _gatewayOptions;

    public GatewayRoutesDocumentFilter(IOptions<GatewayOptions> options)
    {
        _gatewayOptions = options.Value;
    }

    public void Apply(OpenApiDocument SwaggerDocument, DocumentFilterContext Context)
    {
        _ = Context;
        if (_gatewayOptions.Ocelot?.Routes == null || _gatewayOptions.Ocelot.Routes.Count == 0)
        {
            return;
        }

        SwaggerDocument.Paths ??= new OpenApiPaths();
        var ExistingOperations = new HashSet<(string Path, OperationType Operation)>();

        foreach (var RouteConfiguration in _gatewayOptions.Ocelot.Routes)
        {
            var NormalizedPath = NormalizePath(RouteConfiguration.UpstreamPathTemplate);
            if (string.IsNullOrWhiteSpace(NormalizedPath))
            {
                continue;
            }

            if (!SwaggerDocument.Paths.TryGetValue(NormalizedPath, out var PathItem))
            {
                PathItem = new OpenApiPathItem();
                SwaggerDocument.Paths[NormalizedPath] = PathItem;
            }

            var RouteTag = DeriveTag(NormalizedPath);
            var UpstreamMethods = RouteConfiguration.UpstreamHttpMethod?.Count > 0
                ? RouteConfiguration.UpstreamHttpMethod
                : new List<string> { "GET" };

            foreach (var HttpMethodName in UpstreamMethods)
            {
                if (string.IsNullOrWhiteSpace(HttpMethodName) || !Enum.TryParse(HttpMethodName, true, out OperationType OperationTypeValue))
                {
                    continue;
                }

                if (!ExistingOperations.Add((NormalizedPath, OperationTypeValue)))
                {
                    continue;
                }

                var GatewayOperation = BuildOperation(RouteConfiguration, NormalizedPath, RouteTag);
                PathItem.Operations[OperationTypeValue] = GatewayOperation;
            }
        }
    }

    private static OpenApiOperation BuildOperation(RouteConfig RouteConfiguration, string NormalizedPath, string RouteTag)
    {
        var GatewayOperation = new OpenApiOperation
        {
            Summary = $"Proxy {string.Join(", ", RouteConfiguration.UpstreamHttpMethod ?? new List<string> { "GET" })} {NormalizedPath}",
            Description = $"Forwards the request to Sepidar endpoint `{RouteConfiguration.DownstreamPathTemplate}`.",
            Tags = new List<OpenApiTag> { new() { Name = RouteTag } },
            Responses = new OpenApiResponses
            {
                ["200"] = new OpenApiResponse
                {
                    Description = "Successful response proxied from Sepidar."
                },
                ["401"] = new OpenApiResponse
                {
                    Description = "Unauthorized - missing client credentials or Sepidar token expired."
                },
                ["412"] = new OpenApiResponse
                {
                    Description = "GenerationVersion mismatch reported by Sepidar."
                }
            },
            Security = new List<OpenApiSecurityRequirement>
            {
                new()
                {
                    [TenantSecurityReference] = Array.Empty<string>(),
                    [ApiKeySecurityReference] = Array.Empty<string>()
                }
            }
        };

        foreach (var ParameterName in ExtractPathParameters(NormalizedPath))
        {
            GatewayOperation.Parameters.Add(new OpenApiParameter
            {
                Name = ParameterName,
                In = ParameterLocation.Path,
                Required = true,
                Schema = new OpenApiSchema { Type = "string" },
                Description = "Value forwarded to Sepidar endpoint."
            });
        }

        return GatewayOperation;
    }

    private static string NormalizePath(string RoutePath)
    {
        if (string.IsNullOrWhiteSpace(RoutePath))
        {
            return string.Empty;
        }

        var TrimmedPath = RoutePath.Trim();
        if (!TrimmedPath.StartsWith('/'))
        {
            TrimmedPath = "/" + TrimmedPath;
        }

        while (TrimmedPath.Contains("//", StringComparison.Ordinal))
        {
            TrimmedPath = TrimmedPath.Replace("//", "/", StringComparison.Ordinal);
        }

        return TrimmedPath;
    }

    private static IEnumerable<string> ExtractPathParameters(string RoutePath)
    {
        var SeenParameters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match ParameterMatch in PathParameterRegex.Matches(RoutePath))
        {
            var ParameterName = ParameterMatch.Groups["name"].Value;
            if (!string.IsNullOrWhiteSpace(ParameterName) && SeenParameters.Add(ParameterName))
            {
                yield return ParameterName;
            }
        }
    }

    private static string DeriveTag(string RoutePath)
    {
        var PathSegments = RoutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var PathSegment in PathSegments)
        {
            if (!PathSegment.Equals("api", StringComparison.OrdinalIgnoreCase))
            {
                return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(PathSegment.Replace("{", string.Empty, StringComparison.Ordinal).Replace("}", string.Empty, StringComparison.Ordinal));
            }
        }

        return "Api";
    }
}
