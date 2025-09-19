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

    public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context)
    {
        if (_gatewayOptions.Ocelot?.Routes == null || _gatewayOptions.Ocelot.Routes.Count == 0)
        {
            return;
        }

        swaggerDoc.Paths ??= new OpenApiPaths();
        var existingOperations = new HashSet<(string Path, OperationType Operation)>();

        foreach (var route in _gatewayOptions.Ocelot.Routes)
        {
            var normalizedPath = NormalizePath(route.UpstreamPathTemplate);
            if (string.IsNullOrWhiteSpace(normalizedPath))
            {
                continue;
            }

            if (!swaggerDoc.Paths.TryGetValue(normalizedPath, out var pathItem))
            {
                pathItem = new OpenApiPathItem();
                swaggerDoc.Paths[normalizedPath] = pathItem;
            }

            var tag = DeriveTag(normalizedPath);
            var methods = route.UpstreamHttpMethod?.Count > 0
                ? route.UpstreamHttpMethod
                : new List<string> { "GET" };

            foreach (var method in methods)
            {
                if (string.IsNullOrWhiteSpace(method) || !Enum.TryParse<OperationType>(method, true, out var operationType))
                {
                    continue;
                }

                if (!existingOperations.Add((normalizedPath, operationType)))
                {
                    continue;
                }

                var operation = BuildOperation(route, normalizedPath, tag);
                pathItem.Operations[operationType] = operation;
            }
        }
    }

    private static OpenApiOperation BuildOperation(RouteConfig route, string normalizedPath, string tag)
    {
        var operation = new OpenApiOperation
        {
            Summary = $"Proxy {string.Join(", ", route.UpstreamHttpMethod ?? new List<string> { "GET" })} {normalizedPath}",
            Description = $"Forwards the request to Sepidar endpoint `{route.DownstreamPathTemplate}`.",
            Tags = new List<OpenApiTag> { new() { Name = tag } },
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

        foreach (var parameterName in ExtractPathParameters(normalizedPath))
        {
            operation.Parameters.Add(new OpenApiParameter
            {
                Name = parameterName,
                In = ParameterLocation.Path,
                Required = true,
                Schema = new OpenApiSchema { Type = "string" },
                Description = "Value forwarded to Sepidar endpoint."
            });
        }

        return operation;
    }

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var trimmed = path.Trim();
        if (!trimmed.StartsWith('/'))
        {
            trimmed = "/" + trimmed;
        }

        while (trimmed.Contains("//", StringComparison.Ordinal))
        {
            trimmed = trimmed.Replace("//", "/", StringComparison.Ordinal);
        }

        return trimmed;
    }

    private static IEnumerable<string> ExtractPathParameters(string path)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in PathParameterRegex.Matches(path))
        {
            var name = match.Groups["name"].Value;
            if (!string.IsNullOrWhiteSpace(name) && seen.Add(name))
            {
                yield return name;
            }
        }
    }

    private static string DeriveTag(string path)
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in segments)
        {
            if (!segment.Equals("api", StringComparison.OrdinalIgnoreCase))
            {
                return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(segment.Replace("{", string.Empty, StringComparison.Ordinal).Replace("}", string.Empty, StringComparison.Ordinal));
            }
        }

        return "Api";
    }
}
