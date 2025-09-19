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

    public void Apply(OpenApiDocument swagger_doc, DocumentFilterContext context)
    {
        if (_gatewayOptions.Ocelot?.Routes == null || _gatewayOptions.Ocelot.Routes.Count == 0)
        {
            return;
        }

        swagger_doc.Paths ??= new OpenApiPaths();
        var existing_operations = new HashSet<(string Path, OperationType Operation)>();

        foreach (var route_config in _gatewayOptions.Ocelot.Routes)
        {
            var normalized_path = NormalizePath(route_config.UpstreamPathTemplate);
            if (string.IsNullOrWhiteSpace(normalized_path))
            {
                continue;
            }

            if (!swagger_doc.Paths.TryGetValue(normalized_path, out var path_item))
            {
                path_item = new OpenApiPathItem();
                swagger_doc.Paths[normalized_path] = path_item;
            }

            var route_tag = DeriveTag(normalized_path);
            var upstream_methods = route_config.UpstreamHttpMethod?.Count > 0
                ? route_config.UpstreamHttpMethod
                : new List<string> { "GET" };

            foreach (var http_method in upstream_methods)
            {
                if (string.IsNullOrWhiteSpace(http_method) || !Enum.TryParse<OperationType>(http_method, true, out var operation_type))
                {
                    continue;
                }

                if (!existing_operations.Add((normalized_path, operation_type)))
                {
                    continue;
                }

                var gateway_operation = BuildOperation(route_config, normalized_path, route_tag);
                path_item.Operations[operation_type] = gateway_operation;
            }
        }
    }

    private static OpenApiOperation BuildOperation(RouteConfig route_config, string normalized_path, string route_tag)
    {
        var gateway_operation = new OpenApiOperation
        {
            Summary = $"Proxy {string.Join(", ", route_config.UpstreamHttpMethod ?? new List<string> { "GET" })} {normalized_path}",
            Description = $"Forwards the request to Sepidar endpoint `{route_config.DownstreamPathTemplate}`.",
            Tags = new List<OpenApiTag> { new() { Name = route_tag } },
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

        foreach (var parameter_name in ExtractPathParameters(normalized_path))
        {
            gateway_operation.Parameters.Add(new OpenApiParameter
            {
                Name = parameter_name,
                In = ParameterLocation.Path,
                Required = true,
                Schema = new OpenApiSchema { Type = "string" },
                Description = "Value forwarded to Sepidar endpoint."
            });
        }

        return gateway_operation;
    }

    private static string NormalizePath(string route_path)
    {
        if (string.IsNullOrWhiteSpace(route_path))
        {
            return string.Empty;
        }

        var trimmed_path = route_path.Trim();
        if (!trimmed_path.StartsWith('/'))
        {
            trimmed_path = "/" + trimmed_path;
        }

        while (trimmed_path.Contains("//", StringComparison.Ordinal))
        {
            trimmed_path = trimmed_path.Replace("//", "/", StringComparison.Ordinal);
        }

        return trimmed_path;
    }

    private static IEnumerable<string> ExtractPathParameters(string route_path)
    {
        var seen_parameters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match parameter_match in PathParameterRegex.Matches(route_path))
        {
            var parameter_name = parameter_match.Groups["name"].Value;
            if (!string.IsNullOrWhiteSpace(parameter_name) && seen_parameters.Add(parameter_name))
            {
                yield return parameter_name;
            }
        }
    }

    private static string DeriveTag(string route_path)
    {
        var path_segments = route_path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var path_segment in path_segments)
        {
            if (!path_segment.Equals("api", StringComparison.OrdinalIgnoreCase))
            {
                return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(path_segment.Replace("{", string.Empty, StringComparison.Ordinal).Replace("}", string.Empty, StringComparison.Ordinal));
            }
        }

        return "Api";
    }
}
