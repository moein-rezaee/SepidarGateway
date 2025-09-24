using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using SepidarGateway.Configuration;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace SepidarGateway.Swagger;

public class GatewayRoutesDocumentFilter : IDocumentFilter
{
    private static readonly Regex PathParameterRegex = new("\\{(?<name>[^}]+)\\}", RegexOptions.Compiled);

    private readonly GatewayOptions _gatewayOptions;

    public GatewayRoutesDocumentFilter(IOptions<GatewayOptions> options)
    {
        _gatewayOptions = options.Value;
    }

    public void Apply(OpenApiDocument swaggerDocument, DocumentFilterContext context)
    {
        _ = context;
        if (_gatewayOptions.Routes is null || _gatewayOptions.Routes.Count == 0)
        {
            return;
        }

        swaggerDocument.Paths ??= new OpenApiPaths();
        var existingOperations = new HashSet<(string Path, OperationType Operation)>();

        foreach (var route in _gatewayOptions.Routes)
        {
            var normalizedPath = NormalizePath(route.Path);
            if (string.IsNullOrWhiteSpace(normalizedPath))
            {
                continue;
            }

            if (!swaggerDocument.Paths.TryGetValue(normalizedPath, out var pathItem))
            {
                pathItem = new OpenApiPathItem();
                swaggerDocument.Paths[normalizedPath] = pathItem;
            }

            pathItem.Operations ??= new Dictionary<OperationType, OpenApiOperation>();

            var tag = DeriveTag(normalizedPath);
            var methods = route.Methods?.Count > 0
                ? route.Methods
                : new List<string> { "GET" };

            foreach (var method in methods)
            {
                if (string.IsNullOrWhiteSpace(method) || !Enum.TryParse(method, true, out OperationType operationType))
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

    private OpenApiOperation BuildOperation(GatewayRoute route, string normalizedPath, string tag)
    {
        var methods = route.Methods?.Count > 0 ? route.Methods : new List<string> { "GET" };
        var operation = new OpenApiOperation
        {
            Summary = $"Proxy {string.Join(", ", methods)} {normalizedPath}",
            Description = "Forwards the request to the configured Sepidar endpoint while enriching headers and authentication.",
            Tags = new List<OpenApiTag> { new() { Name = tag } },
            Parameters = new List<OpenApiParameter>(),
            Responses = new OpenApiResponses
            {
                ["200"] = new OpenApiResponse
                {
                    Description = "Successful response proxied from Sepidar."
                },
                ["401"] = new OpenApiResponse
                {
                    Description = "Unauthorized - Sepidar rejected the current token."
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
                    [new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Id = SwaggerConstants.SepidarTokenScheme,
                            Type = ReferenceType.SecurityScheme
                        }
                    }] = Array.Empty<string>()
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

        if (methods.Any(m => string.Equals(m, "POST", StringComparison.OrdinalIgnoreCase)))
        {
            var pathLower = normalizedPath.Trim('/').ToLowerInvariant();
            if (pathLower.StartsWith("api/devices/register", StringComparison.OrdinalIgnoreCase))
            {
                var mode = _gatewayOptions.Settings?.Sepidar?.RegisterPayloadMode?.Trim() ?? "Detailed";
                var schema = new OpenApiSchema
                {
                    Type = "object",
                    Properties = new Dictionary<string, OpenApiSchema>
                    {
                        ["Cypher"] = new OpenApiSchema { Type = "string", Description = "Base64 AES cipher" },
                        ["IV"] = new OpenApiSchema { Type = "string", Description = "Base64 AES IV" },
                        ["IntegrationID"] = new OpenApiSchema { Type = "integer", Format = "int32" }
                    },
                    Required = new HashSet<string> { "Cypher", "IV", "IntegrationID" }
                };

                if (!string.Equals(mode, "IntegrationOnly", StringComparison.OrdinalIgnoreCase))
                {
                    schema.Properties["DeviceSerial"] = new OpenApiSchema { Type = "string" };
                }

                operation.RequestBody = new OpenApiRequestBody
                {
                    Required = true,
                    Content = new Dictionary<string, OpenApiMediaType>
                    {
                        ["application/json"] = new OpenApiMediaType
                        {
                            Schema = schema
                        }
                    }
                };
            }
            else if (pathLower.StartsWith("api/users/login", StringComparison.OrdinalIgnoreCase))
            {
                operation.RequestBody = new OpenApiRequestBody
                {
                    Required = true,
                    Content = new Dictionary<string, OpenApiMediaType>
                    {
                        ["application/json"] = new OpenApiMediaType
                        {
                            Schema = new OpenApiSchema
                            {
                                Type = "object",
                                Properties = new Dictionary<string, OpenApiSchema>
                                {
                                    ["UserName"] = new OpenApiSchema { Type = "string" },
                                    ["PasswordHash"] = new OpenApiSchema { Type = "string", Description = "MD5 lowercase hex" }
                                },
                                Required = new HashSet<string> { "UserName", "PasswordHash" }
                            }
                        }
                    }
                };
            }
        }

        return operation;
    }

    private static string NormalizePath(string? path)
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

        return trimmed.TrimEnd('/');
    }

    private static string DeriveTag(string normalizedPath)
    {
        var segments = normalizedPath.Trim('/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length > 0
            ? CultureInfo.InvariantCulture.TextInfo.ToTitleCase(segments[0])
            : "Gateway";
    }

    private static IEnumerable<string> ExtractPathParameters(string path)
    {
        foreach (Match match in PathParameterRegex.Matches(path))
        {
            var name = match.Groups["name"].Value;
            if (!string.IsNullOrWhiteSpace(name))
            {
                yield return name;
            }
        }
    }
}
