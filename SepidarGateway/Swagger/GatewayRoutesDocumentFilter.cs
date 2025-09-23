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

            // Hide low-level Sepidar auth/registration proxy routes from Swagger to avoid confusion;
            // users should use simplified /device/* endpoints instead.
            var down = (RouteConfiguration.DownstreamPathTemplate ?? string.Empty).Trim().ToLowerInvariant();
            if (down.Contains("/api/devices/register") || down.Contains("/api/users/login"))
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

    private OpenApiOperation BuildOperation(RouteConfig RouteConfiguration, string NormalizedPath, string RouteTag)
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
            }
        };

        // In single-customer mode, X-Tenant-ID is not required. Keep only client API key if configured.
        GatewayOperation.Security = new List<OpenApiSecurityRequirement>
        {
            new()
            {
                [ApiKeySecurityReference] = Array.Empty<string>()
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

        // Attach request body schemas for known POST endpoints so Swagger "Try it out" works.
        if ((RouteConfiguration.UpstreamHttpMethod?.Any(m => string.Equals(m, "POST", StringComparison.OrdinalIgnoreCase)) ?? false))
        {
            var pathLower = NormalizedPath.Trim('/').ToLowerInvariant();
            if (pathLower.StartsWith("api/devices/register"))
            {
                // Register request body follows Sepidar documentation (Cypher, IV, IntegrationID).
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

                GatewayOperation.RequestBody = new OpenApiRequestBody
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
            else if (pathLower.StartsWith("api/users/login"))
            {
                GatewayOperation.RequestBody = new OpenApiRequestBody
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
                var name = PathSegment.Replace("{", string.Empty, StringComparison.Ordinal).Replace("}", string.Empty, StringComparison.Ordinal);
                return ToPascalCase(name);
            }
        }

        return "Api";
    }

    private static string ToPascalCase(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return value;
        var parts = value.Split(new[] { '-', '_', ' ' }, StringSplitOptions.RemoveEmptyEntries);
        return string.Concat(parts.Select(p => char.ToUpperInvariant(p[0]) + (p.Length > 1 ? p[1..] : string.Empty)));
    }
}
