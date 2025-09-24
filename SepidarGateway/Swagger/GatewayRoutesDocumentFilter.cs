using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using SepidarGateway.Configuration;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace SepidarGateway.Swagger;

public class GatewayRoutesDocumentFilter : IDocumentFilter
{
    private static readonly Regex PathParameterRegex = new("\\{(?<name>[^}]+)\\}", RegexOptions.Compiled);
    private static readonly Regex VersionSegmentRegex = new("^v[0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

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

        var versions = (_gatewayOptions.Settings?.SupportedVersions ?? Array.Empty<string>())
            .Select(version => version?.Trim('/') ?? string.Empty)
            .Where(version => !string.IsNullOrWhiteSpace(version))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (versions.Length == 0)
        {
            versions = new[] { string.Empty };
        }

        foreach (var route in _gatewayOptions.Routes)
        {
            var normalizedPath = NormalizePath(route.Path);
            if (string.IsNullOrWhiteSpace(normalizedPath))
            {
                continue;
            }

            var methods = route.Methods?.Count > 0
                ? route.Methods
                : new List<string> { "GET" };

            foreach (var version in versions)
            {
                var versionedPath = string.IsNullOrEmpty(version)
                    ? normalizedPath
                    : CombineVersion(version, normalizedPath);

                if (!swaggerDocument.Paths.TryGetValue(versionedPath, out var pathItem))
                {
                    pathItem = new OpenApiPathItem();
                    swaggerDocument.Paths[versionedPath] = pathItem;
                }

                pathItem.Operations ??= new Dictionary<OperationType, OpenApiOperation>();

                var tag = DeriveTag(versionedPath);

                foreach (var method in methods)
                {
                    if (string.IsNullOrWhiteSpace(method) || !Enum.TryParse(method, true, out OperationType operationType))
                    {
                        continue;
                    }

                    if (!existingOperations.Add((versionedPath, operationType)))
                    {
                        continue;
                    }

                    var operation = BuildOperation(route, versionedPath, tag);
                    pathItem.Operations[operationType] = operation;
                }
            }
        }
    }

    private OpenApiOperation BuildOperation(GatewayRoute route, string normalizedPath, string tag)
    {
        var methods = route.Methods?.Count > 0 ? route.Methods : new List<string> { "GET" };
        var segments = normalizedPath.Trim('/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .ToList();
        if (segments.Count > 0 && VersionSegmentRegex.IsMatch(segments[0]))
        {
            segments.RemoveAt(0);
        }

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
            var lowerSegments = string.Join('/', segments).ToLowerInvariant();
            if (lowerSegments.StartsWith("api/devices/register", StringComparison.Ordinal))
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
            else if (lowerSegments.StartsWith("api/users/login", StringComparison.Ordinal))
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
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .ToList();

        if (segments.Count > 0 && VersionSegmentRegex.IsMatch(segments[0]))
        {
            segments.RemoveAt(0);
        }

        if (segments.Count == 0)
        {
            return "Gateway";
        }

        if (string.Equals(segments[0], "api", StringComparison.OrdinalIgnoreCase))
        {
            if (segments.Count == 1)
            {
                return "Sepidar Api";
            }

            return $"Sepidar {CultureInfo.InvariantCulture.TextInfo.ToTitleCase(segments[1])}";
        }

        return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(segments[0]);
    }

    private static IEnumerable<string> ExtractPathParameters(string versionedPath)
    {
        foreach (Match match in PathParameterRegex.Matches(versionedPath))
        {
            var name = match.Groups["name"].Value;
            if (!string.IsNullOrWhiteSpace(name))
            {
                yield return name;
            }
        }
    }

    private static string CombineVersion(string version, string normalizedPath)
    {
        var trimmedVersion = version.Trim('/');
        if (string.IsNullOrEmpty(trimmedVersion))
        {
            return normalizedPath;
        }

        if (!normalizedPath.StartsWith('/'))
        {
            return $"/{trimmedVersion}/{normalizedPath}";
        }

        return $"/{trimmedVersion}{normalizedPath}";
    }
}
