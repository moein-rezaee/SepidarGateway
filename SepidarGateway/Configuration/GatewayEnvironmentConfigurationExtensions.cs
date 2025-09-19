using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace SepidarGateway.Configuration;

public static class GatewayEnvironmentConfigurationExtensions
{
    private const string Prefix = "GW_";

    private static readonly Dictionary<string, string> SegmentMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["TENANTID"] = "TenantId",
        ["MATCH"] = "Match",
        ["HOSTNAMES"] = "Hostnames",
        ["HEADER"] = "Header",
        ["HEADERNAME"] = "HeaderName",
        ["HEADERVALUES"] = "HeaderValues",
        ["PATHBASE"] = "PathBase",
        ["SEPIDAR"] = "Sepidar",
        ["BASEURL"] = "BaseUrl",
        ["INTEGRATIONID"] = "IntegrationId",
        ["DEVICESERIAL"] = "DeviceSerial",
        ["GENERATIONVERSION"] = "GenerationVersion",
        ["APIVERSION"] = "ApiVersion",
        ["REGISTERPATH"] = "RegisterPath",
        ["REGISTERFALLBACKPATHS"] = "RegisterFallbackPaths",
        ["LOGINPATH"] = "LoginPath",
        ["ISAUTHORIZEDPATH"] = "IsAuthorizedPath",
        ["CREDENTIALS"] = "Credentials",
        ["USERNAME"] = "UserName",
        ["PASSWORD"] = "Password",
        ["CRYPTO"] = "Crypto",
        ["RSAPUBLICKEYXML"] = "RsaPublicKeyXml",
        ["RSAMODULUS"] = "RsaModulusBase64",
        ["RSAEXPONENT"] = "RsaExponentBase64",
        ["JWT"] = "Jwt",
        ["CACHESECONDS"] = "CacheSeconds",
        ["PREAUTHCHECKSECONDS"] = "PreAuthCheckSeconds",
        ["CLIENTS"] = "Clients",
        ["APIKEYS"] = "ApiKeys",
        ["LIMITS"] = "Limits",
        ["REQUESTSPERMINUTE"] = "RequestsPerMinute",
        ["QUEUELIMIT"] = "QueueLimit",
        ["REQUESTTIMEOUTSECONDS"] = "RequestTimeoutSeconds",
        ["CORS"] = "Cors",
        ["ALLOWEDORIGINS"] = "AllowedOrigins",
        ["ALLOWEDHEADERS"] = "AllowedHeaders",
        ["ALLOWEDMETHODS"] = "AllowedMethods",
        ["ALLOWCREDENTIALS"] = "AllowCredentials"
    };

    private static readonly HashSet<string> ArraySegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "HOSTNAMES",
        "HEADERVALUES",
        "APIKEYS",
        "ALLOWEDORIGINS",
        "ALLOWEDHEADERS",
        "ALLOWEDMETHODS",
        "REGISTERFALLBACKPATHS"
    };

    public static IConfigurationBuilder AddGatewayEnvironmentOverrides(this IConfigurationBuilder builder)
    {
        var overrides = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is not string rawKey || !rawKey.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var segments = rawKey.Split('_', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (segments.Length < 3)
            {
                continue;
            }

            var tenantSegment = segments[1];
            if (!tenantSegment.StartsWith("T", StringComparison.OrdinalIgnoreCase) || !int.TryParse(tenantSegment[1..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var tenantIndex))
            {
                continue;
            }

            var propertySegments = new List<string>();
            for (var i = 2; i < segments.Length; i++)
            {
                var segment = segments[i];
                if (!SegmentMap.TryGetValue(segment, out var mapped))
                {
                    mapped = ToPascalCase(segment);
                }

                propertySegments.Add(mapped);
            }

            if (propertySegments.Count == 0)
            {
                continue;
            }

            var baseSegments = new List<string> { "Gateway", "Tenants", tenantIndex.ToString(CultureInfo.InvariantCulture) };
            var rawValue = entry.Value?.ToString() ?? string.Empty;

            if (ArraySegments.Contains(segments[^1]))
            {
                var propertyName = propertySegments[^1];
                propertySegments.RemoveAt(propertySegments.Count - 1);

                var prefixSegments = baseSegments.Concat(propertySegments).ToArray();
                var basePath = string.Join(':', prefixSegments);
                var items = rawValue.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                if (items.Length == 0)
                {
                    overrides[$"{basePath}:{propertyName}:0"] = string.Empty;
                    continue;
                }

                for (var index = 0; index < items.Length; index++)
                {
                    overrides[$"{basePath}:{propertyName}:{index}"] = items[index];
                }

                continue;
            }

            var configPath = string.Join(':', baseSegments.Concat(propertySegments));
            overrides[configPath] = rawValue;
        }

        if (overrides.Count > 0)
        {
            builder.AddInMemoryCollection(overrides);
        }

        return builder;
    }

    private static string ToPascalCase(string segment)
    {
        if (string.IsNullOrWhiteSpace(segment))
        {
            return segment;
        }

        var builder = new StringBuilder(segment.Length);
        var nextUpper = true;

        foreach (var character in segment.ToLowerInvariant())
        {
            if (!char.IsLetterOrDigit(character))
            {
                nextUpper = true;
                continue;
            }

            builder.Append(nextUpper ? char.ToUpperInvariant(character) : character);
            nextUpper = false;
        }

        return builder.ToString();
    }
}
