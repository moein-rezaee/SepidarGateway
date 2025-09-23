using System.ComponentModel.DataAnnotations;

namespace SepidarGateway.Configuration;

public class GatewayOptions
{
    [Required]
    public TenantOptions Tenant { get; set; } = new();

    public OcelotRootOptions Ocelot { get; set; } = new();
}

public class TenantOptions
{
    // Single-customer mode: no external TenantId required
    public string TenantId { get; set; } = "main";

    // Matching is removed in single-tenant mode, but kept for backward compatibility
    public TenantMatchOptions? Match { get; set; }
        = null;

    public SepidarEndpointOptions Sepidar { get; set; } = new();

    public TenantCredentialOptions Credentials { get; set; } = new();

    public TenantCryptoOptions Crypto { get; set; } = new();

    public TenantJwtOptions Jwt { get; set; } = new();

    public TenantClientOptions? Clients { get; set; }
        = new TenantClientOptions();

    public TenantLimitOptions Limits { get; set; } = new();

    public TenantCorsOptions? Cors { get; set; }
        = new TenantCorsOptions();
}

public class TenantMatchOptions
{
    public string[]? Hostnames { get; set; }
        = Array.Empty<string>();

    public TenantHeaderMatchOptions? Header { get; set; }
        = new();

    public string? PathBase { get; set; }
        = "/";
}

public class TenantHeaderMatchOptions
{
    public string? HeaderName { get; set; }
        = "X-Tenant-ID";

    public string[]? HeaderValues { get; set; }
        = Array.Empty<string>();
}

public class SepidarEndpointOptions
{
    [Required]
    [Url]
    public string BaseUrl { get; set; } = string.Empty;

    [Required]
    public string IntegrationId { get; set; } = string.Empty;

    [Required]
    public string DeviceSerial { get; set; } = string.Empty;

    [Required]
    public string GenerationVersion { get; set; } = string.Empty;

    public string ApiVersion { get; set; } = string.Empty;

    public string RegisterPath { get; set; } = "api/Devices/Register/";

    public string[]? RegisterFallbackPaths { get; set; } = new[] { "api/Device/Register/" };

    // When true, only the configured RegisterPath (and optional RegisterFallbackPaths) are attempted.
    // No built-in candidates or Swagger discovery will be used. Useful for strict environments.
    public bool RegisterStrict { get; set; } = true;

    // Optional cookie header value required by some servers during Register (e.g., "__NCTRACE=...")
    public string? RegisterCookie { get; set; }

    public string LoginPath { get; set; } = "api/users/login/";

    public string IsAuthorizedPath { get; set; } = "api/IsAuthorized/";

    public string SwaggerDocumentPath { get; set; } = "swagger/sepidar/swagger.json";

    // Register payload mode:
    // - Detailed: JSON { DeviceSerial, IntegrationId, Timestamp } encrypted
    // - SimpleTitle: AES of DeviceTitle (or DeviceSerial if title is empty)
    // - IntegrationOnly: AES-128 of IntegrationId only (per Sepidar PDF/Python sample)
    public string RegisterPayloadMode { get; set; } = "Detailed"; // Detailed | SimpleTitle | IntegrationOnly

    // Optional friendly title for the device used when RegisterPayloadMode = SimpleTitle
    public string? DeviceTitle { get; set; }
}

public class TenantCredentialOptions
{
    // Optional at startup; /device/login می‌تواند مقداردهی کند
    public string UserName { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;
}

public class TenantCryptoOptions
{
    public string? RsaPublicKeyXml { get; set; }
        = null;

    public string? RsaModulusBase64 { get; set; }
        = null;

    public string? RsaExponentBase64 { get; set; }
        = null;
}

public class TenantJwtOptions
{
    public int CacheSeconds { get; set; } = 1800;

    public int PreAuthCheckSeconds { get; set; } = 300;
}

public class TenantClientOptions
{
    public string[]? ApiKeys { get; set; }
        = Array.Empty<string>();
}

public class TenantLimitOptions
{
    public int RequestsPerMinute { get; set; } = 60;

    public int QueueLimit { get; set; } = 0;

    public int RequestTimeoutSeconds { get; set; } = 100;
}

public class TenantCorsOptions
{
    public string[]? AllowedOrigins { get; set; }
        = Array.Empty<string>();

    public string[]? AllowedHeaders { get; set; }
        = Array.Empty<string>();

    public string[]? AllowedMethods { get; set; }
        = new[] { "GET", "POST", "PUT", "DELETE", "OPTIONS" };

    public bool AllowCredentials { get; set; }
        = false;
}

public class OcelotRootOptions
{
    public List<RouteOptions> Routes { get; set; } = new();
}

public class RouteOptions
{
    public string DownstreamPathTemplate { get; set; } = string.Empty;

    public string UpstreamPathTemplate { get; set; } = string.Empty;

    public List<string> UpstreamHttpMethod { get; set; } = new();

    public string DownstreamScheme { get; set; } = "http";
}
