using System.ComponentModel.DataAnnotations;

namespace SepidarGateway.Configuration;

public class GatewayOptions
{
    [Required]
    public List<TenantOptions> Tenants { get; set; } = new();

    public OcelotRootOptions Ocelot { get; set; } = new();
}

public class TenantOptions
{
    [Required]
    public string TenantId { get; set; } = string.Empty;

    public TenantMatchOptions Match { get; set; } = new();

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
}

public class TenantCredentialOptions
{
    [Required]
    public string UserName { get; set; } = string.Empty;

    [Required]
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
