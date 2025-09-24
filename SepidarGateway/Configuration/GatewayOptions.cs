using System.ComponentModel.DataAnnotations;

namespace SepidarGateway.Configuration;

public class GatewayOptions
{
    [Required]
    public GatewaySettings Settings { get; set; } = new();

    public List<GatewayRoute> Routes { get; set; } = new();
}

public class GatewaySettings
{
    [Required]
    public string Name { get; set; } = "default";

    [Required]
    public SepidarOptions Sepidar { get; set; } = new();

    public CredentialOptions Credentials { get; set; } = new();

    public CryptoOptions Crypto { get; set; } = new();

    public JwtOptions Jwt { get; set; } = new();

    public string[] SupportedVersions { get; set; } = new[] { "v1" };
}

public class SepidarOptions
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

    public string RegisterPath { get; set; } = "api/Devices/Register";

    public string[]? RegisterFallbackPaths { get; set; } = Array.Empty<string>();

    public bool RegisterStrict { get; set; } = true;

    public string? RegisterCookie { get; set; }
        = null;

    public string LoginPath { get; set; } = "api/users/login";

    public string IsAuthorizedPath { get; set; } = "api/IsAuthorized";

    public string SwaggerDocumentPath { get; set; } = "swagger/sepidar/swagger.json";

    public bool UseProxy { get; set; } = true;

    public string? ProxyUrl { get; set; }
        = null;

    public string? ProxyUserName { get; set; }
        = null;

    public string? ProxyPassword { get; set; }
        = null;

    public string RegisterPayloadMode { get; set; } = "IntegrationOnly";

    public string? DeviceTitle { get; set; }
        = null;
}

public class CredentialOptions
{
    public string UserName { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;
}

public class CryptoOptions
{
    public string? RsaPublicKeyXml { get; set; }
        = null;

    public string? RsaModulusBase64 { get; set; }
        = null;

    public string? RsaExponentBase64 { get; set; }
        = null;
}

public class JwtOptions
{
    public int CacheSeconds { get; set; } = 1800;

    public int PreAuthCheckSeconds { get; set; } = 300;
}

public class GatewayRoute
{
    [Required]
    public string Path { get; set; } = string.Empty;

    public List<string> Methods { get; set; } = new();
}
