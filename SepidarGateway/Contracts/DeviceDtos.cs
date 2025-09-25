using System.Text.Json.Serialization;

namespace SepidarGateway.Contracts;

public sealed class DeviceRegisterRequestDto
{
    [JsonPropertyName("deviceSerial")]
    public string DeviceSerial { get; set; } = string.Empty;
}

public sealed class DeviceLoginRequestDto
{
    [JsonPropertyName("deviceSerial")]
    public string? DeviceSerial { get; set; }

    [JsonPropertyName("integrationId")]
    public string? IntegrationId { get; set; }

    [JsonPropertyName("generationVersion")]
    public string? GenerationVersion { get; set; }

    [JsonPropertyName("userName")]
    public string? UserName { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

    [JsonPropertyName("registerPayload")]
    public DeviceRegisterPayloadOverride? RegisterPayload { get; set; }
}

public sealed class DeviceRegisterPayloadOverride
{
    [JsonPropertyName("cypher")]
    public string? Cypher { get; set; }

    [JsonPropertyName("iv")]
    public string? IV { get; set; }

    [JsonPropertyName("deviceTitle")]
    public string? DeviceTitle { get; set; }
}
