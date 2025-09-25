using System.Text.Json.Serialization;

namespace SepidarGateway.Contracts;

public sealed class DeviceRegisterRequestDto
{
    public string DeviceSerial { get; set; } = string.Empty;
}

public sealed class DeviceLoginRequestDto
{
    [JsonPropertyName("userName")]
    public string? UserName { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

    [JsonPropertyName("deviceSerial")]
    public string? DeviceSerial { get; set; }

    [JsonPropertyName("integrationId")]
    public string? IntegrationId { get; set; }

    [JsonPropertyName("generationVersion")]
    public string? GenerationVersion { get; set; }

    [JsonPropertyName("registerPayload")]
    public DeviceRegisterPayloadDto? RegisterPayload { get; set; }
}

public sealed class DeviceRegisterPayloadDto
{
    [JsonPropertyName("cypher")]
    public string? Cypher { get; set; }

    [JsonPropertyName("iv")]
    public string? Iv { get; set; }

    [JsonPropertyName("deviceTitle")]
    public string? DeviceTitle { get; set; }
}
