using System.Text.Json.Serialization;

namespace SepidarGateway.Contracts;

public sealed class DeviceRegisterRequestDto
{
    [JsonPropertyName("deviceSerial")]
    public string DeviceSerial { get; set; } = string.Empty;
}

public sealed class DeviceLoginRequestDto
{
}
