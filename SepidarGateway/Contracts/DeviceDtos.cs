using System.Text.Json.Serialization;

namespace SepidarGateway.Contracts;

public sealed class DeviceRegisterRequestDto
{
    public string DeviceSerial { get; set; } = string.Empty;
}

public sealed class DeviceLoginRequestDto
{
    [JsonPropertyName("deviceSerial")]
    public string? DeviceSerial { get; set; }
}
