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
}
