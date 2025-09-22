namespace SepidarGateway.Contracts;

public sealed class DeviceRegisterRequestDto
{
    public string DeviceSerial { get; set; } = string.Empty;
}

public sealed class DeviceLoginRequestDto
{
    public string? UserName { get; set; }
    public string? Password { get; set; }
}
