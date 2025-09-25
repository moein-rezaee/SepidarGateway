namespace SepidarGateway.Auth;

public sealed class RegisterPayloadSnapshot
{
    public string Cypher { get; init; } = string.Empty;

    public string IV { get; init; } = string.Empty;

    public string? DeviceTitle { get; init; }
        = null;
}
