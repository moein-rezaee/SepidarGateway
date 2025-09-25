using Microsoft.AspNetCore.Http;

namespace SepidarGateway.Auth;

public sealed record DeviceLoginRawResponse(string Body, string? ContentType, int StatusCode)
{
    public static DeviceLoginRawResponse Empty { get; } =
        new(string.Empty, null, StatusCodes.Status204NoContent);
}
