using Microsoft.AspNetCore.Http;

namespace SepidarGateway.Auth;

public sealed record RegisterDeviceRawResponse(string Body, string? ContentType, int StatusCode)
{
    public static RegisterDeviceRawResponse Empty { get; } =
        new(string.Empty, null, StatusCodes.Status204NoContent);
}
