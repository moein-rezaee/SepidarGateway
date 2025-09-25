using System;

namespace SepidarGateway.Auth;

public sealed class RegisterDeviceFailedException : Exception
{
    public RegisterDeviceFailedException(RegisterDeviceRawResponse response, string message)
        : base(message)
    {
        Response = response ?? throw new ArgumentNullException(nameof(response));
    }

    public RegisterDeviceRawResponse Response { get; }
}
