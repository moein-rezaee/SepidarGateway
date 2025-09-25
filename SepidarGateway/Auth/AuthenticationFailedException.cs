namespace SepidarGateway.Auth;

public sealed class AuthenticationFailedException : Exception
{
    public AuthenticationFailedException(string message, DeviceLoginRawResponse response)
        : base(message)
    {
        Response = response;
    }

    public DeviceLoginRawResponse Response { get; }
}
