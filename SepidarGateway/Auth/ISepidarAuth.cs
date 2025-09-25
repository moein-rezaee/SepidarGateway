using SepidarGateway.Configuration;

namespace SepidarGateway.Auth;

public interface ISepidarAuth
{
    Task EnsureDeviceRegisteredAsync(GatewaySettings settings, CancellationToken cancellationToken);

    Task<RegisterDeviceRawResponse> RegisterDeviceAsync(GatewaySettings settings, CancellationToken cancellationToken);

    Task<DeviceLoginRawResponse> LoginAsync(GatewaySettings settings, CancellationToken cancellationToken);

    Task<string> EnsureTokenAsync(GatewaySettings settings, CancellationToken cancellationToken);

    Task<bool> IsAuthorizedAsync(GatewaySettings settings, CancellationToken cancellationToken);

    void InvalidateToken();
}
