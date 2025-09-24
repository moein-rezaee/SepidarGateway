using SepidarGateway.Configuration;
using SepidarGateway.Contracts;

namespace SepidarGateway.Auth;

public interface ISepidarAuth
{
    Task<string> EnsureDeviceRegisteredAsync(GatewaySettings settings, CancellationToken cancellationToken);

    Task<DeviceLoginResponseDto> LoginAsync(GatewaySettings settings, CancellationToken cancellationToken);

    Task<string> EnsureTokenAsync(GatewaySettings settings, CancellationToken cancellationToken);

    Task<bool> IsAuthorizedAsync(GatewaySettings settings, CancellationToken cancellationToken);

    void InvalidateToken();
}
