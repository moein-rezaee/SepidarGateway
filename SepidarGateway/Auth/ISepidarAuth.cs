using SepidarGateway.Configuration;

namespace SepidarGateway.Auth;

public interface ISepidarAuth
{
    Task EnsureDeviceRegisteredAsync(TenantOptions tenant, CancellationToken cancellationToken);

    Task<string> EnsureTokenAsync(TenantOptions tenant, CancellationToken cancellationToken);

    Task<bool> IsAuthorizedAsync(TenantOptions tenant, CancellationToken cancellationToken);

    void InvalidateToken(string tenantId);
}
