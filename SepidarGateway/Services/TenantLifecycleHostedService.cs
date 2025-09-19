using Microsoft.Extensions.Options;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;

namespace SepidarGateway.Services;

public sealed class TenantLifecycleHostedService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptionsMonitor<GatewayOptions> _optionsMonitor;
    private readonly ILogger<TenantLifecycleHostedService> _logger;

    public TenantLifecycleHostedService(
        IServiceScopeFactory scopeFactory,
        IOptionsMonitor<GatewayOptions> optionsMonitor,
        ILogger<TenantLifecycleHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _optionsMonitor = optionsMonitor;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var tenant_list = _optionsMonitor.CurrentValue.Tenants.ToList();
                using var tenant_scope = _scopeFactory.CreateScope();
                var auth_service = tenant_scope.ServiceProvider.GetRequiredService<ISepidarAuth>();

                foreach (var tenant_option in tenant_list)
                {
                    try
                    {
                        await auth_service.EnsureDeviceRegisteredAsync(tenant_option, stoppingToken).ConfigureAwait(false);
                        var jwt_token = await auth_service.EnsureTokenAsync(tenant_option, stoppingToken).ConfigureAwait(false);
                        _logger.LogDebug("Tenant {TenantId} token cached {TokenLength}", tenant_option.TenantId, jwt_token.Length);
                        await auth_service.IsAuthorizedAsync(tenant_option, stoppingToken).ConfigureAwait(false);
                    }
                    catch (Exception auth_error) when (!stoppingToken.IsCancellationRequested)
                    {
                        _logger.LogError(auth_error, "Failed lifecycle operation for tenant {TenantId}", tenant_option.TenantId);
                        auth_service.InvalidateToken(tenant_option.TenantId);
                    }
                }
            }
            catch (Exception iteration_error) when (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogError(iteration_error, "Tenant lifecycle iteration failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken).ConfigureAwait(false);
            }
            catch (TaskCanceledException)
            {
                // ignore
            }
        }
    }
}
