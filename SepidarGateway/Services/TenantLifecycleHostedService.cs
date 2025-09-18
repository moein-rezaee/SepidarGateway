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
                var tenants = _optionsMonitor.CurrentValue.Tenants.ToList();
                using var scope = _scopeFactory.CreateScope();
                var auth = scope.ServiceProvider.GetRequiredService<ISepidarAuth>();

                foreach (var tenant in tenants)
                {
                    try
                    {
                        await auth.EnsureDeviceRegisteredAsync(tenant, stoppingToken).ConfigureAwait(false);
                        var token = await auth.EnsureTokenAsync(tenant, stoppingToken).ConfigureAwait(false);
                        _logger.LogDebug("Tenant {TenantId} token cached {TokenLength}", tenant.TenantId, token.Length);
                        await auth.IsAuthorizedAsync(tenant, stoppingToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
                    {
                        _logger.LogError(ex, "Failed lifecycle operation for tenant {TenantId}", tenant.TenantId);
                        auth.InvalidateToken(tenant.TenantId);
                    }
                }
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogError(ex, "Tenant lifecycle iteration failed");
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
