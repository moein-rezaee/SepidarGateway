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

    protected override async Task ExecuteAsync(CancellationToken StoppingToken)
    {
        while (!StoppingToken.IsCancellationRequested)
        {
            try
            {
                var tenant = _optionsMonitor.CurrentValue.Tenant;
                using var TenantScope = _scopeFactory.CreateScope();
                var AuthService = TenantScope.ServiceProvider.GetRequiredService<ISepidarAuth>();
                try
                {
                    await AuthService.EnsureDeviceRegisteredAsync(tenant, StoppingToken).ConfigureAwait(false);
                    var JwtToken = await AuthService.EnsureTokenAsync(tenant, StoppingToken).ConfigureAwait(false);
                    _logger.LogDebug("Tenant {TenantId} token cached {TokenLength}", tenant.TenantId, JwtToken.Length);
                    await AuthService.IsAuthorizedAsync(tenant, StoppingToken).ConfigureAwait(false);
                }
                catch (Exception AuthError) when (!StoppingToken.IsCancellationRequested)
                {
                    _logger.LogError(AuthError, "Failed lifecycle operation for tenant {TenantId}", tenant.TenantId);
                    AuthService.InvalidateToken(tenant.TenantId);
                }
            }
            catch (Exception IterationError) when (!StoppingToken.IsCancellationRequested)
            {
                _logger.LogError(IterationError, "Tenant lifecycle iteration failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(60), StoppingToken).ConfigureAwait(false);
            }
            catch (TaskCanceledException)
            {
                // ignore
            }
        }
    }
}
