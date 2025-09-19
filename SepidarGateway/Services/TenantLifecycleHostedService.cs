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
                var TenantList = _optionsMonitor.CurrentValue.Tenants.ToList();
                using var TenantScope = _scopeFactory.CreateScope();
                var AuthService = TenantScope.ServiceProvider.GetRequiredService<ISepidarAuth>();

                foreach (var TenantOption in TenantList)
                {
                    try
                    {
                        await AuthService.EnsureDeviceRegisteredAsync(TenantOption, StoppingToken).ConfigureAwait(false);
                        var JwtToken = await AuthService.EnsureTokenAsync(TenantOption, StoppingToken).ConfigureAwait(false);
                        _logger.LogDebug("Tenant {TenantId} token cached {TokenLength}", TenantOption.TenantId, JwtToken.Length);
                        await AuthService.IsAuthorizedAsync(TenantOption, StoppingToken).ConfigureAwait(false);
                    }
                    catch (Exception AuthError) when (!StoppingToken.IsCancellationRequested)
                    {
                        _logger.LogError(AuthError, "Failed lifecycle operation for tenant {TenantId}", TenantOption.TenantId);
                        AuthService.InvalidateToken(TenantOption.TenantId);
                    }
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
