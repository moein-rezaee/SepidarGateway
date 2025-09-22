using Microsoft.Extensions.Options;
using SepidarGateway.Configuration;

namespace SepidarGateway.Middleware;

public sealed class ClientAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ClientAuthorizationMiddleware> _logger;

    public ClientAuthorizationMiddleware(RequestDelegate next, ILogger<ClientAuthorizationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext Context, IOptionsMonitor<GatewayOptions> optionsMonitor)
    {
        var TenantOptions = optionsMonitor.CurrentValue.Tenant;
        if (TenantOptions?.Clients?.ApiKeys is { Length: > 0 })
        {
            if (!Context.Request.Headers.TryGetValue("X-API-Key", out var ApiKeyValue) ||
                string.IsNullOrWhiteSpace(ApiKeyValue))
            {
                _logger.LogWarning("Missing API key for tenant {TenantId}", TenantOptions.TenantId);
                Context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await Context.Response.WriteAsync("Missing API key");
                return;
            }

            if (!TenantOptions.Clients.ApiKeys.Any(ConfiguredKey =>
                    string.Equals(ConfiguredKey, ApiKeyValue.ToString(), StringComparison.Ordinal)))
            {
                _logger.LogWarning("Invalid API key for tenant {TenantId}", TenantOptions.TenantId);
                Context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await Context.Response.WriteAsync("Invalid API key");
                return;
            }
        }

        await _next(Context);
    }
}
