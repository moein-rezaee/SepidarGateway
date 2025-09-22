using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;
using SepidarGateway.Configuration;

namespace SepidarGateway.Middleware;

public sealed class TenantCorsPolicyProvider : ICorsPolicyProvider
{
    private readonly IOptionsMonitor<GatewayOptions> _options;
    private readonly ILogger<TenantCorsPolicyProvider> _logger;

    public TenantCorsPolicyProvider(IOptionsMonitor<GatewayOptions> options, ILogger<TenantCorsPolicyProvider> logger)
    {
        _options = options;
        _logger = logger;
    }

    public Task<CorsPolicy?> GetPolicyAsync(HttpContext Context, string? PolicyName)
    {
        var TenantOptions = _options.CurrentValue.Tenant;
        var CorsBuilder = new CorsPolicyBuilder();

        if (TenantOptions?.Cors?.AllowedOrigins is { Length: > 0 })
        {
            CorsBuilder.WithOrigins(TenantOptions.Cors.AllowedOrigins);
        }
        else
        {
            CorsBuilder.AllowAnyOrigin();
        }

        if (TenantOptions?.Cors?.AllowedHeaders is { Length: > 0 })
        {
            CorsBuilder.WithHeaders(TenantOptions.Cors.AllowedHeaders);
        }
        else
        {
            CorsBuilder.AllowAnyHeader();
        }

        if (TenantOptions?.Cors?.AllowedMethods is { Length: > 0 })
        {
            CorsBuilder.WithMethods(TenantOptions.Cors.AllowedMethods);
        }
        else
        {
            CorsBuilder.AllowAnyMethod();
        }

        if (TenantOptions?.Cors?.AllowCredentials == true)
        {
            CorsBuilder.AllowCredentials();
        }

        var CorsPolicy = CorsBuilder.Build();
        if (TenantOptions is not null)
        {
            _logger.LogDebug("Applied CORS policy for tenant {TenantId}", TenantOptions.TenantId);
        }
        return Task.FromResult<CorsPolicy?>(CorsPolicy);
    }
}
