using Microsoft.AspNetCore.Cors.Infrastructure;
using SepidarGateway.Tenancy;

namespace SepidarGateway.Middleware;

public sealed class TenantCorsPolicyProvider : ICorsPolicyProvider
{
    private readonly ITenantContextAccessor _tenantAccessor;
    private readonly ILogger<TenantCorsPolicyProvider> _logger;

    public TenantCorsPolicyProvider(ITenantContextAccessor tenantAccessor, ILogger<TenantCorsPolicyProvider> logger)
    {
        _tenantAccessor = tenantAccessor;
        _logger = logger;
    }

    public Task<CorsPolicy?> GetPolicyAsync(HttpContext Context, string? PolicyName)
    {
        var TenantOptions = _tenantAccessor.CurrentTenant?.Options;
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
