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

    public Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
    {
        var tenant = _tenantAccessor.CurrentTenant?.Options;
        var builder = new CorsPolicyBuilder();

        if (tenant?.Cors?.AllowedOrigins is { Length: > 0 })
        {
            builder.WithOrigins(tenant.Cors.AllowedOrigins);
        }
        else
        {
            builder.AllowAnyOrigin();
        }

        if (tenant?.Cors?.AllowedHeaders is { Length: > 0 })
        {
            builder.WithHeaders(tenant.Cors.AllowedHeaders);
        }
        else
        {
            builder.AllowAnyHeader();
        }

        if (tenant?.Cors?.AllowedMethods is { Length: > 0 })
        {
            builder.WithMethods(tenant.Cors.AllowedMethods);
        }
        else
        {
            builder.AllowAnyMethod();
        }

        if (tenant?.Cors?.AllowCredentials == true)
        {
            builder.AllowCredentials();
        }

        var policy = builder.Build();
        if (tenant is not null)
        {
            _logger.LogDebug("Applied CORS policy for tenant {TenantId}", tenant.TenantId);
        }
        return Task.FromResult<CorsPolicy?>(policy);
    }
}
