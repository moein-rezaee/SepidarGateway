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
        var tenant_options = _tenantAccessor.CurrentTenant?.Options;
        var cors_builder = new CorsPolicyBuilder();

        if (tenant_options?.Cors?.AllowedOrigins is { Length: > 0 })
        {
            cors_builder.WithOrigins(tenant_options.Cors.AllowedOrigins);
        }
        else
        {
            cors_builder.AllowAnyOrigin();
        }

        if (tenant_options?.Cors?.AllowedHeaders is { Length: > 0 })
        {
            cors_builder.WithHeaders(tenant_options.Cors.AllowedHeaders);
        }
        else
        {
            cors_builder.AllowAnyHeader();
        }

        if (tenant_options?.Cors?.AllowedMethods is { Length: > 0 })
        {
            cors_builder.WithMethods(tenant_options.Cors.AllowedMethods);
        }
        else
        {
            cors_builder.AllowAnyMethod();
        }

        if (tenant_options?.Cors?.AllowCredentials == true)
        {
            cors_builder.AllowCredentials();
        }

        var cors_policy = cors_builder.Build();
        if (tenant_options is not null)
        {
            _logger.LogDebug("Applied CORS policy for tenant {TenantId}", tenant_options.TenantId);
        }
        return Task.FromResult<CorsPolicy?>(cors_policy);
    }
}
