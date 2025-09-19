using SepidarGateway.Tenancy;

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

    public async Task InvokeAsync(HttpContext context, ITenantContextAccessor tenant_accessor)
    {
        var tenant_context = tenant_accessor.CurrentTenant;
        if (tenant_context?.Options.Clients?.ApiKeys is { Length: > 0 })
        {
            if (!context.Request.Headers.TryGetValue("X-API-Key", out var api_key_value) ||
                string.IsNullOrWhiteSpace(api_key_value))
            {
                _logger.LogWarning("Missing API key for tenant {TenantId}", tenant_context.Options.TenantId);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Missing API key");
                return;
            }

            if (!tenant_context.Options.Clients.ApiKeys.Any(configured_key =>
                    string.Equals(configured_key, api_key_value.ToString(), StringComparison.Ordinal)))
            {
                _logger.LogWarning("Invalid API key for tenant {TenantId}", tenant_context.Options.TenantId);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Invalid API key");
                return;
            }
        }

        await _next(context);
    }
}
