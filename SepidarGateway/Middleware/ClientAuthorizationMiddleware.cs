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

    public async Task InvokeAsync(HttpContext context, ITenantContextAccessor tenantAccessor)
    {
        var tenant = tenantAccessor.CurrentTenant;
        if (tenant?.Options.Clients?.ApiKeys is { Length: > 0 })
        {
            if (!context.Request.Headers.TryGetValue("X-API-Key", out var provided) ||
                string.IsNullOrWhiteSpace(provided))
            {
                _logger.LogWarning("Missing API key for tenant {TenantId}", tenant.Options.TenantId);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Missing API key");
                return;
            }

            if (!tenant.Options.Clients.ApiKeys.Any(k => string.Equals(k, provided.ToString(), StringComparison.Ordinal)))
            {
                _logger.LogWarning("Invalid API key for tenant {TenantId}", tenant.Options.TenantId);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Invalid API key");
                return;
            }
        }

        await _next(context);
    }
}
