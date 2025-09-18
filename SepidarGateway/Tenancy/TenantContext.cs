using Microsoft.Extensions.Options;
using SepidarGateway.Configuration;

namespace SepidarGateway.Tenancy;

public interface ITenantResolver
{
    TenantOptions? Resolve(HttpContext context);
}

public sealed class TenantContext
{
    public TenantContext(TenantOptions options)
    {
        Options = options;
    }

    public TenantOptions Options { get; }
}

public interface ITenantContextAccessor
{
    TenantContext? CurrentTenant { get; set; }
}

internal sealed class TenantContextAccessor : ITenantContextAccessor
{
    private static readonly object TenantKey = new();
    private readonly IHttpContextAccessor _httpContextAccessor;

    public TenantContextAccessor(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public TenantContext? CurrentTenant
    {
        get => _currentTenant ??
               (_httpContextAccessor.HttpContext?.Items.TryGetValue(TenantKey, out var value) == true
                   ? value as TenantContext
                   : null);
        set
        {
            _currentTenant = value;
            if (_httpContextAccessor.HttpContext != null)
            {
                _httpContextAccessor.HttpContext.Items[TenantKey] = value!;
            }
        }
    }

    private TenantContext? _currentTenant;
}

internal sealed class TenantResolver : ITenantResolver
{
    private readonly IOptionsMonitor<GatewayOptions> _optionsMonitor;

    public TenantResolver(IOptionsMonitor<GatewayOptions> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }

    public TenantOptions? Resolve(HttpContext context)
    {
        var gatewayOptions = _optionsMonitor.CurrentValue;
        foreach (var tenant in gatewayOptions.Tenants)
        {
            if (IsMatch(tenant, context))
            {
                return tenant;
            }
        }

        return null;
    }

    private static bool IsMatch(TenantOptions tenant, HttpContext context)
    {
        var match = tenant.Match;
        if (match.Hostnames is { Length: > 0 })
        {
            var host = context.Request.Host.Host;
            if (!match.Hostnames.Any(h => string.Equals(h, host, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        if (match.Header is { } header &&
            !string.IsNullOrWhiteSpace(header.HeaderName) &&
            header.HeaderValues is { Length: > 0 })
        {
            if (!context.Request.Headers.TryGetValue(header.HeaderName, out var values))
            {
                return false;
            }

            var headerValues = values.ToArray();
            var requestValues = headerValues.Length == 0
                ? Array.Empty<string>()
                : headerValues
                    .Select(v => v?.Trim())
                    .Where(v => !string.IsNullOrWhiteSpace(v))
                    .Select(v => v!)
                    .ToArray();
            if (!header.HeaderValues.Any(expected =>
                    requestValues.Any(actual => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))))
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(match.PathBase) && match.PathBase != "/" && context.Request.Path.HasValue)
        {
            if (!context.Request.Path.StartsWithSegments(match.PathBase, out var remaining))
            {
                return false;
            }

            context.Request.PathBase = match.PathBase;
            context.Request.Path = remaining;
        }

        return true;
    }
}

public sealed class TenantContextMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ITenantResolver _resolver;
    private readonly ITenantContextAccessor _accessor;
    private readonly ILogger<TenantContextMiddleware> _logger;

    public TenantContextMiddleware(
        RequestDelegate next,
        ITenantResolver resolver,
        ITenantContextAccessor accessor,
        ILogger<TenantContextMiddleware> logger)
    {
        _next = next;
        _resolver = resolver;
        _accessor = accessor;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var tenant = _resolver.Resolve(context);
        if (tenant == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Tenant not found");
            return;
        }

        var tenantContext = new TenantContext(tenant);
        _accessor.CurrentTenant = tenantContext;

        using (_logger.BeginScope(new Dictionary<string, object>
               {
                   ["TenantId"] = tenant.TenantId
               }))
        {
            await _next(context);
        }
    }
}
