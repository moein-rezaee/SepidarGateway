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
               (_httpContextAccessor.HttpContext?.Items.TryGetValue(TenantKey, out var tenant_value) == true
                   ? tenant_value as TenantContext
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
        var gateway_options = _optionsMonitor.CurrentValue;
        foreach (var tenant_option in gateway_options.Tenants)
        {
            if (IsMatch(tenant_option, context))
            {
                return tenant_option;
            }
        }

        return null;
    }

    private static bool IsMatch(TenantOptions tenant, HttpContext context)
    {
        var tenant_match = tenant.Match;
        if (tenant_match.Hostnames is { Length: > 0 })
        {
            var request_host = context.Request.Host.Host;
            if (!tenant_match.Hostnames.Any(h => string.Equals(h, request_host, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        if (tenant_match.Header is { } header_rule &&
            !string.IsNullOrWhiteSpace(header_rule.HeaderName) &&
            header_rule.HeaderValues is { Length: > 0 })
        {
            if (!context.Request.Headers.TryGetValue(header_rule.HeaderName, out var header_value_span))
            {
                return false;
            }

            var header_values = header_value_span.ToArray();
            var request_values = header_values.Length == 0
                ? Array.Empty<string>()
                : header_values
                    .Select(v => v?.Trim())
                    .Where(v => !string.IsNullOrWhiteSpace(v))
                    .Select(v => v!)
                    .ToArray();
            if (!header_rule.HeaderValues.Any(expected =>
                    request_values.Any(actual => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))))
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(tenant_match.PathBase) && tenant_match.PathBase != "/" && context.Request.Path.HasValue)
        {
            if (!context.Request.Path.StartsWithSegments(tenant_match.PathBase, out var path_remaining))
            {
                return false;
            }

            context.Request.PathBase = tenant_match.PathBase;
            context.Request.Path = path_remaining;
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
        var tenant_option = _resolver.Resolve(context);
        if (tenant_option == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Tenant not found");
            return;
        }

        var tenant_context = new TenantContext(tenant_option);
        _accessor.CurrentTenant = tenant_context;

        using (_logger.BeginScope(new Dictionary<string, object>
               {
                   ["TenantId"] = tenant_option.TenantId
               }))
        {
            await _next(context);
        }
    }
}
