using Microsoft.Extensions.Options;
using SepidarGateway.Configuration;

namespace SepidarGateway.Tenancy;

public interface ITenantResolver
{
    TenantOptions? Resolve(HttpContext Context);
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
               (_httpContextAccessor.HttpContext?.Items.TryGetValue(TenantKey, out var TenantValue) == true
                   ? TenantValue as TenantContext
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

    public TenantOptions? Resolve(HttpContext Context)
    {
        var GatewayOptions = _optionsMonitor.CurrentValue;
        foreach (var TenantOption in GatewayOptions.Tenants)
        {
            if (IsMatch(TenantOption, Context))
            {
                return TenantOption;
            }
        }

        return null;
    }

    private static bool IsMatch(TenantOptions Tenant, HttpContext Context)
    {
        var TenantMatch = Tenant.Match;
        if (TenantMatch.Hostnames is { Length: > 0 })
        {
            var RequestHost = Context.Request.Host.Host;
            if (!TenantMatch.Hostnames.Any(Hostname => string.Equals(Hostname, RequestHost, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        if (TenantMatch.Header is { } HeaderRule &&
            !string.IsNullOrWhiteSpace(HeaderRule.HeaderName) &&
            HeaderRule.HeaderValues is { Length: > 0 })
        {
            if (!Context.Request.Headers.TryGetValue(HeaderRule.HeaderName, out var HeaderValueSpan))
            {
                return false;
            }

            var HeaderValues = HeaderValueSpan.ToArray();
            var RequestValues = HeaderValues.Length == 0
                ? Array.Empty<string>()
                : HeaderValues
                    .Select(Value => Value?.Trim())
                    .Where(Value => !string.IsNullOrWhiteSpace(Value))
                    .Select(Value => Value!)
                    .ToArray();
            if (!HeaderRule.HeaderValues.Any(Expected =>
                    RequestValues.Any(Actual => string.Equals(Actual, Expected, StringComparison.OrdinalIgnoreCase))))
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(TenantMatch.PathBase) && TenantMatch.PathBase != "/" && Context.Request.Path.HasValue)
        {
            if (!Context.Request.Path.StartsWithSegments(TenantMatch.PathBase, out var PathRemaining))
            {
                return false;
            }

            Context.Request.PathBase = TenantMatch.PathBase;
            Context.Request.Path = PathRemaining;
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

    public async Task InvokeAsync(HttpContext Context)
    {
        if (ShouldBypassTenantResolution(Context))
        {
            _accessor.CurrentTenant = null;
            await _next(Context);
            return;
        }

        var TenantOption = _resolver.Resolve(Context);
        if (TenantOption == null)
        {
            Context.Response.StatusCode = StatusCodes.Status404NotFound;
            await Context.Response.WriteAsync("Tenant not found");
            return;
        }

        var TenantContext = new TenantContext(TenantOption);
        _accessor.CurrentTenant = TenantContext;

        using (_logger.BeginScope(new Dictionary<string, object>
               {
                   ["TenantId"] = TenantOption.TenantId
               }))
        {
            await _next(Context);
        }
    }

    private static bool ShouldBypassTenantResolution(HttpContext Context)
    {
        var RequestPath = Context.Request.Path;
        if (!RequestPath.HasValue)
        {
            return false;
        }

        if (RequestPath.Equals("/", StringComparison.Ordinal))
        {
            return true;
        }

        if (RequestPath.Equals("/favicon.ico", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (RequestPath.StartsWithSegments("/swagger", StringComparison.OrdinalIgnoreCase, out _))
        {
            return true;
        }

        if (RequestPath.StartsWithSegments("/health", StringComparison.OrdinalIgnoreCase, out _))
        {
            return true;
        }

        return false;
    }
}
