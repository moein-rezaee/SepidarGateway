using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SepidarGateway.Configuration;
using SepidarGateway.Tenancy;
using Xunit;

namespace SepidarGateway.Tests;

public class TenantResolverTests
{
    [Fact]
    public void Resolve_ReturnsTenantWhenAllMatchersPass()
    {
        var tenant = new TenantOptions
        {
            TenantId = "main",
            Match = new TenantMatchOptions
            {
                Hostnames = new[] { "gateway.internal" },
                Header = new TenantHeaderMatchOptions
                {
                    HeaderName = "X-Tenant-ID",
                    HeaderValues = new[] { "main" }
                },
                PathBase = "/t/main"
            },
            Sepidar = new SepidarEndpointOptions
            {
                BaseUrl = "http://example", IntegrationId = "1", DeviceSerial = "1", GenerationVersion = "101"
            }
        };

        var options = new GatewayOptions { Tenants = new List<TenantOptions> { tenant } };
        var resolver = new TenantResolver(new StaticOptionsMonitor(options));

        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("gateway.internal");
        context.Request.Path = "/t/main/api/Customers";
        context.Request.Headers["X-Tenant-ID"] = "main";

        var resolved = resolver.Resolve(context);
        Assert.NotNull(resolved);
        Assert.Equal(tenant, resolved);
        Assert.Equal("/t/main", context.Request.PathBase.Value);
        Assert.Equal("/api/Customers", context.Request.Path.Value);
    }

    [Fact]
    public void Resolve_ReturnsNullWhenHostDoesNotMatch()
    {
        var tenant = new TenantOptions
        {
            TenantId = "main",
            Match = new TenantMatchOptions
            {
                Hostnames = new[] { "gateway.internal" }
            },
            Sepidar = new SepidarEndpointOptions
            {
                BaseUrl = "http://example", IntegrationId = "1", DeviceSerial = "1", GenerationVersion = "101"
            }
        };

        var options = new GatewayOptions { Tenants = new List<TenantOptions> { tenant } };
        var resolver = new TenantResolver(new StaticOptionsMonitor(options));

        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("other.host");

        var resolved = resolver.Resolve(context);
        Assert.Null(resolved);
    }

    private sealed class StaticOptionsMonitor : IOptionsMonitor<GatewayOptions>
    {
        public StaticOptionsMonitor(GatewayOptions value)
        {
            CurrentValue = value;
        }

        public GatewayOptions CurrentValue { get; }

        public GatewayOptions Get(string? name) => CurrentValue;

        public IDisposable OnChange(Action<GatewayOptions, string?> listener) => new NoopDisposable();

        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }
}
