using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SepidarGateway.Configuration;
using SepidarGateway.Tenancy;
using Xunit;

namespace SepidarGateway.Tests.Tenancy;

public class TenantResolverTests
{
    [Fact]
    public void Resolve_ByHeaderAndPathBase_ReturnsTenant()
    {
        var options = new GatewayOptions
        {
            Tenants =
            {
                new TenantOptions
                {
                    TenantId = "one",
                    Match = new TenantMatchOptions
                    {
                        Header = new TenantHeaderMatchOptions
                        {
                            HeaderName = "X-Tenant-ID",
                            HeaderValues = new[] { "one" }
                        },
                        PathBase = "/t/one"
                    }
                }
            }
        };

        var resolver = new TenantResolver(new StaticOptionsMonitor<GatewayOptions>(options));
        var context = new DefaultHttpContext();
        context.Request.Path = "/t/one/api/items";
        context.Request.Headers["X-Tenant-ID"] = "one";

        var tenant = resolver.Resolve(context);
        tenant.Should().NotBeNull();
        tenant!.TenantId.Should().Be("one");
        context.Request.PathBase.Value.Should().Be("/t/one");
        context.Request.Path.Value.Should().Be("/api/items");
    }

    [Fact]
    public void Resolve_InvalidHeader_ReturnsNull()
    {
        var options = new GatewayOptions
        {
            Tenants =
            {
                new TenantOptions
                {
                    TenantId = "one",
                    Match = new TenantMatchOptions
                    {
                        Header = new TenantHeaderMatchOptions
                        {
                            HeaderName = "X-Tenant-ID",
                            HeaderValues = new[] { "one" }
                        }
                    }
                }
            }
        };

        var resolver = new TenantResolver(new StaticOptionsMonitor<GatewayOptions>(options));
        var context = new DefaultHttpContext();
        var tenant = resolver.Resolve(context);
        tenant.Should().BeNull();
    }
}

file class StaticOptionsMonitor<T> : IOptionsMonitor<T>
{
    private readonly T _value;

    public StaticOptionsMonitor(T value)
    {
        _value = value;
    }

    public T CurrentValue => _value;

    public T Get(string? name) => _value;

    public IDisposable OnChange(Action<T, string?> listener) => NullDisposable.Instance;

    private sealed class NullDisposable : IDisposable
    {
        public static readonly NullDisposable Instance = new();

        public void Dispose()
        {
        }
    }
}
