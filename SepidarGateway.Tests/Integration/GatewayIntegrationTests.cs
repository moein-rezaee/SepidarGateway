using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;
using SepidarGateway.Handlers;
using SepidarGateway.Observability;
using SepidarGateway.Tenancy;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace SepidarGateway.Tests.Integration;

public class GatewayIntegrationTests : IAsyncLifetime
{
    private readonly WireMockServer _server;
    private readonly SepidarCryptoService _crypto = new();

    public GatewayIntegrationTests()
    {
        _server = WireMockServer.Start();
    }

    public Task InitializeAsync()
    {
        ConfigureSepidarStubs();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _server.Stop();
        _server.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task HeaderHandler_ForwardsRequestsWithRequiredHeaders()
    {
        var tenant = CreateTenant();
        var httpClientFactory = new StubClientFactory();
        var authLogger = NullLogger<SepidarAuthService>.Instance;
        var authService = new SepidarAuthService(httpClientFactory, _crypto, authLogger);
        await authService.EnsureDeviceRegisteredAsync(tenant, CancellationToken.None);

        var httpContext = new DefaultHttpContext();
        httpContext.Items[CorrelationIdMiddleware.HeaderName] = Guid.NewGuid().ToString();
        var httpContextAccessor = new HttpContextAccessor { HttpContext = httpContext };
        var tenantAccessor = new TenantContextAccessor(httpContextAccessor)
        {
            CurrentTenant = new TenantContext(tenant)
        };

        var handlerLogger = NullLogger<SepidarHeaderHandler>.Instance;
        var handler = new SepidarHeaderHandler(tenantAccessor, authService, _crypto, handlerLogger, httpContextAccessor)
        {
            InnerHandler = new HttpClientHandler()
        };

        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(new Uri(tenant.Sepidar.BaseUrl), "/api/Customers"));
        var response = await invoker.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();

        var customers = await response.Content.ReadFromJsonAsync<List<TestCustomer>>();
        customers.Should().NotBeNull();
        customers!.Should().HaveCount(1);

        var forwarded = _server
            .FindLogEntries(Request.Create().WithPath("/api/Customers"))
            .Should().ContainSingle().Subject;

        forwarded.RequestMessage.Headers.Should().ContainKey("GenerationVersion");
        forwarded.RequestMessage.Headers.Should().ContainKey("IntegrationID");
        forwarded.RequestMessage.Headers.Should().ContainKey("ArbitraryCode");
        forwarded.RequestMessage.Headers.Should().ContainKey("EncArbitraryCode");
        forwarded.RequestMessage.Headers.Should().ContainKey("Authorization");
        forwarded.RequestMessage.Headers["Authorization"].Should().ContainSingle(h => h.StartsWith("Bearer", StringComparison.OrdinalIgnoreCase));
    }

    private TenantOptions CreateTenant()
    {
        var baseUrl = _server.Urls.First();
        return new TenantOptions
        {
            TenantId = "test",
            Sepidar = new SepidarEndpointOptions
            {
                BaseUrl = baseUrl,
                IntegrationId = "123",
                DeviceSerial = "SERIAL",
                GenerationVersion = "1.0.0"
            },
            Credentials = new TenantCredentialOptions
            {
                UserName = "gateway",
                PasswordMd5 = "0123456789ABCDEF0123456789ABCDEF"
            },
            Jwt = new TenantJwtOptions
            {
                CacheSeconds = 600,
                PreAuthCheckSeconds = 0
            },
            Limits = new TenantLimitOptions
            {
                RequestTimeoutSeconds = 30
            },
            Clients = new TenantClientOptions
            {
                ApiKeys = new[] { "integration-key" }
            }
        };
    }

    private void ConfigureSepidarStubs()
    {
        var rsa = System.Security.Cryptography.RSA.Create(2048);
        var registerPayload = new
        {
            RsaPublicKeyXml = (string?)null,
            RsaModulusBase64 = Convert.ToBase64String(rsa.ExportParameters(false).Modulus!),
            RsaExponentBase64 = Convert.ToBase64String(rsa.ExportParameters(false).Exponent!)
        };
        var encrypted = _crypto.EncryptRegisterPayload("SERIAL", System.Text.Json.JsonSerializer.Serialize(registerPayload));

        _server
            .Given(Request.Create().WithPath("/api/Devices/Register/").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new
            {
                Cypher = encrypted.CipherText,
                IV = encrypted.IvBase64
            }));

        _server
            .Given(Request.Create().WithPath("/api/users/login/").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new
            {
                Token = "integration-token",
                ExpiresIn = 600
            }));

        _server
            .Given(Request.Create().WithPath("/api/IsAuthorized/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody("true"));

        _server
            .Given(Request.Create().WithPath("/api/Customers").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new[]
            {
                new TestCustomer(1, "Acme")
            }));
    }

    private sealed record TestCustomer(int Id, string Name);

    private sealed class StubClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }
}
