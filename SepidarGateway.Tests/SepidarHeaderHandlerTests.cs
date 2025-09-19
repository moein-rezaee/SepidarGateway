using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;
using SepidarGateway.Handlers;
using SepidarGateway.Observability;
using SepidarGateway.Tenancy;
using Xunit;

namespace SepidarGateway.Tests;

public class SepidarHeaderHandlerTests
{
    [Fact]
    public async Task SendAsync_RewritesUriAndInjectsHeaders()
    {
        var tenantOptions = BuildTenantOptions();
        var tenantContextAccessor = new TestTenantContextAccessor
        {
            CurrentTenant = new TenantContext(tenantOptions)
        };

        var auth = new StubSepidarAuth();
        var crypto = new SepidarCryptoService();
        using var loggerFactory = LoggerFactory.Create(builder => builder.SetMinimumLevel(LogLevel.Debug));
        var logger = loggerFactory.CreateLogger<SepidarHeaderHandler>();
        var httpContextAccessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext()
        };
        httpContextAccessor.HttpContext!.Items[CorrelationIdMiddleware.HeaderName] = "corr-id";

        var recordingHandler = new RecordingHandler();
        var handler = new SepidarHeaderHandler(tenantContextAccessor, auth, crypto, logger, httpContextAccessor)
        {
            InnerHandler = recordingHandler
        };

        using var invoker = new HttpMessageInvoker(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://gateway.internal/api/Customers");
        var response = await invoker.SendAsync(request, CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(recordingHandler.LastRequest);
        Assert.Equal(new Uri("http://sepidar.local:7373/api/Customers?api-version=101"), recordingHandler.LastRequest!.RequestUri);

        var headers = recordingHandler.LastRequest.Headers;
        Assert.Equal("101", headers.GetValues("GenerationVersion").Single());
        Assert.Equal("integration", headers.GetValues("IntegrationID").Single());
        Assert.Equal("101", headers.GetValues("api-version").Single());
        Assert.True(headers.Contains("ArbitraryCode"));
        Assert.True(headers.Contains("EncArbitraryCode"));
        Assert.Equal("Bearer", headers.Authorization?.Scheme);
        Assert.Equal("stub-token", headers.Authorization?.Parameter);
        Assert.Equal("corr-id", headers.GetValues(CorrelationIdMiddleware.HeaderName).Single());
    }

    private static TenantOptions BuildTenantOptions()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);

        return new TenantOptions
        {
            TenantId = "MAIN",
            Sepidar = new SepidarEndpointOptions
            {
                BaseUrl = "http://sepidar.local:7373",
                IntegrationId = "integration",
                DeviceSerial = "serial",
                GenerationVersion = "101",
                ApiVersion = "101"
            },
            Credentials = new TenantCredentialOptions
            {
                UserName = "user",
                Password = "password"
            },
            Crypto = new TenantCryptoOptions
            {
                RsaModulusBase64 = Convert.ToBase64String(parameters.Modulus!),
                RsaExponentBase64 = Convert.ToBase64String(parameters.Exponent!)
            },
            Limits = new TenantLimitOptions
            {
                RequestTimeoutSeconds = 30
            }
        };
    }

    private sealed class StubSepidarAuth : ISepidarAuth
    {
        public Task EnsureDeviceRegisteredAsync(TenantOptions tenant, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<string> EnsureTokenAsync(TenantOptions tenant, CancellationToken cancellationToken) => Task.FromResult("stub-token");

        public Task<bool> IsAuthorizedAsync(TenantOptions tenant, CancellationToken cancellationToken) => Task.FromResult(true);

        public void InvalidateToken(string tenantId)
        {
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class TestTenantContextAccessor : ITenantContextAccessor
    {
        public TenantContext? CurrentTenant { get; set; }
    }
}
