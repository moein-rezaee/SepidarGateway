using System.Net;
using System.Net.Http;
using System.Text.Json;
using FluentAssertions;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;
using Xunit;

namespace SepidarGateway.Tests.Auth;

public class SepidarAuthServiceTests
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task EnsureTokenAsync_CachesTokenAndRegistersOnce()
    {
        var tenant = CreateTenant();
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var crypto = new SepidarCryptoService();
        var registerCrypto = new
        {
            RsaPublicKeyXml = (string?)null,
            RsaModulusBase64 = Convert.ToBase64String(rsa.ExportParameters(false).Modulus!),
            RsaExponentBase64 = Convert.ToBase64String(rsa.ExportParameters(false).Exponent!)
        };
        var encryptedRegister = crypto.EncryptRegisterPayload(tenant.Sepidar.DeviceSerial, JsonSerializer.Serialize(registerCrypto, SerializerOptions));

        var handler = new StubHandler(message =>
        {
            var path = message.RequestUri!.AbsolutePath;
            if (path.EndsWith("/api/Devices/Register/", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse(new
                {
                    Cypher = encryptedRegister.CipherText,
                    IV = encryptedRegister.IvBase64
                });
            }

            if (path.EndsWith("/api/users/login/", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse(new
                {
                    Token = "cached-token",
                    ExpiresIn = 120
                });
            }

            if (path.EndsWith("/api/IsAuthorized/", StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("true")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var factory = new StubClientFactory(handler);
        var logger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<SepidarAuthService>();
        var service = new SepidarAuthService(factory, crypto, logger);

        var token1 = await service.EnsureTokenAsync(tenant, CancellationToken.None);
        var token2 = await service.EnsureTokenAsync(tenant, CancellationToken.None);

        token1.Should().Be("cached-token");
        token2.Should().Be(token1);
        handler.CountRequests("/api/users/login/").Should().Be(1);
        handler.CountRequests("/api/Devices/Register/").Should().Be(1);

        var authorized = await service.IsAuthorizedAsync(tenant, CancellationToken.None);
        authorized.Should().BeTrue();
        handler.CountRequests("/api/IsAuthorized/").Should().Be(1);
    }

    private static TenantOptions CreateTenant() => new()
    {
        TenantId = "t1",
        Sepidar = new SepidarEndpointOptions
        {
            BaseUrl = "http://localhost:7777",
            IntegrationId = "123",
            DeviceSerial = "SERIAL",
            GenerationVersion = "1.0.0"
        },
        Credentials = new TenantCredentialOptions
        {
            UserName = "user",
            PasswordMd5 = "0123456789ABCDEF0123456789ABCDEF"
        },
        Jwt = new TenantJwtOptions
        {
            CacheSeconds = 300,
            PreAuthCheckSeconds = 0
        },
        Limits = new TenantLimitOptions
        {
            RequestTimeoutSeconds = 30
        }
    };

    private static HttpResponseMessage JsonResponse(object payload)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload, SerializerOptions))
        };
    }

    private sealed class StubClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public StubClientFactory(HttpMessageHandler handler)
        {
            _handler = handler;
        }

        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        private readonly List<HttpRequestMessage> _requests = new();

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        public int CountRequests(string pathContains) => _requests.Count(r => r.RequestUri!.AbsolutePath.Contains(pathContains, StringComparison.OrdinalIgnoreCase));

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _requests.Add(request);
            return Task.FromResult(_responder(request));
        }
    }
}
