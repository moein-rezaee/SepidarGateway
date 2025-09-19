using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.Logging;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;
using Xunit;

namespace SepidarGateway.Tests;

public class SepidarAuthServiceTests
{
    [Fact]
    public async Task Register_UsesHeadersWithoutAppendingQueryParameters()
    {
        var registerHandler = new RegisterHandler();
        var httpClientFactory = new SingleClientFactory(new HttpClient(registerHandler));
        using var loggerFactory = LoggerFactory.Create(builder => builder.SetMinimumLevel(LogLevel.Debug));
        var logger = loggerFactory.CreateLogger<SepidarAuthService>();
        var crypto = new StubCrypto();
        var service = new SepidarAuthService(httpClientFactory, crypto, logger);

        var tenant = new TenantOptions
        {
            TenantId = "MAIN",
            Sepidar = new SepidarEndpointOptions
            {
                BaseUrl = "http://example.org:7373",
                IntegrationId = "integration",
                DeviceSerial = "serial",
                GenerationVersion = "101",
                ApiVersion = "101",
                RegisterPath = "api/Devices/Register/",
                RegisterFallbackPaths = Array.Empty<string>()
            },
            Credentials = new TenantCredentialOptions
            {
                UserName = "user",
                Password = "password"
            },
            Crypto = new TenantCryptoOptions(),
            Jwt = new TenantJwtOptions(),
            Limits = new TenantLimitOptions
            {
                RequestTimeoutSeconds = 30
            }
        };

        await service.EnsureDeviceRegisteredAsync(tenant, CancellationToken.None);

        Assert.Single(registerHandler.Requests);
        var request = registerHandler.Requests[0];
        Assert.Equal("http://example.org:7373/api/Devices/Register/", request.RequestUri!.ToString());
        Assert.Equal(string.Empty, request.RequestUri!.Query);
        Assert.Equal("101", request.Headers.GetValues("api-version").Single());
        Assert.Equal("101", request.Headers.GetValues("GenerationVersion").Single());
        Assert.Equal("integration", request.Headers.GetValues("IntegrationID").Single());

        Assert.Equal(StubCrypto.Modulus, tenant.Crypto.RsaModulusBase64);
        Assert.Equal(StubCrypto.Exponent, tenant.Crypto.RsaExponentBase64);
        Assert.Contains("Exponent", tenant.Crypto.RsaPublicKeyXml, StringComparison.Ordinal);
    }

    private sealed class SingleClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;

        public SingleClientFactory(HttpClient client)
        {
            _client = client;
        }

        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class RegisterHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            Assert.Equal(string.Empty, request.RequestUri?.Query);

            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"Cypher\":\"cipher\",\"IV\":\"iv\"}", Encoding.UTF8, "application/json")
            };

            return Task.FromResult(response);
        }
    }

    private sealed class StubCrypto : ISepidarCrypto
    {
        public const string Modulus = "AQID";
        public const string Exponent = "AQAB";

        public (string CipherText, string IvBase64) EncryptRegisterPayload(string serialSeed, string payload)
            => ("cipher", "iv");

        public string DecryptRegisterPayload(string serialSeed, string cipherTextBase64, string ivBase64)
            => $"{{\"RsaPublicKeyXml\":\"<RSAKeyValue><Modulus>{Modulus}</Modulus><Exponent>{Exponent}</Exponent></RSAKeyValue>\",\"RsaModulusBase64\":\"{Modulus}\",\"RsaExponentBase64\":\"{Exponent}\"}}";

        public string EncryptArbitraryCode(string arbitraryCode, TenantCryptoOptions cryptoOptions) => "enc";
    }
}
