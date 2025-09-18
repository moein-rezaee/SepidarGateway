using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;

namespace SepidarGateway.Auth;

public sealed class SepidarAuthService : ISepidarAuth
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISepidarCrypto _crypto;
    private readonly ILogger<SepidarAuthService> _logger;
    private readonly ConcurrentDictionary<string, TenantAuthState> _states = new();

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public SepidarAuthService(
        IHttpClientFactory httpClientFactory,
        ISepidarCrypto crypto,
        ILogger<SepidarAuthService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _crypto = crypto;
        _logger = logger;
    }

    public async Task EnsureDeviceRegisteredAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        var state = GetState(tenant.TenantId);
        if (state.Registered)
        {
            return;
        }

        await state.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (state.Registered)
            {
                return;
            }

            await RegisterInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            state.Registered = true;
        }
        finally
        {
            state.Lock.Release();
        }
    }

    public async Task<string> EnsureTokenAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        var state = GetState(tenant.TenantId);
        await EnsureDeviceRegisteredAsync(tenant, cancellationToken).ConfigureAwait(false);

        if (state.Token is { } token && state.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
        {
            return token;
        }

        await state.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (state.Token is { } cached && state.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
            {
                return cached;
            }

            var login = await LoginInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            state.Token = login.Token;
            state.ExpiresAt = login.ExpiresAt;
            return login.Token;
        }
        finally
        {
            state.Lock.Release();
        }
    }

    public async Task<bool> IsAuthorizedAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        var state = GetState(tenant.TenantId);
        if (state.Token is null)
        {
            return false;
        }

        if (state.LastAuthorizationCheck + TimeSpan.FromSeconds(tenant.Jwt.PreAuthCheckSeconds) > DateTimeOffset.UtcNow)
        {
            return true;
        }

        await state.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (state.Token is null)
            {
                return false;
            }

            if (state.LastAuthorizationCheck + TimeSpan.FromSeconds(tenant.Jwt.PreAuthCheckSeconds) > DateTimeOffset.UtcNow)
            {
                return true;
            }

            var client = CreateHttpClient(tenant);
            using var request = new HttpRequestMessage(HttpMethod.Get, BuildTenantUri(tenant, "api/IsAuthorized/"));
            PrepareHeaders(request.Headers, tenant, state.Token);

            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("JWT expired for tenant {TenantId}", tenant.TenantId);
                InvalidateToken(tenant.TenantId);
                return false;
            }

            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var authorized = bool.TryParse(content, out var parsed) ? parsed : content.Contains("true", StringComparison.OrdinalIgnoreCase);
            state.LastAuthorizationCheck = DateTimeOffset.UtcNow;
            if (!authorized)
            {
                InvalidateToken(tenant.TenantId);
            }

            return authorized;
        }
        finally
        {
            state.Lock.Release();
        }
    }

    public void InvalidateToken(string tenantId)
    {
        if (_states.TryGetValue(tenantId, out var state))
        {
            state.Token = null;
            state.ExpiresAt = DateTimeOffset.MinValue;
        }
    }

    private TenantAuthState GetState(string tenantId)
    {
        return _states.GetOrAdd(tenantId, _ => new TenantAuthState());
    }

    private async Task RegisterInternalAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Registering Sepidar device for tenant {TenantId}", tenant.TenantId);
        var client = CreateHttpClient(tenant);

        var payload = JsonSerializer.Serialize(new
        {
            DeviceSerial = tenant.Sepidar.DeviceSerial,
            IntegrationId = tenant.Sepidar.IntegrationId,
            Timestamp = DateTimeOffset.UtcNow
        }, SerializerOptions);

        var encrypted = _crypto.EncryptRegisterPayload(tenant.Sepidar.DeviceSerial, payload);
        var body = JsonSerializer.Serialize(new
        {
            Cypher = encrypted.CipherText,
            IV = encrypted.IvBase64,
            DeviceSerial = tenant.Sepidar.DeviceSerial
        }, SerializerOptions);

        using var request = new HttpRequestMessage(HttpMethod.Post, BuildTenantUri(tenant, "api/Devices/Register/"))
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var registerResponse = JsonSerializer.Deserialize<RegisterResponse>(responseBody, SerializerOptions)
                              ?? throw new InvalidOperationException("Invalid register response");

        var plaintext = _crypto.DecryptRegisterPayload(
            tenant.Sepidar.DeviceSerial,
            registerResponse.Cypher,
            registerResponse.IV);

        var crypto = JsonSerializer.Deserialize<RegisterCryptoResponse>(plaintext, SerializerOptions)
                     ?? throw new InvalidOperationException("Invalid crypto payload");

        tenant.Crypto.RsaPublicKeyXml = crypto.RsaPublicKeyXml;
        tenant.Crypto.RsaModulusBase64 = crypto.RsaModulusBase64;
        tenant.Crypto.RsaExponentBase64 = crypto.RsaExponentBase64;
    }

    private async Task<LoginResult> LoginInternalAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Logging in tenant {TenantId}", tenant.TenantId);
        var client = CreateHttpClient(tenant);
        var arbitraryCode = Guid.NewGuid().ToString();
        var encArbitraryCode = _crypto.EncryptArbitraryCode(arbitraryCode, tenant.Crypto);

        using var request = new HttpRequestMessage(HttpMethod.Post, BuildTenantUri(tenant, "api/users/login/"));
        request.Headers.Add("GenerationVersion", tenant.Sepidar.GenerationVersion);
        request.Headers.Add("IntegrationID", tenant.Sepidar.IntegrationId);
        request.Headers.Add("ArbitraryCode", arbitraryCode);
        request.Headers.Add("EncArbitraryCode", encArbitraryCode);

        var loginPayload = JsonSerializer.Serialize(new
        {
            UserName = tenant.Credentials.UserName,
            PasswordHash = tenant.Credentials.PasswordMd5
        }, SerializerOptions);
        request.Content = new StringContent(loginPayload, Encoding.UTF8, "application/json");

        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.PreconditionFailed)
        {
            throw new InvalidOperationException("Generation version mismatch");
        }

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var loginResponse = JsonSerializer.Deserialize<LoginResponse>(content, SerializerOptions)
                           ?? throw new InvalidOperationException("Invalid login response");

        var expires = DateTimeOffset.UtcNow.AddSeconds(Math.Min(
            tenant.Jwt.CacheSeconds,
            loginResponse.ExpiresIn > 0 ? loginResponse.ExpiresIn : tenant.Jwt.CacheSeconds));

        return new LoginResult(loginResponse.Token, expires);
    }

    private HttpClient CreateHttpClient(TenantOptions tenant)
    {
        var client = _httpClientFactory.CreateClient("SepidarAuth");
        client.Timeout = TimeSpan.FromSeconds(tenant.Limits.RequestTimeoutSeconds);
        return client;
    }

    private Uri BuildTenantUri(TenantOptions tenant, string relativePath)
    {
        var baseUri = new Uri(tenant.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        return new Uri(baseUri, relativePath);
    }

    private void PrepareHeaders(HttpRequestHeaders headers, TenantOptions tenant, string token)
    {
        headers.TryAddWithoutValidation("GenerationVersion", tenant.Sepidar.GenerationVersion);
        headers.TryAddWithoutValidation("IntegrationID", tenant.Sepidar.IntegrationId);
        headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        headers.TryAddWithoutValidation("ArbitraryCode", Guid.NewGuid().ToString());
    }

    private sealed record RegisterResponse(string Cypher, string IV);

    private sealed record RegisterCryptoResponse
    {
        public string? RsaPublicKeyXml { get; set; }
        public string? RsaModulusBase64 { get; set; }
        public string? RsaExponentBase64 { get; set; }
    }

    private sealed record LoginResponse
    {
        public string Token { get; set; } = string.Empty;
        public int ExpiresIn { get; set; } = 0;
    }

    private sealed record LoginResult(string Token, DateTimeOffset ExpiresAt);

    private sealed class TenantAuthState
    {
        public SemaphoreSlim Lock { get; } = new(1, 1);
        public bool Registered { get; set; }
        public string? Token { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset LastAuthorizationCheck { get; set; } = DateTimeOffset.MinValue;
    }
}
