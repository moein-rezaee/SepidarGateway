using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
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
        var auth_state = GetState(tenant.TenantId);
        if (auth_state.Registered)
        {
            return;
        }

        await auth_state.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (auth_state.Registered)
            {
                return;
            }

            await RegisterInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            auth_state.Registered = true;
        }
        finally
        {
            auth_state.Lock.Release();
        }
    }

    public async Task<string> EnsureTokenAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        var auth_state = GetState(tenant.TenantId);
        await EnsureDeviceRegisteredAsync(tenant, cancellationToken).ConfigureAwait(false);

        if (auth_state.Token is { } cached_token && auth_state.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
        {
            return cached_token;
        }

        await auth_state.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (auth_state.Token is { } fresh_token && auth_state.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
            {
                return fresh_token;
            }

            var login_result = await LoginInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            auth_state.Token = login_result.Token;
            auth_state.ExpiresAt = login_result.ExpiresAt;
            return login_result.Token;
        }
        finally
        {
            auth_state.Lock.Release();
        }
    }

    public async Task<bool> IsAuthorizedAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        var auth_state = GetState(tenant.TenantId);
        if (auth_state.Token is null)
        {
            return false;
        }

        if (auth_state.LastAuthorizationCheck + TimeSpan.FromSeconds(tenant.Jwt.PreAuthCheckSeconds) > DateTimeOffset.UtcNow)
        {
            return true;
        }

        await auth_state.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (auth_state.Token is null)
            {
                return false;
            }

            if (auth_state.LastAuthorizationCheck + TimeSpan.FromSeconds(tenant.Jwt.PreAuthCheckSeconds) > DateTimeOffset.UtcNow)
            {
                return true;
            }

            var http_client = CreateHttpClient(tenant);
            using var request_message = new HttpRequestMessage(HttpMethod.Get, BuildTenantUri(tenant, "api/IsAuthorized/"));
            PrepareHeaders(request_message.Headers, tenant, auth_state.Token);

            using var http_response = await http_client.SendAsync(request_message, cancellationToken).ConfigureAwait(false);
            if (http_response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("JWT expired for tenant {TenantId}", tenant.TenantId);
                InvalidateToken(tenant.TenantId);
                return false;
            }

            http_response.EnsureSuccessStatusCode();
            var response_content = await http_response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var authorized = bool.TryParse(response_content, out var parsed_value)
                             ? parsed_value
                             : response_content.Contains("true", StringComparison.OrdinalIgnoreCase);
            auth_state.LastAuthorizationCheck = DateTimeOffset.UtcNow;
            if (!authorized)
            {
                InvalidateToken(tenant.TenantId);
            }

            return authorized;
        }
        finally
        {
            auth_state.Lock.Release();
        }
    }

    public void InvalidateToken(string tenantId)
    {
        if (_states.TryGetValue(tenantId, out var tenant_state))
        {
            tenant_state.Token = null;
            tenant_state.ExpiresAt = DateTimeOffset.MinValue;
        }
    }

    private TenantAuthState GetState(string tenantId)
    {
        return _states.GetOrAdd(tenantId, _ => new TenantAuthState());
    }

    private async Task RegisterInternalAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Registering Sepidar device for tenant {TenantId}", tenant.TenantId);
        var http_client = CreateHttpClient(tenant);

        var device_payload = JsonSerializer.Serialize(new
        {
            DeviceSerial = tenant.Sepidar.DeviceSerial,
            IntegrationId = tenant.Sepidar.IntegrationId,
            Timestamp = DateTimeOffset.UtcNow
        }, SerializerOptions);

        var encrypted_payload = _crypto.EncryptRegisterPayload(tenant.Sepidar.DeviceSerial, device_payload);
        var request_body = JsonSerializer.Serialize(new
        {
            Cypher = encrypted_payload.CipherText,
            IV = encrypted_payload.IvBase64,
            DeviceSerial = tenant.Sepidar.DeviceSerial
        }, SerializerOptions);

        using var register_request = new HttpRequestMessage(HttpMethod.Post, BuildTenantUri(tenant, "api/Devices/Register/"))
        {
            Content = new StringContent(request_body, Encoding.UTF8, "application/json")
        };

        using var register_response = await http_client.SendAsync(register_request, cancellationToken).ConfigureAwait(false);
        register_response.EnsureSuccessStatusCode();

        var response_body = await register_response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var register_payload = JsonSerializer.Deserialize<RegisterResponse>(response_body, SerializerOptions)
                              ?? throw new InvalidOperationException("Invalid register response");

        var plain_text = _crypto.DecryptRegisterPayload(
            tenant.Sepidar.DeviceSerial,
            register_payload.Cypher,
            register_payload.IV);

        var tenant_crypto = JsonSerializer.Deserialize<RegisterCryptoResponse>(plain_text, SerializerOptions)
                             ?? throw new InvalidOperationException("Invalid crypto payload");

        tenant.Crypto.RsaPublicKeyXml = tenant_crypto.RsaPublicKeyXml;
        tenant.Crypto.RsaModulusBase64 = tenant_crypto.RsaModulusBase64;
        tenant.Crypto.RsaExponentBase64 = tenant_crypto.RsaExponentBase64;
    }

    private async Task<LoginResult> LoginInternalAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Logging in tenant {TenantId}", tenant.TenantId);
        var http_client = CreateHttpClient(tenant);
        var arbitrary_code = Guid.NewGuid().ToString();
        var encrypted_code = _crypto.EncryptArbitraryCode(arbitrary_code, tenant.Crypto);

        using var login_request = new HttpRequestMessage(HttpMethod.Post, BuildTenantUri(tenant, "api/users/login/"));
        login_request.Headers.Add("GenerationVersion", tenant.Sepidar.GenerationVersion);
        login_request.Headers.Add("IntegrationID", tenant.Sepidar.IntegrationId);
        login_request.Headers.Add("ArbitraryCode", arbitrary_code);
        login_request.Headers.Add("EncArbitraryCode", encrypted_code);

        var password_hash = ComputePasswordHash(tenant.Credentials.Password);

        var login_payload = JsonSerializer.Serialize(new
        {
            UserName = tenant.Credentials.UserName,
            PasswordHash = password_hash
        }, SerializerOptions);
        login_request.Content = new StringContent(login_payload, Encoding.UTF8, "application/json");

        using var login_response_message = await http_client.SendAsync(login_request, cancellationToken).ConfigureAwait(false);
        if (login_response_message.StatusCode == System.Net.HttpStatusCode.PreconditionFailed)
        {
            throw new InvalidOperationException("Generation version mismatch");
        }

        login_response_message.EnsureSuccessStatusCode();
        var response_content = await login_response_message.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var login_response = JsonSerializer.Deserialize<LoginResponse>(response_content, SerializerOptions)
                           ?? throw new InvalidOperationException("Invalid login response");

        var token_expiry = DateTimeOffset.UtcNow.AddSeconds(Math.Min(
            tenant.Jwt.CacheSeconds,
            login_response.ExpiresIn > 0 ? login_response.ExpiresIn : tenant.Jwt.CacheSeconds));

        return new LoginResult(login_response.Token, token_expiry);
    }

    private HttpClient CreateHttpClient(TenantOptions tenant)
    {
        var http_client = _httpClientFactory.CreateClient("SepidarAuth");
        http_client.Timeout = TimeSpan.FromSeconds(tenant.Limits.RequestTimeoutSeconds);
        return http_client;
    }

    private Uri BuildTenantUri(TenantOptions tenant, string relativePath)
    {
        var base_uri = new Uri(tenant.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        return new Uri(base_uri, relativePath);
    }

    private void PrepareHeaders(HttpRequestHeaders headers, TenantOptions tenant, string token)
    {
        headers.TryAddWithoutValidation("GenerationVersion", tenant.Sepidar.GenerationVersion);
        headers.TryAddWithoutValidation("IntegrationID", tenant.Sepidar.IntegrationId);
        headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        headers.TryAddWithoutValidation("ArbitraryCode", Guid.NewGuid().ToString());
    }

    private static string ComputePasswordHash(string password)
    {
        using var md5_hash = MD5.Create();
        var password_bytes = Encoding.UTF8.GetBytes(password ?? string.Empty);
        var hash_bytes = md5_hash.ComputeHash(password_bytes);
        var hash_builder = new StringBuilder(hash_bytes.Length * 2);
        foreach (var hash_byte in hash_bytes)
        {
            hash_builder.Append(hash_byte.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        }

        return hash_builder.ToString();
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
