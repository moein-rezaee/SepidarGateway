using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
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
        var AuthState = GetState(tenant.TenantId);
        if (AuthState.Registered)
        {
            return;
        }

        await AuthState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (AuthState.Registered)
            {
                return;
            }

            await RegisterInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            AuthState.Registered = true;
        }
        finally
        {
            AuthState.Lock.Release();
        }
    }

    public async Task<string> EnsureTokenAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        var AuthState = GetState(tenant.TenantId);
        await EnsureDeviceRegisteredAsync(tenant, cancellationToken).ConfigureAwait(false);

        if (AuthState.Token is { } CachedToken && AuthState.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
        {
            return CachedToken;
        }

        await AuthState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (AuthState.Token is { } FreshToken && AuthState.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
            {
                return FreshToken;
            }

            var LoginResult = await LoginInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            AuthState.Token = LoginResult.Token;
            AuthState.ExpiresAt = LoginResult.ExpiresAt;
            return LoginResult.Token;
        }
        finally
        {
            AuthState.Lock.Release();
        }
    }

    public async Task<bool> IsAuthorizedAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        var AuthState = GetState(tenant.TenantId);
        if (AuthState.Token is null)
        {
            return false;
        }

        if (AuthState.LastAuthorizationCheck + TimeSpan.FromSeconds(tenant.Jwt.PreAuthCheckSeconds) > DateTimeOffset.UtcNow)
        {
            return true;
        }

        await AuthState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (AuthState.Token is null)
            {
                return false;
            }

            if (AuthState.LastAuthorizationCheck + TimeSpan.FromSeconds(tenant.Jwt.PreAuthCheckSeconds) > DateTimeOffset.UtcNow)
            {
                return true;
            }

            var HttpClient = CreateHttpClient(tenant);
            using var RequestMessage = new HttpRequestMessage(HttpMethod.Get, BuildTenantUri(tenant, "api/IsAuthorized"));
            PrepareHeaders(RequestMessage.Headers, tenant, AuthState.Token);

            using var HttpResponse = await HttpClient.SendAsync(RequestMessage, cancellationToken).ConfigureAwait(false);
            if (HttpResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("JWT expired for tenant {TenantId}", tenant.TenantId);
                InvalidateToken(tenant.TenantId);
                return false;
            }

            HttpResponse.EnsureSuccessStatusCode();
            var ResponseContent = await HttpResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var Authorized = bool.TryParse(ResponseContent, out var ParsedValue)
                             ? ParsedValue
                             : ResponseContent.Contains("true", StringComparison.OrdinalIgnoreCase);
            AuthState.LastAuthorizationCheck = DateTimeOffset.UtcNow;
            if (!Authorized)
            {
                InvalidateToken(tenant.TenantId);
            }

            return Authorized;
        }
        finally
        {
            AuthState.Lock.Release();
        }
    }

    public void InvalidateToken(string tenantId)
    {
        if (_states.TryGetValue(tenantId, out var TenantState))
        {
            TenantState.Token = null;
            TenantState.ExpiresAt = DateTimeOffset.MinValue;
        }
    }

    private TenantAuthState GetState(string tenantId)
    {
        return _states.GetOrAdd(tenantId, _ => new TenantAuthState());
    }

    private async Task RegisterInternalAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Registering Sepidar device for tenant {TenantId}", tenant.TenantId);
        var HttpClient = CreateHttpClient(tenant);

        var DevicePayload = JsonSerializer.Serialize(new
        {
            DeviceSerial = tenant.Sepidar.DeviceSerial,
            IntegrationId = tenant.Sepidar.IntegrationId,
            Timestamp = DateTimeOffset.UtcNow
        }, SerializerOptions);

        var EncryptedPayload = _crypto.EncryptRegisterPayload(tenant.Sepidar.DeviceSerial, DevicePayload);
        var RequestBody = JsonSerializer.Serialize(new
        {
            Cypher = EncryptedPayload.CipherText,
            IV = EncryptedPayload.IvBase64,
            DeviceSerial = tenant.Sepidar.DeviceSerial
        }, SerializerOptions);

        using var RegisterRequest = new HttpRequestMessage(HttpMethod.Post, BuildTenantUri(tenant, "api/Devices/Register"))
        {
            Content = new StringContent(RequestBody, Encoding.UTF8, "application/json")
        };

        using var RegisterResponse = await HttpClient.SendAsync(RegisterRequest, cancellationToken).ConfigureAwait(false);
        RegisterResponse.EnsureSuccessStatusCode();

        var ResponseBody = await RegisterResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var RegisterPayload = JsonSerializer.Deserialize<RegisterResponse>(ResponseBody, SerializerOptions)
                              ?? throw new InvalidOperationException("Invalid register response");

        var PlainText = _crypto.DecryptRegisterPayload(
            tenant.Sepidar.DeviceSerial,
            RegisterPayload.Cypher,
            RegisterPayload.IV);

        var TenantCrypto = JsonSerializer.Deserialize<RegisterCryptoResponse>(PlainText, SerializerOptions)
                             ?? throw new InvalidOperationException("Invalid crypto payload");

        tenant.Crypto.RsaPublicKeyXml = TenantCrypto.RsaPublicKeyXml;
        tenant.Crypto.RsaModulusBase64 = TenantCrypto.RsaModulusBase64;
        tenant.Crypto.RsaExponentBase64 = TenantCrypto.RsaExponentBase64;
    }

    private async Task<LoginResult> LoginInternalAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Logging in tenant {TenantId}", tenant.TenantId);
        var HttpClient = CreateHttpClient(tenant);
        var ArbitraryCode = Guid.NewGuid().ToString();
        var EncryptedCode = _crypto.EncryptArbitraryCode(ArbitraryCode, tenant.Crypto);

        using var LoginRequest = new HttpRequestMessage(HttpMethod.Post, BuildTenantUri(tenant, "api/users/login"));
        LoginRequest.Headers.Add("GenerationVersion", tenant.Sepidar.GenerationVersion);
        LoginRequest.Headers.Add("IntegrationID", tenant.Sepidar.IntegrationId);
        LoginRequest.Headers.Add("ArbitraryCode", ArbitraryCode);
        LoginRequest.Headers.Add("EncArbitraryCode", EncryptedCode);

        var PasswordHash = ComputePasswordHash(tenant.Credentials.Password);

        var LoginPayload = JsonSerializer.Serialize(new
        {
            UserName = tenant.Credentials.UserName,
            PasswordHash = PasswordHash
        }, SerializerOptions);
        LoginRequest.Content = new StringContent(LoginPayload, Encoding.UTF8, "application/json");

        using var LoginResponseMessage = await HttpClient.SendAsync(LoginRequest, cancellationToken).ConfigureAwait(false);
        if (LoginResponseMessage.StatusCode == System.Net.HttpStatusCode.PreconditionFailed)
        {
            throw new InvalidOperationException("Generation version mismatch");
        }

        LoginResponseMessage.EnsureSuccessStatusCode();
        var ResponseContent = await LoginResponseMessage.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var LoginResponse = JsonSerializer.Deserialize<LoginResponse>(ResponseContent, SerializerOptions)
                           ?? throw new InvalidOperationException("Invalid login response");

        var TokenExpiry = DateTimeOffset.UtcNow.AddSeconds(Math.Min(
            tenant.Jwt.CacheSeconds,
            LoginResponse.ExpiresIn > 0 ? LoginResponse.ExpiresIn : tenant.Jwt.CacheSeconds));

        return new LoginResult(LoginResponse.Token, TokenExpiry);
    }

    private HttpClient CreateHttpClient(TenantOptions tenant)
    {
        var HttpClient = _httpClientFactory.CreateClient("SepidarAuth");
        HttpClient.Timeout = TimeSpan.FromSeconds(tenant.Limits.RequestTimeoutSeconds);
        return HttpClient;
    }

    private Uri BuildTenantUri(TenantOptions tenant, string relativePath)
    {
        var BaseUri = new Uri(tenant.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var RelativePath = relativePath.TrimStart('/');
        var TargetUri = new Uri(BaseUri, RelativePath);

        if (!string.IsNullOrWhiteSpace(tenant.Sepidar.GenerationVersion))
        {
            var UriBuilder = new UriBuilder(TargetUri);
            var Query = QueryHelpers.ParseQuery(UriBuilder.Query);
            if (!Query.ContainsKey("api-version"))
            {
                var QueryBuilder = new QueryBuilder();
                foreach (var QueryPair in Query)
                {
                    foreach (var QueryValue in QueryPair.Value)
                    {
                        QueryBuilder.Add(QueryPair.Key, QueryValue ?? string.Empty);
                    }
                }

                QueryBuilder.Add("api-version", tenant.Sepidar.GenerationVersion);
                UriBuilder.Query = QueryBuilder.ToQueryString().Value?.TrimStart('?') ?? string.Empty;
                TargetUri = UriBuilder.Uri;
            }
        }

        return TargetUri;
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
        using var Md5Hash = MD5.Create();
        var PasswordBytes = Encoding.UTF8.GetBytes(password ?? string.Empty);
        var HashBytes = Md5Hash.ComputeHash(PasswordBytes);
        var HashBuilder = new StringBuilder(HashBytes.Length * 2);
        foreach (var HashByte in HashBytes)
        {
            HashBuilder.Append(HashByte.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        }

        return HashBuilder.ToString();
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
