using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
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
            using var RequestMessage = new HttpRequestMessage(HttpMethod.Get, BuildTenantUri(tenant, tenant.Sepidar.IsAuthorizedPath));
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

        var AttemptedPaths = new List<string>();
        var ProcessedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var RegisterQueue = new Queue<string>(EnumerateRegisterPaths(tenant));
        var DiscoveryAttempted = false;

        while (true)
        {
            while (RegisterQueue.Count > 0)
            {
                var RegisterPath = RegisterQueue.Dequeue();
                if (!ProcessedPaths.Add(RegisterPath))
                {
                    continue;
                }

                AttemptedPaths.Add(RegisterPath);
                using var RegisterRequest = new HttpRequestMessage(HttpMethod.Post, BuildTenantUri(tenant, RegisterPath))
                {
                    Content = new StringContent(RequestBody, Encoding.UTF8, "application/json")
                };

                if (!string.IsNullOrWhiteSpace(tenant.Sepidar.ApiVersion))
                {
                    RegisterRequest.Headers.TryAddWithoutValidation("api-version", tenant.Sepidar.ApiVersion);
                }

                RegisterRequest.Headers.TryAddWithoutValidation("GenerationVersion", tenant.Sepidar.GenerationVersion);
                RegisterRequest.Headers.TryAddWithoutValidation("IntegrationID", tenant.Sepidar.IntegrationId);

                using var RegisterResponse = await HttpClient.SendAsync(RegisterRequest, cancellationToken).ConfigureAwait(false);
                if (RegisterResponse.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    _logger.LogWarning("Register endpoint {Path} not found for tenant {TenantId}", RegisterPath, tenant.TenantId);
                    continue;
                }

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
                return;
            }

            if (DiscoveryAttempted)
            {
                break;
            }

            DiscoveryAttempted = true;
            var DiscoveredPaths = await DiscoverRegisterPathsAsync(tenant, cancellationToken).ConfigureAwait(false);
            foreach (var DiscoveredPath in DiscoveredPaths.SelectMany(ExpandPathVariants))
            {
                if (!ProcessedPaths.Contains(DiscoveredPath))
                {
                    RegisterQueue.Enqueue(DiscoveredPath);
                }
            }
        }

        throw new HttpRequestException($"No register endpoint returned a successful response. Attempted: {string.Join(", ", AttemptedPaths)}");
    }

    private async Task<IEnumerable<string>> DiscoverRegisterPathsAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        try
        {
            var HttpClient = CreateHttpClient(tenant);
            var SwaggerUri = BuildTenantUri(tenant, tenant.Sepidar.SwaggerDocumentPath);
            using var SwaggerRequest = new HttpRequestMessage(HttpMethod.Get, SwaggerUri);
            using var SwaggerResponse = await HttpClient.SendAsync(SwaggerRequest, cancellationToken).ConfigureAwait(false);

            if (!SwaggerResponse.IsSuccessStatusCode)
            {
                _logger.LogWarning("Failed to resolve register path from Swagger for tenant {TenantId}. Status code {StatusCode}", tenant.TenantId, (int)SwaggerResponse.StatusCode);
                return Array.Empty<string>();
            }

            await using var SwaggerStream = await SwaggerResponse.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var SwaggerDocument = await JsonDocument.ParseAsync(SwaggerStream, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (!SwaggerDocument.RootElement.TryGetProperty("paths", out var PathsElement) || PathsElement.ValueKind != JsonValueKind.Object)
            {
                return Array.Empty<string>();
            }

            var RegisterPaths = new List<string>();
            foreach (var PathProperty in PathsElement.EnumerateObject())
            {
                var RouteName = PathProperty.Name?.Trim();
                if (string.IsNullOrWhiteSpace(RouteName))
                {
                    continue;
                }

                var Normalized = RouteName.Trim('/');
                if (Normalized.Length == 0)
                {
                    continue;
                }

                if (Normalized.Contains("register", StringComparison.OrdinalIgnoreCase))
                {
                    RegisterPaths.Add(Normalized);
                }
            }

            if (RegisterPaths.Count > 0)
            {
                _logger.LogInformation("Discovered register endpoints from Swagger for tenant {TenantId}: {Paths}", tenant.TenantId, string.Join(", ", RegisterPaths));
            }

            return RegisterPaths;
        }
        catch (Exception DiscoveryException) when (DiscoveryException is HttpRequestException or JsonException or InvalidOperationException)
        {
            _logger.LogWarning(DiscoveryException, "Unable to auto-discover register endpoints for tenant {TenantId}", tenant.TenantId);
            return Array.Empty<string>();
        }
    }

    private async Task<LoginResult> LoginInternalAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Logging in tenant {TenantId}", tenant.TenantId);
        var HttpClient = CreateHttpClient(tenant);
        var ArbitraryCode = Guid.NewGuid().ToString();
        var EncryptedCode = _crypto.EncryptArbitraryCode(ArbitraryCode, tenant.Crypto);

        using var LoginRequest = new HttpRequestMessage(HttpMethod.Post, BuildTenantUri(tenant, tenant.Sepidar.LoginPath));
        LoginRequest.Headers.Add("GenerationVersion", tenant.Sepidar.GenerationVersion);
        LoginRequest.Headers.Add("IntegrationID", tenant.Sepidar.IntegrationId);
        LoginRequest.Headers.Add("ArbitraryCode", ArbitraryCode);
        LoginRequest.Headers.Add("EncArbitraryCode", EncryptedCode);

        if (!string.IsNullOrWhiteSpace(tenant.Sepidar.ApiVersion))
        {
            LoginRequest.Headers.TryAddWithoutValidation("api-version", tenant.Sepidar.ApiVersion);
        }

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
        var NormalizedPath = string.IsNullOrWhiteSpace(relativePath)
            ? string.Empty
            : relativePath.TrimStart('/');
        var BaseUri = new Uri(tenant.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        return new Uri(BaseUri, NormalizedPath);
    }

    private IEnumerable<string> EnumerateRegisterPaths(TenantOptions tenant)
    {
        var Visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var Candidate in EnumerateCandidateSources(tenant))
        {
            foreach (var Variant in ExpandPathVariants(Candidate))
            {
                if (Visited.Add(Variant))
                {
                    yield return Variant;
                }
            }
        }
    }

    private static IEnumerable<string> EnumerateCandidateSources(TenantOptions tenant)
    {
        if (!string.IsNullOrWhiteSpace(tenant.Sepidar.RegisterPath))
        {
            yield return tenant.Sepidar.RegisterPath;
        }

        if (tenant.Sepidar.RegisterFallbackPaths is { Length: > 0 })
        {
            foreach (var FallbackPath in tenant.Sepidar.RegisterFallbackPaths)
            {
                if (!string.IsNullOrWhiteSpace(FallbackPath))
                {
                    yield return FallbackPath;
                }
            }
        }

        yield return "api/Devices/Register/";
        yield return "api/Device/Register/";
        yield return "api/Device/RegisterDevice/";
        yield return "api/Devices/RegisterDevice/";
        yield return "api/RegisterDevice/";
        yield return "api/Register/";
    }

    private static IEnumerable<string> ExpandPathVariants(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            yield break;
        }

        var Normalized = path.Trim().TrimStart('/');
        if (string.IsNullOrEmpty(Normalized))
        {
            yield break;
        }

        var WithTrailing = Normalized.EndsWith('/') ? Normalized : Normalized + "/";
        yield return WithTrailing;
        yield return WithTrailing.TrimEnd('/');

        var LowerCase = WithTrailing.ToLowerInvariant();
        yield return LowerCase;
        yield return LowerCase.TrimEnd('/');
    }

    private void PrepareHeaders(HttpRequestHeaders headers, TenantOptions tenant, string token)
    {
        headers.TryAddWithoutValidation("GenerationVersion", tenant.Sepidar.GenerationVersion);
        headers.TryAddWithoutValidation("IntegrationID", tenant.Sepidar.IntegrationId);

        if (!string.IsNullOrWhiteSpace(tenant.Sepidar.ApiVersion))
        {
            headers.TryAddWithoutValidation("api-version", tenant.Sepidar.ApiVersion);
        }

        var ArbitraryCode = Guid.NewGuid().ToString();
        var EncryptedCode = _crypto.EncryptArbitraryCode(ArbitraryCode, tenant.Crypto);

        headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        headers.TryAddWithoutValidation("ArbitraryCode", ArbitraryCode);
        headers.TryAddWithoutValidation("EncArbitraryCode", EncryptedCode);
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
