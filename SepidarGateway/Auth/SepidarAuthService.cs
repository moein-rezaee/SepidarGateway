using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SepidarGateway.Configuration;
using SepidarGateway.Contracts;
using SepidarGateway.Crypto;

namespace SepidarGateway.Auth;

public sealed class SepidarAuthService : ISepidarAuth
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISepidarCrypto _crypto;
    private readonly ILogger<SepidarAuthService> _logger;
    private readonly ConcurrentDictionary<string, TenantAuthState> _states = new();

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };
    private static readonly JsonSerializerOptions PreserveNamesOptions = new JsonSerializerOptions
    {
        PropertyNamingPolicy = null
    };

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
        if (!AuthState.Registered && HasRsaConfigured(tenant.Crypto))
        {
            // Assume device already registered when RSA is pre-provisioned via configuration
            AuthState.Registered = true;
            return;
        }
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

    public async Task<DeviceLoginResponseDto> LoginAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        var AuthState = GetState(tenant.TenantId);
        await EnsureDeviceRegisteredAsync(tenant, cancellationToken).ConfigureAwait(false);

        await AuthState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var LoginResult = await LoginInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            AuthState.Token = LoginResult.Token;
            AuthState.ExpiresAt = LoginResult.ExpiresAt;
            return MapLoginResult(LoginResult);
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
            using var RequestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                BuildTenantUri(tenant, tenant.Sepidar.IsAuthorizedPath, includeApiVersionQuery: true));
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

        var deviceSerial = tenant.Sepidar.DeviceSerial?.Trim();
        if (string.IsNullOrWhiteSpace(deviceSerial))
        {
            throw new InvalidOperationException("Tenant device serial is not configured.");
        }

        tenant.Sepidar.DeviceSerial = deviceSerial;

        var configuredIntegrationId = tenant.Sepidar.IntegrationId?.Trim();
        if (string.IsNullOrWhiteSpace(configuredIntegrationId))
        {
            configuredIntegrationId = DeriveIntegrationIdFromSerial(deviceSerial);
            if (string.IsNullOrWhiteSpace(configuredIntegrationId))
            {
                throw new InvalidOperationException("IntegrationID is not configured and could not be derived from the device serial.");
            }

            tenant.Sepidar.IntegrationId = configuredIntegrationId;
        }

        if (!configuredIntegrationId.All(char.IsDigit))
        {
            throw new InvalidOperationException($"IntegrationID '{configuredIntegrationId}' must contain only digits.");
        }

        var payloadMode = tenant.Sepidar.RegisterPayloadMode?.Trim() ?? "IntegrationOnly";
        string DevicePayload;
        if (string.Equals(payloadMode, "Detailed", StringComparison.OrdinalIgnoreCase))
        {
            DevicePayload = JsonSerializer.Serialize(new
            {
                DeviceSerial = tenant.Sepidar.DeviceSerial,
                IntegrationId = configuredIntegrationId,
                Timestamp = DateTimeOffset.UtcNow
            }, PreserveNamesOptions);
        }
        else if (string.Equals(payloadMode, "SimpleTitle", StringComparison.OrdinalIgnoreCase))
        {
            var title = string.IsNullOrWhiteSpace(tenant.Sepidar.DeviceTitle)
                ? tenant.Sepidar.DeviceSerial
                : tenant.Sepidar.DeviceTitle!;
            DevicePayload = title ?? string.Empty;
        }
        else
        {
            DevicePayload = configuredIntegrationId;
        }

        var encryptedPayload = _crypto.EncryptRegisterPayload(tenant.Sepidar.DeviceSerial, DevicePayload);

        if (configuredIntegrationId.Length < 4)
        {
            throw new InvalidOperationException("IntegrationID must be at least four digits long.");
        }

        var integrationIdValue = int.Parse(configuredIntegrationId, CultureInfo.InvariantCulture);
        var registerBody = JsonSerializer.Serialize(new RegisterRequest(
            encryptedPayload.CipherText,
            encryptedPayload.IvBase64,
            integrationIdValue), PreserveNamesOptions);

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

                var success = await AttemptRegisterAsync(HttpClient, tenant, RegisterPath, registerBody, includeApiVersion: false, cancellationToken).ConfigureAwait(false);
                if (!success)
                {
                    success = await AttemptRegisterAsync(HttpClient, tenant, RegisterPath, registerBody, includeApiVersion: true, cancellationToken).ConfigureAwait(false);
                }

                if (!success)
                {
                    continue;
                }

                return;
            }

            if (DiscoveryAttempted || tenant.Sepidar.RegisterStrict)
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

    private async Task<bool> AttemptRegisterAsync(HttpClient httpClient, TenantOptions tenant, string registerPath, string requestBody, bool includeApiVersion, CancellationToken cancellationToken)
    {
        var registerUri = BuildTenantUri(tenant, registerPath, includeApiVersionQuery: includeApiVersion);
        using var registerRequest = new HttpRequestMessage(HttpMethod.Post, registerUri)
        {
            Content = new StringContent(requestBody, Encoding.UTF8, "application/json")
        };
        // Optional cookie header if required by server during register
        if (!string.IsNullOrWhiteSpace(tenant.Sepidar.RegisterCookie))
        {
            registerRequest.Headers.TryAddWithoutValidation("Cookie", tenant.Sepidar.RegisterCookie);
        }

        HttpResponseMessage? response = null;
        try
        {
            response = await httpClient.SendAsync(registerRequest, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException httpException) when (httpException.InnerException is SocketException socketException)
        {
            _logger.LogError(httpException,
                "Register endpoint {Path} connection failed for tenant {TenantId}. URI: {Uri}. SocketError: {SocketError}",
                registerPath,
                tenant.TenantId,
                registerUri,
                socketException.SocketErrorCode);
            return false;
        }

        using (response)
        {
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger.LogWarning("Register endpoint {Path} not found for tenant {TenantId} (URI: {Uri})", registerPath, tenant.TenantId, registerUri);
                return false;
            }

            if (!response.IsSuccessStatusCode)
            {
                string snippet = string.Empty;
                try
                {
                    var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    snippet = content.Length > 500 ? content.Substring(0, 500) + "..." : content;
                }
                catch { }

                _logger.LogError("Register endpoint {Path} returned {StatusCode} for tenant {TenantId}. URI: {Uri}. Body: {Body}", registerPath, (int)response.StatusCode, tenant.TenantId, registerUri, snippet);
                return false;
            }

            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var registerPayload = JsonSerializer.Deserialize<RegisterResponse>(responseBody, SerializerOptions)
                                  ?? throw new InvalidOperationException("Invalid register response");
            var plainText = _crypto.DecryptRegisterPayload(
                tenant.Sepidar.DeviceSerial,
                registerPayload.Cypher,
                registerPayload.IV);

            if (!TryApplyRegisterCryptoPayload(tenant, plainText))
            {
                throw new InvalidOperationException("Invalid crypto payload");
            }

            if (!string.IsNullOrWhiteSpace(registerPayload.DeviceTitle))
            {
                tenant.Sepidar.DeviceTitle = registerPayload.DeviceTitle.Trim();
            }

            return true;
        }
    }

    private async Task<LoginResult> LoginInternalAsync(TenantOptions tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Logging in tenant {TenantId}", tenant.TenantId);
        var HttpClient = CreateHttpClient(tenant);
        var ArbitraryCode = Guid.NewGuid().ToString();
        var EncryptedCode = _crypto.EncryptArbitraryCode(ArbitraryCode, tenant.Crypto);

        // لاگین بدون api-version در Query بر اساس کرل موفق
        var userName = tenant.Credentials.UserName?.Trim();
        var password = tenant.Credentials.Password?.Trim() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(userName))
        {
            throw new InvalidOperationException("Tenant username is not configured.");
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("Tenant password is not configured.");
        }

        tenant.Credentials.UserName = userName;
        tenant.Credentials.Password = password;

        var LoginUri = BuildTenantUri(tenant, tenant.Sepidar.LoginPath, includeApiVersionQuery: false);

        using var LoginRequest = new HttpRequestMessage(HttpMethod.Post, LoginUri);
        // هدر api-version برای Login ارسال نمی‌شود تا کاملاً مطابق کرل باشد

        LoginRequest.Headers.Add("GenerationVersion", tenant.Sepidar.GenerationVersion);
        LoginRequest.Headers.Add("IntegrationID", tenant.Sepidar.IntegrationId);
        LoginRequest.Headers.Add("ArbitraryCode", ArbitraryCode);
        LoginRequest.Headers.Add("EncArbitraryCode", EncryptedCode);

        var PasswordHash = LooksLikeMd5(password)
            ? password.ToLowerInvariant()
            : ComputePasswordHash(password);

        var LoginPayload = JsonSerializer.Serialize(new
        {
            UserName = tenant.Credentials.UserName,
            PasswordHash = PasswordHash
        }, PreserveNamesOptions);
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

        var ExpiresInSeconds = LoginResponse.ExpiresIn > 0 ? LoginResponse.ExpiresIn : tenant.Jwt.CacheSeconds;
        var TokenExpiry = DateTimeOffset.UtcNow.AddSeconds(Math.Min(tenant.Jwt.CacheSeconds, ExpiresInSeconds));

        return new LoginResult(LoginResponse, TokenExpiry, ExpiresInSeconds);
    }

    private HttpClient CreateHttpClient(TenantOptions tenant)
    {
        var HttpClient = _httpClientFactory.CreateClient("SepidarAuth");
        HttpClient.Timeout = TimeSpan.FromSeconds(tenant.Limits.RequestTimeoutSeconds);
        return HttpClient;
    }

    private Uri BuildTenantUri(TenantOptions tenant, string relativePath, bool includeApiVersionQuery = false)
    {
        var NormalizedPath = string.IsNullOrWhiteSpace(relativePath)
            ? string.Empty
            : relativePath.TrimStart('/');
        var BaseUri = new Uri(tenant.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var TenantUri = new Uri(BaseUri, NormalizedPath);

        if (!includeApiVersionQuery || string.IsNullOrWhiteSpace(tenant.Sepidar.ApiVersion))
        {
            return TenantUri;
        }

        var Builder = new UriBuilder(TenantUri);
        var ExistingQuery = Builder.Query;
        var TrimmedQuery = string.IsNullOrEmpty(ExistingQuery)
            ? string.Empty
            : ExistingQuery.TrimStart('?');

        var HasApiVersion = TrimmedQuery
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Any(Part => Part.StartsWith("api-version=", StringComparison.OrdinalIgnoreCase));

        if (!HasApiVersion)
        {
            var EncodedValue = Uri.EscapeDataString(tenant.Sepidar.ApiVersion);
            Builder.Query = string.IsNullOrEmpty(TrimmedQuery)
                ? $"api-version={EncodedValue}"
                : $"{TrimmedQuery}&api-version={EncodedValue}";
        }

        return Builder.Uri;
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

        if (!tenant.Sepidar.RegisterStrict && tenant.Sepidar.RegisterFallbackPaths is { Length: > 0 })
        {
            foreach (var FallbackPath in tenant.Sepidar.RegisterFallbackPaths)
            {
                if (!string.IsNullOrWhiteSpace(FallbackPath))
                {
                    yield return FallbackPath;
                }
            }
        }

        if (!tenant.Sepidar.RegisterStrict)
        {
            yield return "api/Devices/Register/";
            yield return "api/Device/Register/";
            yield return "api/Device/RegisterDevice/";
            yield return "api/Devices/RegisterDevice/";
            yield return "api/RegisterDevice/";
            yield return "api/Register/";
        }
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

    private static string DeriveIntegrationIdFromSerial(string serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return string.Empty;
        }

        var digits = new StringBuilder(capacity: 4);
        foreach (var ch in serial)
        {
            if (!char.IsDigit(ch))
            {
                continue;
            }

            digits.Append(ch);
            if (digits.Length >= 4)
            {
                break;
            }
        }

        return digits.ToString();
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

    private bool TryApplyRegisterCryptoPayload(TenantOptions tenant, string plainText)
    {
        if (string.IsNullOrWhiteSpace(plainText))
        {
            return false;
        }

        var sanitized = plainText.Trim();
        sanitized = sanitized.TrimStart((char)0xFEFF);

        if (sanitized.Length == 0)
        {
            return false;
        }

        if (sanitized.StartsWith("{", StringComparison.Ordinal))
        {
            try
            {
                var tenantCrypto = JsonSerializer.Deserialize<RegisterCryptoResponse>(sanitized, SerializerOptions);
                if (tenantCrypto is null)
                {
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(tenantCrypto.RsaPublicKeyXml))
                {
                    tenant.Crypto.RsaPublicKeyXml = tenantCrypto.RsaPublicKeyXml;
                    tenant.Crypto.RsaModulusBase64 = null;
                    tenant.Crypto.RsaExponentBase64 = null;
                    return true;
                }

                if (!string.IsNullOrWhiteSpace(tenantCrypto.RsaModulusBase64) &&
                    !string.IsNullOrWhiteSpace(tenantCrypto.RsaExponentBase64))
                {
                    tenant.Crypto.RsaPublicKeyXml = null;
                    tenant.Crypto.RsaModulusBase64 = tenantCrypto.RsaModulusBase64;
                    tenant.Crypto.RsaExponentBase64 = tenantCrypto.RsaExponentBase64;
                    return true;
                }

                return false;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        var candidate = sanitized;
        if (!candidate.StartsWith("<", StringComparison.Ordinal))
        {
            var xmlIndex = candidate.IndexOf('<');
            if (xmlIndex >= 0)
            {
                candidate = candidate.Substring(xmlIndex);
            }
        }

        if (candidate.Contains("<RSAKeyValue", StringComparison.OrdinalIgnoreCase))
        {
            tenant.Crypto.RsaPublicKeyXml = candidate;
            tenant.Crypto.RsaModulusBase64 = null;
            tenant.Crypto.RsaExponentBase64 = null;
            return true;
        }

        return false;
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

    private static bool LooksLikeMd5(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length != 32)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!Uri.IsHexDigit(ch))
            {
                return false;
            }
        }

        return true;
    }

    private sealed record RegisterRequest(string Cypher, string IV, int IntegrationID);

    private sealed record RegisterResponse(string Cypher, string IV)
    {
        public string? DeviceTitle { get; init; }
    }

    private sealed record RegisterCryptoResponse
    {
        public string? RsaPublicKeyXml { get; set; }
        public string? RsaModulusBase64 { get; set; }
        public string? RsaExponentBase64 { get; set; }
    }

    private static DeviceLoginResponseDto MapLoginResult(LoginResult loginResult)
    {
        var Response = loginResult.Response;
        return new DeviceLoginResponseDto
        {
            Token = Response.Token,
            ExpiresIn = loginResult.ExpiresInSeconds,
            ExpiresAt = loginResult.ExpiresAt,
            UserId = Response.UserID,
            UserName = Response.UserName,
            Title = Response.Title,
            CanEditCustomer = Response.CanEditCustomer,
            CanRegisterCustomer = Response.CanRegisterCustomer,
            CanRegisterOrder = Response.CanRegisterOrder,
            CanRegisterReturnOrder = Response.CanRegisterReturnOrder,
            CanRegisterInvoice = Response.CanRegisterInvoice,
            CanRegisterReturnInvoice = Response.CanRegisterReturnInvoice,
            CanPrintInvoice = Response.CanPrintInvoice,
            CanPrintReturnInvoice = Response.CanPrintReturnInvoice,
            CanPrintInvoiceBeforeSend = Response.CanPrintInvoiceBeforeSend,
            CanPrintReturnInvoiceBeforeSend = Response.CanPrintReturnInvoiceBeforeSend,
            CanRevokeInvoice = Response.CanRevokeInvoice
        };
    }

    private sealed record LoginResponse
    {
        public string Token { get; set; } = string.Empty;
        public int ExpiresIn { get; set; }
        public int UserID { get; set; }
        public string? UserName { get; set; }
        public string? Title { get; set; }
        public bool CanEditCustomer { get; set; }
        public bool CanRegisterCustomer { get; set; }
        public bool CanRegisterOrder { get; set; }
        public bool CanRegisterReturnOrder { get; set; }
        public bool CanRegisterInvoice { get; set; }
        public bool CanRegisterReturnInvoice { get; set; }
        public bool CanPrintInvoice { get; set; }
        public bool CanPrintReturnInvoice { get; set; }
        public bool CanPrintInvoiceBeforeSend { get; set; }
        public bool CanPrintReturnInvoiceBeforeSend { get; set; }
        public bool CanRevokeInvoice { get; set; }
    }

    private sealed record LoginResult(LoginResponse Response, DateTimeOffset ExpiresAt, int ExpiresInSeconds)
    {
        public string Token => Response.Token;
    }

    private sealed class TenantAuthState
    {
        public SemaphoreSlim Lock { get; } = new(1, 1);
        public bool Registered { get; set; }
        public string? Token { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset LastAuthorizationCheck { get; set; } = DateTimeOffset.MinValue;
    }

    private static bool HasRsaConfigured(TenantCryptoOptions crypto)
    {
        return !string.IsNullOrWhiteSpace(crypto.RsaPublicKeyXml)
               || (!string.IsNullOrWhiteSpace(crypto.RsaModulusBase64) &&
                   !string.IsNullOrWhiteSpace(crypto.RsaExponentBase64));
    }
}
