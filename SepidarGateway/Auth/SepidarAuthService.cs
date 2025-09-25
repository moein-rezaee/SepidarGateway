using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;

namespace SepidarGateway.Auth;

public sealed class SepidarAuthService : ISepidarAuth
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISepidarCrypto _crypto;
    private readonly ILogger<SepidarAuthService> _logger;
    private readonly AuthState _state = new();
    private static readonly TimeSpan RegisterCacheLifetime = TimeSpan.FromMinutes(2);

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

    public async Task EnsureDeviceRegisteredAsync(GatewaySettings tenant, CancellationToken cancellationToken)
    {
        var authState = _state;
        if (!authState.Registered && HasRsaConfigured(tenant.Crypto))
        {
            // Assume device already registered when RSA is pre-provisioned via configuration
            authState.Registered = true;
            authState.LastRegisterResponse ??= RegisterDeviceRawResponse.Empty;
            authState.RegisterCacheEntry = null;
            authState.RegisterExpiresAt = DateTimeOffset.MaxValue;
            return;
        }

        if (authState.Registered && authState.RegisterExpiresAt > DateTimeOffset.UtcNow)
        {
            return;
        }

        await authState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!authState.Registered && HasRsaConfigured(tenant.Crypto))
            {
                authState.Registered = true;
                authState.LastRegisterResponse ??= RegisterDeviceRawResponse.Empty;
                authState.RegisterCacheEntry = null;
                authState.RegisterExpiresAt = DateTimeOffset.MaxValue;
                return;
            }

            if (authState.Registered && authState.RegisterExpiresAt > DateTimeOffset.UtcNow)
            {
                return;
            }

            var registerResult = await RegisterInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            UpdateRegisterCache(authState, registerResult.Response, registerResult.CacheEntry);
        }
        finally
        {
            authState.Lock.Release();
        }
    }

    public async Task<RegisterDeviceRawResponse> RegisterDeviceAsync(GatewaySettings tenant, CancellationToken cancellationToken)
    {
        var authState = _state;
        await authState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (authState.Registered &&
                authState.RegisterExpiresAt > DateTimeOffset.UtcNow &&
                authState.LastRegisterResponse is { } cached)
            {
                return cached;
            }

            var registerResult = await RegisterInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            UpdateRegisterCache(authState, registerResult.Response, registerResult.CacheEntry);
            return registerResult.Response;
        }
        finally
        {
            authState.Lock.Release();
        }
    }

    public async Task<string> EnsureTokenAsync(GatewaySettings tenant, CancellationToken cancellationToken)
    {
        var authState = _state;
        await EnsureDeviceRegisteredAsync(tenant, cancellationToken).ConfigureAwait(false);

        if (authState.Token is { } cachedToken && authState.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
        {
            return cachedToken;
        }

        await authState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (authState.Token is { } freshToken && authState.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
            {
                return freshToken;
            }

            if (authState.RegisterCacheEntry is null && authState.RegisterExpiresAt <= DateTimeOffset.UtcNow)
            {
                throw new InvalidOperationException("Device registration cache is empty. Please register the device again.");
            }

            var LoginResult = await LoginInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            authState.Token = LoginResult.Token;
            authState.ExpiresAt = LoginResult.ExpiresAt;
            return LoginResult.Token;
        }
        finally
        {
            authState.Lock.Release();
        }
    }

    public async Task<DeviceLoginRawResponse> LoginAsync(GatewaySettings tenant, CancellationToken cancellationToken)
    {
        var authState = _state;
        await EnsureDeviceRegisteredAsync(tenant, cancellationToken).ConfigureAwait(false);

        await authState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (authState.RegisterCacheEntry is null && authState.RegisterExpiresAt <= DateTimeOffset.UtcNow)
            {
                throw new InvalidOperationException("Device registration cache is empty. Please register the device again.");
            }

            var LoginResult = await LoginInternalAsync(tenant, cancellationToken).ConfigureAwait(false);
            authState.Token = LoginResult.Token;
            authState.ExpiresAt = LoginResult.ExpiresAt;
            return LoginResult.RawResponse;
        }
        finally
        {
            authState.Lock.Release();
        }
    }

    public async Task<bool> IsAuthorizedAsync(GatewaySettings tenant, CancellationToken cancellationToken)
    {
        var authState = _state;
        if (authState.Token is null)
        {
            return false;
        }

        if (authState.LastAuthorizationCheck + TimeSpan.FromSeconds(tenant.Jwt.PreAuthCheckSeconds) > DateTimeOffset.UtcNow)
        {
            return true;
        }

        await authState.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (authState.Token is null)
            {
                return false;
            }

            if (authState.LastAuthorizationCheck + TimeSpan.FromSeconds(tenant.Jwt.PreAuthCheckSeconds) > DateTimeOffset.UtcNow)
            {
                return true;
            }

            var HttpClient = CreateHttpClient(tenant);
            using var RequestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                BuildTenantUri(tenant, tenant.Sepidar.IsAuthorizedPath, includeApiVersionQuery: true));
            PrepareHeaders(RequestMessage.Headers, tenant, authState.Token);

            using var HttpResponse = await HttpClient.SendAsync(RequestMessage, cancellationToken).ConfigureAwait(false);
            if (HttpResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("JWT expired for gateway {Gateway}", tenant.Name);
                InvalidateToken();
                return false;
            }

            HttpResponse.EnsureSuccessStatusCode();
            var ResponseContent = await HttpResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var Authorized = bool.TryParse(ResponseContent, out var ParsedValue)
                             ? ParsedValue
                             : ResponseContent.Contains("true", StringComparison.OrdinalIgnoreCase);
            authState.LastAuthorizationCheck = DateTimeOffset.UtcNow;
            if (!Authorized)
            {
                InvalidateToken();
            }

            return Authorized;
        }
        finally
        {
            authState.Lock.Release();
        }
    }

    public void InvalidateToken()
    {
        var authState = _state;
        authState.Token = null;
        authState.ExpiresAt = DateTimeOffset.MinValue;
        authState.LastAuthorizationCheck = DateTimeOffset.MinValue;
    }

    private async Task<RegisterResult> RegisterInternalAsync(GatewaySettings tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Registering Sepidar device for gateway {Gateway}", tenant.Name);
        var HttpClient = CreateHttpClient(tenant);

        string DevicePayload = string.Empty;
        var payloadMode = tenant.Sepidar.RegisterPayloadMode?.Trim();
        if (string.IsNullOrWhiteSpace(payloadMode))
        {
            payloadMode = "Detailed";
        }

        var integrationIdValue = (tenant.Sepidar.IntegrationId ?? string.Empty).Trim();
        tenant.Sepidar.IntegrationId = integrationIdValue;
        if (string.Equals(payloadMode, "IntegrationOnly", StringComparison.OrdinalIgnoreCase))
        {
            DevicePayload = integrationIdValue;
        }
        else if (string.Equals(payloadMode, "SimpleTitle", StringComparison.OrdinalIgnoreCase))
        {
            var title = string.IsNullOrWhiteSpace(tenant.Sepidar.DeviceTitle)
                ? (tenant.Sepidar.DeviceSerial ?? string.Empty)
                : tenant.Sepidar.DeviceTitle!;
            DevicePayload = title;
        }
        else
        {
            DevicePayload = JsonSerializer.Serialize(new
            {
                DeviceSerial = tenant.Sepidar.DeviceSerial ?? string.Empty,
                IntegrationId = integrationIdValue,
                Timestamp = DateTimeOffset.UtcNow
            }, PreserveNamesOptions);
        }

        if (string.IsNullOrWhiteSpace(integrationIdValue))
        {
            throw new InvalidOperationException("Integration ID is not configured.");
        }

        if (!int.TryParse(integrationIdValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var integrationIdNumber))
        {
            throw new InvalidOperationException($"Integration ID '{integrationIdValue}' is not numeric.");
        }

        var variantBodies = new List<string>();

        if (string.Equals(payloadMode, "IntegrationOnly", StringComparison.OrdinalIgnoreCase))
        {
            var enc128 = _crypto.EncryptRegisterPayload(tenant.Sepidar.DeviceSerial ?? string.Empty, DevicePayload, 16);
            variantBodies.Add(JsonSerializer.Serialize(new
            {
                Cypher = enc128.CipherText,
                IV = enc128.IvBase64,
                IntegrationID = integrationIdNumber
            }, PreserveNamesOptions));

            var enc256 = _crypto.EncryptRegisterPayload(tenant.Sepidar.DeviceSerial ?? string.Empty, DevicePayload, 32);
            if (!string.Equals(enc256.CipherText, enc128.CipherText, StringComparison.Ordinal) ||
                !string.Equals(enc256.IvBase64, enc128.IvBase64, StringComparison.Ordinal))
            {
                variantBodies.Add(JsonSerializer.Serialize(new
                {
                    Cypher = enc256.CipherText,
                    IV = enc256.IvBase64,
                    IntegrationID = integrationIdNumber
                }, PreserveNamesOptions));
            }
        }
        else
        {
            var encryptedPayload = _crypto.EncryptRegisterPayload(tenant.Sepidar.DeviceSerial ?? string.Empty, DevicePayload);
            if (string.Equals(payloadMode, "SimpleTitle", StringComparison.OrdinalIgnoreCase))
            {
                variantBodies.Add(JsonSerializer.Serialize(new
                {
                    Cypher = encryptedPayload.CipherText,
                    IV = encryptedPayload.IvBase64,
                    IntegrationID = integrationIdNumber
                }, PreserveNamesOptions));
            }
            else
            {
                variantBodies.Add(JsonSerializer.Serialize(new
                {
                    Cypher = encryptedPayload.CipherText,
                    IV = encryptedPayload.IvBase64,
                    IntegrationID = integrationIdNumber,
                    DeviceSerial = tenant.Sepidar.DeviceSerial ?? string.Empty
                }, PreserveNamesOptions));
            }
        }

        var AttemptedPaths = new List<string>();
        var ProcessedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var RegisterQueue = new Queue<string>(EnumerateRegisterPaths(tenant));
        var DiscoveryAttempted = false;
        RegisterAttemptResult? lastFailure = null;

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

                RegisterAttemptResult? registerResult = null;
                foreach (var body in variantBodies)
                {
                    registerResult = await AttemptRegisterAsync(HttpClient, tenant, RegisterPath, body, includeApiVersion: false, cancellationToken).ConfigureAwait(false);
                    if (registerResult is { Success: true })
                    {
                        return new RegisterResult(registerResult.Response, registerResult.CacheEntry);
                    }

                    if (registerResult is not null)
                    {
                        lastFailure = registerResult;
                    }

                    registerResult = await AttemptRegisterAsync(HttpClient, tenant, RegisterPath, body, includeApiVersion: true, cancellationToken).ConfigureAwait(false);
                    if (registerResult is { Success: true })
                    {
                        return new RegisterResult(registerResult.Response, registerResult.CacheEntry);
                    }

                    if (registerResult is not null)
                    {
                        lastFailure = registerResult;
                    }
                }
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

        if (lastFailure is { } failure)
        {
            throw new RegisterDeviceFailedException(
                failure.Response,
                $"Register endpoint {failure.Path} returned status code {failure.Response.StatusCode} for gateway {tenant.Name}.");
        }

        throw new HttpRequestException($"No register endpoint returned a successful response. Attempted: {string.Join(", ", AttemptedPaths)}");
    }

    private async Task<IEnumerable<string>> DiscoverRegisterPathsAsync(GatewaySettings tenant, CancellationToken cancellationToken)
    {
        try
        {
            var HttpClient = CreateHttpClient(tenant);
            var SwaggerUri = BuildTenantUri(tenant, tenant.Sepidar.SwaggerDocumentPath);
            using var SwaggerRequest = new HttpRequestMessage(HttpMethod.Get, SwaggerUri);
            using var SwaggerResponse = await HttpClient.SendAsync(SwaggerRequest, cancellationToken).ConfigureAwait(false);

            if (!SwaggerResponse.IsSuccessStatusCode)
            {
                _logger.LogWarning("Failed to resolve register path from Swagger for gateway {Gateway}. Status code {StatusCode}", tenant.Name, (int)SwaggerResponse.StatusCode);
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
                _logger.LogInformation("Discovered register endpoints from Swagger for gateway {Gateway}: {Paths}", tenant.Name, string.Join(", ", RegisterPaths));
            }

            return RegisterPaths;
        }
        catch (Exception DiscoveryException) when (DiscoveryException is HttpRequestException or JsonException or InvalidOperationException)
        {
            _logger.LogWarning(DiscoveryException, "Unable to auto-discover register endpoints for gateway {Gateway}", tenant.Name);
            return Array.Empty<string>();
        }
    }

    private async Task<RegisterAttemptResult?> AttemptRegisterAsync(HttpClient httpClient, GatewaySettings tenant, string registerPath, string requestBody, bool includeApiVersion, CancellationToken cancellationToken)
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
                "Register endpoint {Path} connection failed for gateway {Gateway}. URI: {Uri}. SocketError: {SocketError}",
                registerPath,
                tenant.Name,
                registerUri,
                socketException.SocketErrorCode);
            return null;
        }

        using (response)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var contentType = response.Content.Headers.ContentType?.ToString();
            var rawResponse = new RegisterDeviceRawResponse(responseBody, contentType, (int)response.StatusCode);

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger.LogWarning("Register endpoint {Path} not found for gateway {Gateway} (URI: {Uri})", registerPath, tenant.Name, registerUri);
                return new RegisterAttemptResult(registerPath, rawResponse, Success: false, null);
            }

            if (!response.IsSuccessStatusCode)
            {
                var snippet = responseBody.Length > 500 ? responseBody[..500] + "..." : responseBody;
                _logger.LogError("Register endpoint {Path} returned {StatusCode} for gateway {Gateway}. URI: {Uri}. Body: {Body}", registerPath, (int)response.StatusCode, tenant.Name, registerUri, snippet);
                return new RegisterAttemptResult(registerPath, rawResponse, Success: false, null);
            }

            var registerPayload = ParseRegisterResponse(responseBody);
            if (registerPayload is null)
            {
                var snippet = responseBody.Length > 500 ? responseBody[..500] + "..." : responseBody;
                _logger.LogError("Register endpoint {Path} returned an unrecognized payload for gateway {Gateway}. URI: {Uri}. Body: {Body}", registerPath, tenant.Name, registerUri, snippet);
                return new RegisterAttemptResult(registerPath, rawResponse, Success: false, null);
            }

            var plainText = _crypto.DecryptRegisterPayload(
                tenant.Sepidar.DeviceSerial ?? string.Empty,
                registerPayload.Cypher,
                registerPayload.IV);

            var tenantCrypto = ParseRegisterCryptoResponse(plainText)
                               ?? throw new InvalidOperationException("Invalid crypto payload");

            tenant.Crypto.RsaPublicKeyXml = tenantCrypto.RsaPublicKeyXml;
            tenant.Crypto.RsaModulusBase64 = tenantCrypto.RsaModulusBase64;
            tenant.Crypto.RsaExponentBase64 = tenantCrypto.RsaExponentBase64;

            if (!string.IsNullOrWhiteSpace(registerPayload.DeviceTitle))
            {
                tenant.Sepidar.DeviceTitle = registerPayload.DeviceTitle;
            }

            var cacheEntry = new RegisterCacheEntry
            {
                Cypher = registerPayload.Cypher,
                IV = registerPayload.IV,
                DeviceTitle = registerPayload.DeviceTitle,
                CachedAt = DateTimeOffset.UtcNow
            };

            return new RegisterAttemptResult(registerPath, rawResponse, Success: true, cacheEntry);
        }
    }

    private sealed record RegisterAttemptResult(string Path, RegisterDeviceRawResponse Response, bool Success, RegisterCacheEntry? CacheEntry);

    private sealed record RegisterResult(RegisterDeviceRawResponse Response, RegisterCacheEntry? CacheEntry);

    private async Task<LoginResult> LoginInternalAsync(GatewaySettings tenant, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Logging in gateway {Gateway}", tenant.Name);
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

        var integrationId = (tenant.Sepidar.IntegrationId ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(integrationId))
        {
            throw new InvalidOperationException("Integration ID is not configured.");
        }

        var LoginUri = BuildTenantUri(tenant, tenant.Sepidar.LoginPath, includeApiVersionQuery: false);

        using var LoginRequest = new HttpRequestMessage(HttpMethod.Post, LoginUri);
        // هدر api-version برای Login ارسال نمی‌شود تا کاملاً مطابق کرل باشد

        LoginRequest.Headers.Add("GenerationVersion", tenant.Sepidar.GenerationVersion);
        LoginRequest.Headers.Add("IntegrationID", integrationId);
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
        if (LoginResponseMessage.StatusCode == HttpStatusCode.PreconditionFailed)
        {
            throw new InvalidOperationException("Generation version mismatch");
        }

        var ResponseContent = await LoginResponseMessage.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var ContentType = LoginResponseMessage.Content.Headers.ContentType?.ToString();

        if (LoginResponseMessage.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            var errorMessage = ExtractLoginErrorMessage(ResponseContent, LoginResponseMessage.StatusCode);
            var rawError = new DeviceLoginRawResponse(ResponseContent, ContentType, (int)LoginResponseMessage.StatusCode);
            throw new AuthenticationFailedException(errorMessage, rawError);
        }

        LoginResponseMessage.EnsureSuccessStatusCode();
        var LoginResponse = JsonSerializer.Deserialize<LoginResponse>(ResponseContent, SerializerOptions)
                           ?? throw new InvalidOperationException("Invalid login response");

        var ExpiresInSeconds = LoginResponse.ExpiresIn > 0 ? LoginResponse.ExpiresIn : tenant.Jwt.CacheSeconds;
        var TokenExpiry = DateTimeOffset.UtcNow.AddSeconds(Math.Min(tenant.Jwt.CacheSeconds, ExpiresInSeconds));

        var rawSuccess = new DeviceLoginRawResponse(ResponseContent, ContentType, (int)LoginResponseMessage.StatusCode);

        return new LoginResult(LoginResponse, TokenExpiry, ExpiresInSeconds, rawSuccess);
    }

    private static string ExtractLoginErrorMessage(string? responseBody, HttpStatusCode statusCode)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return statusCode switch
            {
                HttpStatusCode.BadRequest => "Sepidar rejected the login request.",
                HttpStatusCode.Forbidden => "The Sepidar user does not have permission to sign in.",
                HttpStatusCode.Unauthorized => "Invalid Sepidar credentials.",
                _ => "Sepidar login failed."
            };
        }

        var trimmed = responseBody.Trim();
        if (trimmed.StartsWith('{') && trimmed.EndsWith('}'))
        {
            try
            {
                using var document = JsonDocument.Parse(trimmed);
                if (document.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var property in document.RootElement.EnumerateObject())
                    {
                        if (!property.Name.Equals("message", StringComparison.OrdinalIgnoreCase) &&
                            !property.Name.EndsWith("Message", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        if (property.Value.ValueKind == JsonValueKind.String)
                        {
                            var message = property.Value.GetString();
                            if (!string.IsNullOrWhiteSpace(message))
                            {
                                return message;
                            }
                        }
                    }
                }

                if (document.RootElement.ValueKind == JsonValueKind.String)
                {
                    var rootMessage = document.RootElement.GetString();
                    if (!string.IsNullOrWhiteSpace(rootMessage))
                    {
                        return rootMessage;
                    }
                }
            }
            catch (JsonException)
            {
                // Fall through to plain text handling
            }
        }

        return trimmed.Length > 512 ? trimmed[..512] : trimmed;
    }

    private HttpClient CreateHttpClient(GatewaySettings tenant)
    {
        var HttpClient = _httpClientFactory.CreateClient("SepidarAuth");
        HttpClient.Timeout = TimeSpan.FromSeconds(60);
        return HttpClient;
    }

    private Uri BuildTenantUri(GatewaySettings tenant, string relativePath, bool includeApiVersionQuery = false)
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

    private IEnumerable<string> EnumerateRegisterPaths(GatewaySettings tenant)
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

    private static IEnumerable<string> EnumerateCandidateSources(GatewaySettings tenant)
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

    private void PrepareHeaders(HttpRequestHeaders headers, GatewaySettings tenant, string token)
    {
        headers.TryAddWithoutValidation("GenerationVersion", tenant.Sepidar.GenerationVersion);
        var integrationId = (tenant.Sepidar.IntegrationId ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(integrationId))
        {
            throw new InvalidOperationException("Integration ID is not configured.");
        }

        headers.TryAddWithoutValidation("IntegrationID", integrationId);

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

    private static RegisterResponse? ParseRegisterResponse(string responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return null;
        }

        var trimmed = responseBody.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        if (trimmed[0] == '<')
        {
            try
            {
                var document = XDocument.Parse(trimmed);
                var root = document.Root;
                if (root is null)
                {
                    return null;
                }

                static string? ReadElement(XElement rootElement, string name)
                {
                    return rootElement
                        .Descendants()
                        .FirstOrDefault(e => string.Equals(e.Name.LocalName, name, StringComparison.OrdinalIgnoreCase))?
                        .Value;
                }

                var cypher = ReadElement(root, "Cypher");
                var iv = ReadElement(root, "IV");
                var deviceTitle = ReadElement(root, "DeviceTitle");

                if (string.IsNullOrWhiteSpace(cypher) || string.IsNullOrWhiteSpace(iv))
                {
                    return null;
                }

                return new RegisterResponse
                {
                    Cypher = cypher.Trim(),
                    IV = iv.Trim(),
                    DeviceTitle = string.IsNullOrWhiteSpace(deviceTitle) ? null : deviceTitle.Trim()
                };
            }
            catch (Exception ex) when (ex is XmlException or InvalidOperationException)
            {
                return null;
            }
        }

        try
        {
            return JsonSerializer.Deserialize<RegisterResponse>(trimmed, SerializerOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed class RegisterResponse
    {
        public string Cypher { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
        public string? DeviceTitle { get; set; }
            = null;
    }

    private static RegisterCryptoResponse? ParseRegisterCryptoResponse(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        var trimmed = payload.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        if (trimmed[0] == '<')
        {
            try
            {
                var document = XDocument.Parse(trimmed);
                var root = document.Root;
                if (root is null)
                {
                    return null;
                }

                static string? ReadElement(XElement rootElement, string name)
                {
                    return rootElement
                        .Descendants()
                        .FirstOrDefault(e => string.Equals(e.Name.LocalName, name, StringComparison.OrdinalIgnoreCase))?
                        .Value;
                }

                var publicKeyXml = ReadElement(root, "RsaPublicKeyXml");
                var modulus = ReadElement(root, "RsaModulusBase64");
                var exponent = ReadElement(root, "RsaExponentBase64");

                if (string.IsNullOrWhiteSpace(publicKeyXml))
                {
                    var rsaNode = root
                        .Descendants()
                        .FirstOrDefault(e => string.Equals(e.Name.LocalName, "RSAKeyValue", StringComparison.OrdinalIgnoreCase));

                    if (rsaNode is not null)
                    {
                        publicKeyXml = rsaNode.ToString(SaveOptions.DisableFormatting);
                    }
                    else if (string.Equals(root.Name.LocalName, "RSAKeyValue", StringComparison.OrdinalIgnoreCase))
                    {
                        publicKeyXml = root.ToString(SaveOptions.DisableFormatting);
                    }
                }

                return new RegisterCryptoResponse
                {
                    RsaPublicKeyXml = string.IsNullOrWhiteSpace(publicKeyXml) ? null : publicKeyXml,
                    RsaModulusBase64 = string.IsNullOrWhiteSpace(modulus) ? null : modulus.Trim(),
                    RsaExponentBase64 = string.IsNullOrWhiteSpace(exponent) ? null : exponent.Trim()
                };
            }
            catch (Exception ex) when (ex is XmlException or InvalidOperationException)
            {
                return null;
            }
        }

        try
        {
            return JsonSerializer.Deserialize<RegisterCryptoResponse>(trimmed, SerializerOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed record RegisterCryptoResponse
    {
        public string? RsaPublicKeyXml { get; set; }
        public string? RsaModulusBase64 { get; set; }
        public string? RsaExponentBase64 { get; set; }
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

    private sealed record LoginResult(LoginResponse Response, DateTimeOffset ExpiresAt, int ExpiresInSeconds, DeviceLoginRawResponse RawResponse)
    {
        public string Token => Response.Token;
    }

    private sealed class AuthState
    {
        public SemaphoreSlim Lock { get; } = new(1, 1);
        public bool Registered { get; set; }
        public RegisterDeviceRawResponse? LastRegisterResponse { get; set; }
        public string? Token { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset LastAuthorizationCheck { get; set; } = DateTimeOffset.MinValue;
        public RegisterCacheEntry? RegisterCacheEntry { get; set; }
        public DateTimeOffset RegisterExpiresAt { get; set; } = DateTimeOffset.MinValue;
    }

    private void UpdateRegisterCache(AuthState authState, RegisterDeviceRawResponse response, RegisterCacheEntry? cacheEntry)
    {
        authState.Registered = true;
        authState.LastRegisterResponse = response;
        authState.RegisterCacheEntry = cacheEntry;
        authState.RegisterExpiresAt = DateTimeOffset.UtcNow.Add(RegisterCacheLifetime);
        authState.Token = null;
        authState.ExpiresAt = DateTimeOffset.MinValue;
        authState.LastAuthorizationCheck = DateTimeOffset.MinValue;
    }

    private sealed class RegisterCacheEntry
    {
        public string Cypher { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
        public string? DeviceTitle { get; set; }
            = null;
        public DateTimeOffset CachedAt { get; set; } = DateTimeOffset.MinValue;
    }

    private static bool HasRsaConfigured(CryptoOptions crypto)
    {
        return !string.IsNullOrWhiteSpace(crypto.RsaPublicKeyXml)
               || (!string.IsNullOrWhiteSpace(crypto.RsaModulusBase64) &&
                   !string.IsNullOrWhiteSpace(crypto.RsaExponentBase64));
    }
}
