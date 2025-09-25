using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;
using SepidarGateway.Contracts;

namespace SepidarGateway.Services;

public interface ISepidarGatewayService
{
    Task<RegisterDeviceRawResponse> RegisterDeviceAsync(DeviceRegisterRequestDto request, CancellationToken cancellationToken);

    Task<DeviceLoginRawResponse> LoginAsync(DeviceLoginRequestDto request, CancellationToken cancellationToken);

    Task<bool> EnsureAuthorizationAsync(CancellationToken cancellationToken);

    Task ProxyAsync(HttpContext context, string downstreamPath, CancellationToken cancellationToken);
}

public sealed class SepidarGatewayService : ISepidarGatewayService
{
    public const string ProxyClientName = "SepidarProxy";
    private static readonly TimeSpan RegisterCacheLifetime = TimeSpan.FromMinutes(2);

    private static readonly string[] HopByHopResponseHeaders =
    [
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailers",
        "Transfer-Encoding",
        "Upgrade"
    ];

    private readonly IOptionsMonitor<GatewayOptions> _optionsMonitor;
    private readonly ISepidarAuth _auth;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SepidarGatewayService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IRegisterPayloadCache _registerCache;

    public SepidarGatewayService(
        IOptionsMonitor<GatewayOptions> optionsMonitor,
        ISepidarAuth auth,
        IHttpClientFactory httpClientFactory,
        ILogger<SepidarGatewayService> logger,
        IConfiguration configuration,
        IRegisterPayloadCache registerCache)
    {
        _optionsMonitor = optionsMonitor;
        _auth = auth;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _configuration = configuration;
        _registerCache = registerCache;
    }

    public async Task<RegisterDeviceRawResponse> RegisterDeviceAsync(DeviceRegisterRequestDto request, CancellationToken cancellationToken)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var settings = GetSettings();

        if (string.IsNullOrWhiteSpace(request.DeviceSerial))
        {
            throw new InvalidOperationException("Missing 'deviceSerial'");
        }

        settings.Sepidar.DeviceSerial = request.DeviceSerial.Trim();
        settings.Sepidar.IntegrationId = DeriveIntegrationId(settings.Sepidar.DeviceSerial);
        settings.Sepidar.RegisterPayloadMode = "IntegrationOnly";

        if (string.IsNullOrWhiteSpace(settings.Sepidar.IntegrationId))
        {
            throw new InvalidOperationException("Unable to derive IntegrationID from deviceSerial");
        }

        try
        {
            var response = await _auth.RegisterDeviceAsync(settings, cancellationToken).ConfigureAwait(false);

            if (!TryCacheRegisterPayload(settings, response))
            {
                _registerCache.Clear();
            }

            return response;
        }
        catch (RegisterDeviceFailedException ex)
        {
            _registerCache.Clear();
            _logger.LogWarning(ex, "Sepidar register returned status {StatusCode} for device {DeviceSerial}", ex.Response.StatusCode, settings.Sepidar.DeviceSerial);
            return ex.Response;
        }
        catch (Exception ex)
        {
            _registerCache.Clear();
            _logger.LogError(ex, "Failed to register Sepidar device");
            throw;
        }
    }

    public async Task<DeviceLoginRawResponse> LoginAsync(DeviceLoginRequestDto request, CancellationToken cancellationToken)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var settings = GetSettings();
        ApplyConfiguredValues(settings);

        RegisterPayloadSnapshot? registerSnapshot;
        string? cachedSerial = settings.Sepidar.DeviceSerial?.Trim();

        if (_registerCache.TryGet(out var cachedEntry) && cachedEntry is not null)
        {
            cachedSerial = string.IsNullOrWhiteSpace(cachedEntry.DeviceSerial)
                ? cachedSerial
                : cachedEntry.DeviceSerial.Trim();

            if (!string.IsNullOrWhiteSpace(cachedEntry.DeviceTitle))
            {
                settings.Sepidar.DeviceTitle = cachedEntry.DeviceTitle;
            }

            registerSnapshot = new RegisterPayloadSnapshot
            {
                Cypher = cachedEntry.Cypher,
                IV = cachedEntry.IV,
                DeviceTitle = cachedEntry.DeviceTitle
            };
        }
        else
        {
            _logger.LogWarning("Register payload cache is empty before login for gateway {Gateway}", settings.Name);
            throw new InvalidOperationException("Register payload cache is empty. Please register the device again before logging in.");
        }

        if (!string.IsNullOrWhiteSpace(request.DeviceSerial))
        {
            cachedSerial = request.DeviceSerial.Trim();
        }

        if (!string.IsNullOrWhiteSpace(cachedSerial))
        {
            settings.Sepidar.DeviceSerial = cachedSerial;
        }

        if (string.IsNullOrWhiteSpace(settings.Credentials.UserName))
        {
            throw new InvalidOperationException("Sepidar username is not configured in the environment.");
        }

        if (string.IsNullOrWhiteSpace(settings.Credentials.Password))
        {
            throw new InvalidOperationException("Sepidar password is not configured in the environment.");
        }

        if (string.IsNullOrWhiteSpace(settings.Sepidar.IntegrationId))
        {
            throw new InvalidOperationException("Integration ID is not configured in app settings.");
        }

        if (string.IsNullOrWhiteSpace(settings.Sepidar.GenerationVersion))
        {
            throw new InvalidOperationException("Generation version is not configured in app settings.");
        }

        if (string.IsNullOrWhiteSpace(settings.Sepidar.DeviceSerial))
        {
            throw new InvalidOperationException("Device serial is not configured.");
        }

        try
        {
            return await _auth.LoginAsync(settings, registerSnapshot, cancellationToken).ConfigureAwait(false);
        }
        catch (AuthenticationFailedException)
        {
            _registerCache.Clear();
            throw;
        }
        catch
        {
            _registerCache.Clear();
            throw;
        }
    }

    public Task<bool> EnsureAuthorizationAsync(CancellationToken cancellationToken)
    {
        var settings = GetSettings();
        return _auth.IsAuthorizedAsync(settings, cancellationToken);
    }

    public async Task ProxyAsync(HttpContext context, string downstreamPath, CancellationToken cancellationToken)
    {
        var settings = GetSettings();
        var targetUri = BuildTargetUri(settings, downstreamPath, context.Request.QueryString);
        var httpClient = _httpClientFactory.CreateClient(ProxyClientName);

        _logger.LogDebug("Proxy {Method} {Path} -> {Uri}", context.Request.Method, downstreamPath, targetUri);

        using var requestMessage = await CreateProxyRequestAsync(context.Request, targetUri, cancellationToken).ConfigureAwait(false);
        using var responseMessage = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

        await CopyResponseAsync(context.Response, responseMessage, cancellationToken).ConfigureAwait(false);
    }

    private void ApplyConfiguredValues(GatewaySettings settings)
    {
        settings.Credentials.UserName = ResolveConfigurationValue(
                "Gateway:Settings:Credentials:UserName",
                settings.Credentials.UserName,
                settings)?.Trim() ?? string.Empty;

        settings.Credentials.Password = ResolveConfigurationValue(
                "Gateway:Settings:Credentials:Password",
                settings.Credentials.Password,
                settings)?.Trim() ?? string.Empty;

        settings.Sepidar.IntegrationId = ResolveConfigurationValue(
                "Gateway:Settings:Sepidar:IntegrationId",
                settings.Sepidar.IntegrationId,
                settings)?.Trim() ?? string.Empty;

        settings.Sepidar.GenerationVersion = ResolveConfigurationValue(
                "Gateway:Settings:Sepidar:GenerationVersion",
                settings.Sepidar.GenerationVersion,
                settings)?.Trim() ?? string.Empty;

        var configuredSerial = ResolveConfigurationValue(
            "Gateway:Settings:Sepidar:DeviceSerial",
            settings.Sepidar.DeviceSerial,
            settings);

        if (!string.IsNullOrWhiteSpace(configuredSerial))
        {
            settings.Sepidar.DeviceSerial = configuredSerial.Trim();
        }
    }

    private string? ResolveConfigurationValue(string key, string? fallback, GatewaySettings settings)
    {
        var value = _configuration[key];
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var envKey = key.Replace(":", "__", StringComparison.Ordinal);
        value = Environment.GetEnvironmentVariable(envKey);
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        if (!string.IsNullOrWhiteSpace(settings.Name))
        {
            var normalizedName = settings.Name.Trim();
            if (!string.IsNullOrEmpty(normalizedName))
            {
                var uppercaseName = normalizedName.Replace('-', '_').Replace(' ', '_').ToUpperInvariant();
                var segments = key.Split(':', StringSplitOptions.RemoveEmptyEntries);
                if (segments.Length >= 3)
                {
                    var suffix = string.Join('_', segments.Skip(2).Select(ToEnvToken));
                    var candidate = $"GW_{uppercaseName}_{suffix}";
                    value = Environment.GetEnvironmentVariable(candidate);
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        return value;
                    }
                }
            }
        }

        return fallback;
    }

    private static string ToEnvToken(string segment)
    {
        if (string.IsNullOrWhiteSpace(segment))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(segment.Length);
        foreach (var ch in segment)
        {
            if (char.IsLetterOrDigit(ch))
            {
                builder.Append(char.ToUpperInvariant(ch));
            }
            else
            {
                builder.Append('_');
            }
        }

        var token = builder.ToString().Trim('_');
        while (token.Contains("__", StringComparison.Ordinal))
        {
            token = token.Replace("__", "_", StringComparison.Ordinal);
        }

        return token;
    }

    private bool TryCacheRegisterPayload(GatewaySettings settings, RegisterDeviceRawResponse response)
    {
        if (response is null || string.IsNullOrWhiteSpace(response.Body))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(response.Body);
            var root = document.RootElement;

            var cypher = FindStringValue(root, "cypher");
            var iv = FindStringValue(root, "iv");
            var deviceTitle = FindStringValue(root, "deviceTitle");
            var deviceSerial = settings.Sepidar.DeviceSerial?.Trim();

            if (string.IsNullOrWhiteSpace(deviceSerial))
            {
                deviceSerial = FindStringValue(root, "deviceSerial")?.Trim();
            }

            if (string.IsNullOrWhiteSpace(cypher) || string.IsNullOrWhiteSpace(iv))
            {
                return false;
            }

            var entry = new RegisterPayloadCacheEntry(
                deviceSerial ?? string.Empty,
                cypher.Trim(),
                iv.Trim(),
                string.IsNullOrWhiteSpace(deviceTitle) ? null : deviceTitle.Trim());

            _registerCache.Store(entry, RegisterCacheLifetime);

            if (!string.IsNullOrWhiteSpace(entry.DeviceTitle))
            {
                settings.Sepidar.DeviceTitle = entry.DeviceTitle;
            }

            _logger.LogInformation(
                "Cached register payload for device {DeviceSerial} with lifetime {Lifetime}",
                entry.DeviceSerial,
                RegisterCacheLifetime);

            return true;
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse register payload for device {DeviceSerial}", settings.Sepidar.DeviceSerial);
            return false;
        }
    }

    private static string? FindStringValue(JsonElement element, string targetName)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.Name.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                {
                    if (property.Value.ValueKind == JsonValueKind.String)
                    {
                        return property.Value.GetString();
                    }

                    if (property.Value.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
                    {
                        return property.Value.GetRawText();
                    }
                }

                var nested = FindStringValue(property.Value, targetName);
                if (!string.IsNullOrWhiteSpace(nested))
                {
                    return nested;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var nested = FindStringValue(item, targetName);
                if (!string.IsNullOrWhiteSpace(nested))
                {
                    return nested;
                }
            }
        }

        return null;
    }

    private GatewaySettings GetSettings()
    {
        var settings = _optionsMonitor.CurrentValue.Settings;
        if (settings is null)
        {
            throw new InvalidOperationException("Gateway settings are not configured.");
        }

        return settings;
    }

    private static string DeriveIntegrationId(string serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return string.Empty;
        }

        var digits = new string(serial.Where(char.IsDigit).ToArray());
        if (digits.Length == 0)
        {
            return string.Empty;
        }

        if (digits.Length >= 4)
        {
            return digits[..4];
        }

        return digits.PadRight(4, '0');
    }

    private static Uri BuildTargetUri(GatewaySettings settings, string downstreamPath, QueryString queryString)
    {
        var baseUri = new Uri(settings.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var relativePath = (downstreamPath ?? string.Empty).TrimStart('/');
        var target = new Uri(baseUri, relativePath);
        if (!queryString.HasValue)
        {
            return target;
        }

        var builder = new UriBuilder(target)
        {
            Query = queryString.Value!.TrimStart('?')
        };
        return builder.Uri;
    }

    private static async Task<HttpRequestMessage> CreateProxyRequestAsync(HttpRequest sourceRequest, Uri targetUri, CancellationToken cancellationToken)
    {
        var requestMessage = new HttpRequestMessage(new HttpMethod(sourceRequest.Method), targetUri);

        foreach (var header in sourceRequest.Headers)
        {
            if (header.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
        }

        if (sourceRequest.ContentLength is > 0)
        {
            var stream = new MemoryStream();
            await sourceRequest.Body.CopyToAsync(stream, cancellationToken).ConfigureAwait(false);
            stream.Position = 0;
            if (sourceRequest.Body.CanSeek)
            {
                sourceRequest.Body.Position = 0;
            }

            var content = new StreamContent(stream);
            foreach (var header in sourceRequest.Headers)
            {
                if (header.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase))
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }

            requestMessage.Content = content;
        }
        else
        {
            var requiresEmptyBody = string.Equals(sourceRequest.Method, "POST", StringComparison.OrdinalIgnoreCase)
                || string.Equals(sourceRequest.Method, "PUT", StringComparison.OrdinalIgnoreCase)
                || string.Equals(sourceRequest.Method, "PATCH", StringComparison.OrdinalIgnoreCase);
            requestMessage.Content = requiresEmptyBody ? new StreamContent(Stream.Null) : null;
        }

        if (requestMessage.Content is null && sourceRequest.Headers.TryGetValue("Transfer-Encoding", out var transferEncoding))
        {
            foreach (var value in transferEncoding)
            {
                if (value?.Contains("chunked", StringComparison.OrdinalIgnoreCase) == true)
                {
                    requestMessage.Headers.TransferEncodingChunked = true;
                    break;
                }
            }
        }

        return requestMessage;
    }

    private static async Task CopyResponseAsync(HttpResponse destinationResponse, HttpResponseMessage sourceResponse, CancellationToken cancellationToken)
    {
        destinationResponse.StatusCode = (int)sourceResponse.StatusCode;

        foreach (var header in sourceResponse.Headers)
        {
            if (HopByHopResponseHeaders.Contains(header.Key, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            destinationResponse.Headers[header.Key] = header.Value.ToArray();
        }

        if (sourceResponse.Content is not null)
        {
            foreach (var header in sourceResponse.Content.Headers)
            {
                destinationResponse.Headers[header.Key] = header.Value.ToArray();
            }

            await sourceResponse.Content.CopyToAsync(destinationResponse.Body, cancellationToken).ConfigureAwait(false);
        }

        foreach (var header in HopByHopResponseHeaders)
        {
            destinationResponse.Headers.Remove(header);
        }
    }
}
