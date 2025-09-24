using System.IO;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;
using SepidarGateway.Contracts;

namespace SepidarGateway.Services;

public interface ISepidarGatewayService
{
    Task<string> RegisterDeviceAsync(DeviceRegisterRequestDto request, CancellationToken cancellationToken);

    Task<DeviceLoginResponseDto> LoginAsync(DeviceLoginRequestDto request, CancellationToken cancellationToken);

    Task<bool> EnsureAuthorizationAsync(CancellationToken cancellationToken);

    Task ProxyAsync(HttpContext context, string downstreamPath, CancellationToken cancellationToken);
}

public sealed class SepidarGatewayService : ISepidarGatewayService
{
    public const string ProxyClientName = "SepidarProxy";

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

    public SepidarGatewayService(
        IOptionsMonitor<GatewayOptions> optionsMonitor,
        ISepidarAuth auth,
        IHttpClientFactory httpClientFactory,
        ILogger<SepidarGatewayService> logger)
    {
        _optionsMonitor = optionsMonitor;
        _auth = auth;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<string> RegisterDeviceAsync(DeviceRegisterRequestDto request, CancellationToken cancellationToken)
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
            var response = await _auth.EnsureDeviceRegisteredAsync(settings, cancellationToken).ConfigureAwait(false);
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to register Sepidar device");
            throw;
        }
    }

    public async Task<DeviceLoginResponseDto> LoginAsync(DeviceLoginRequestDto request, CancellationToken cancellationToken)
    {
        var settings = GetSettings();
        if (!string.IsNullOrWhiteSpace(request.UserName))
        {
            settings.Credentials.UserName = request.UserName.Trim();
        }

        if (!string.IsNullOrWhiteSpace(request.Password))
        {
            settings.Credentials.Password = request.Password.Trim();
        }

        return await _auth.LoginAsync(settings, cancellationToken).ConfigureAwait(false);
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
