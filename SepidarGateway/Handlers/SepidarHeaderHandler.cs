using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;
using SepidarGateway.Auth;
using SepidarGateway.Crypto;
using SepidarGateway.Observability;
using Microsoft.Extensions.Options;
using SepidarGateway.Configuration;

namespace SepidarGateway.Handlers;

public sealed class SepidarHeaderHandler : DelegatingHandler
{
    private readonly IOptionsMonitor<GatewayOptions> _options;
    private readonly ISepidarAuth _auth;
    private readonly ISepidarCrypto _crypto;
    private readonly ILogger<SepidarHeaderHandler> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public SepidarHeaderHandler(
        IOptionsMonitor<GatewayOptions> options,
        ISepidarAuth auth,
        ISepidarCrypto crypto,
        ILogger<SepidarHeaderHandler> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _options = options;
        _auth = auth;
        _crypto = crypto;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage Request, CancellationToken CancellationToken)
    {
        var TenantOptions = _options.CurrentValue.Tenant;
        if (TenantOptions is null)
        {
            throw new InvalidOperationException("Tenant context missing for downstream request");
        }

        string effectivePath = Request.RequestUri?.AbsolutePath.Trim('/').ToLowerInvariant() ?? string.Empty;
        if (Request.RequestUri is { } OriginalUri)
        {
            var BaseUri = new Uri(TenantOptions.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
            var DownstreamUri = new Uri(BaseUri, OriginalUri.PathAndQuery.TrimStart('/'));
            var registerPathNormUri = (TenantOptions.Sepidar.RegisterPath ?? string.Empty).Trim('/').ToLowerInvariant();
            var isRegister = !string.IsNullOrEmpty(registerPathNormUri) &&
                             (effectivePath.Equals(registerPathNormUri, StringComparison.OrdinalIgnoreCase) ||
                              effectivePath.StartsWith(registerPathNormUri + "/", StringComparison.OrdinalIgnoreCase))
                             || effectivePath.Contains("/register", StringComparison.OrdinalIgnoreCase);
            var isLogin = effectivePath.Contains("/users/login", StringComparison.OrdinalIgnoreCase);
            var shouldAppendApiVersion = !(isRegister || isLogin);
            Request.RequestUri = shouldAppendApiVersion
                ? AppendApiVersionQuery(DownstreamUri, TenantOptions.Sepidar.ApiVersion)
                : DownstreamUri;
        }

        Request.Headers.Remove("GenerationVersion");
        Request.Headers.Remove("IntegrationID");
        Request.Headers.Remove("ArbitraryCode");
        Request.Headers.Remove("EncArbitraryCode");
        Request.Headers.Remove("api-version");

        Request.Headers.TryAddWithoutValidation("GenerationVersion", TenantOptions.Sepidar.GenerationVersion);
        Request.Headers.TryAddWithoutValidation("IntegrationID", TenantOptions.Sepidar.IntegrationId);

        if (!string.IsNullOrWhiteSpace(TenantOptions.Sepidar.ApiVersion))
        {
            Request.Headers.TryAddWithoutValidation("api-version", TenantOptions.Sepidar.ApiVersion);
        }

        var ArbitraryCode = Guid.NewGuid().ToString();
        // Only add ArbitraryCode headers if RSA is configured (post-registration)
        var hasRsa = !string.IsNullOrWhiteSpace(TenantOptions.Crypto.RsaPublicKeyXml)
                     || (!string.IsNullOrWhiteSpace(TenantOptions.Crypto.RsaModulusBase64)
                         && !string.IsNullOrWhiteSpace(TenantOptions.Crypto.RsaExponentBase64));
        if (hasRsa)
        {
            var EncryptedCode = _crypto.EncryptArbitraryCode(ArbitraryCode, TenantOptions.Crypto);
            Request.Headers.TryAddWithoutValidation("ArbitraryCode", ArbitraryCode);
            Request.Headers.TryAddWithoutValidation("EncArbitraryCode", EncryptedCode);
        }

        if (Request.Headers.Contains("Authorization"))
        {
            Request.Headers.Authorization = null;
        }

        // Avoid token acquisition on registration endpoint to prevent recursion and allow first-time register
        var registerPathNorm = (TenantOptions.Sepidar.RegisterPath ?? string.Empty).Trim('/').ToLowerInvariant();
        var skipToken = !string.IsNullOrEmpty(registerPathNorm) &&
                        (effectivePath.Equals(registerPathNorm, StringComparison.OrdinalIgnoreCase) ||
                         effectivePath.StartsWith(registerPathNorm + "/", StringComparison.OrdinalIgnoreCase));

        if (!skipToken)
        {
            try
            {
                // If caller provided manual token via Swagger Authorize (X-Sepidar-Token), use it.
                var ctx = _httpContextAccessor.HttpContext;
                if (ctx != null && ctx.Request.Headers.TryGetValue("X-Sepidar-Token", out var manualToken) && !string.IsNullOrWhiteSpace(manualToken))
                {
                    Request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", manualToken.ToString());
                }
                else
                {
                    var JwtToken = await _auth.EnsureTokenAsync(TenantOptions, CancellationToken).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(JwtToken))
                    {
                        Request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", JwtToken);
                    }
                }
            }
            catch (Exception ex)
            {
                // Allow downstream to decide (may return 401). Avoid turning it into 500.
                _logger.LogWarning(ex, "Proceeding without JWT for tenant {TenantId}", TenantOptions.TenantId);
            }
        }

        _logger.LogDebug("Forwarding request for tenant {TenantId} to {Uri}", TenantOptions.TenantId, Request.RequestUri);

        var CorrelationId = _httpContextAccessor.HttpContext?.Items[CorrelationIdMiddleware.HeaderName] as string;
        if (!string.IsNullOrWhiteSpace(CorrelationId))
        {
            Request.Headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, CorrelationId);
        }

        return await base.SendAsync(Request, CancellationToken).ConfigureAwait(false);
    }

    private static Uri AppendApiVersionQuery(Uri uri, string? apiVersion)
    {
        if (string.IsNullOrWhiteSpace(apiVersion))
        {
            return uri;
        }

        var Builder = new UriBuilder(uri);
        var ExistingQuery = Builder.Query;
        var TrimmedQuery = string.IsNullOrEmpty(ExistingQuery)
            ? string.Empty
            : ExistingQuery.TrimStart('?');

        var HasApiVersion = TrimmedQuery
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Any(Part => Part.StartsWith("api-version=", StringComparison.OrdinalIgnoreCase));

        if (HasApiVersion)
        {
            return Builder.Uri;
        }

        var EncodedValue = Uri.EscapeDataString(apiVersion);
        Builder.Query = string.IsNullOrEmpty(TrimmedQuery)
            ? $"api-version={EncodedValue}"
            : $"{TrimmedQuery}&api-version={EncodedValue}";

        return Builder.Uri;
    }
}
