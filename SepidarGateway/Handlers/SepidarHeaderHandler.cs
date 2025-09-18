using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;
using SepidarGateway.Auth;
using SepidarGateway.Crypto;
using SepidarGateway.Observability;
using SepidarGateway.Tenancy;

namespace SepidarGateway.Handlers;

public sealed class SepidarHeaderHandler : DelegatingHandler
{
    private readonly ITenantContextAccessor _tenantAccessor;
    private readonly ISepidarAuth _auth;
    private readonly ISepidarCrypto _crypto;
    private readonly ILogger<SepidarHeaderHandler> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public SepidarHeaderHandler(
        ITenantContextAccessor tenantAccessor,
        ISepidarAuth auth,
        ISepidarCrypto crypto,
        ILogger<SepidarHeaderHandler> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _tenantAccessor = tenantAccessor;
        _auth = auth;
        _crypto = crypto;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var tenant = _tenantAccessor.CurrentTenant?.Options;
        if (tenant is null)
        {
            throw new InvalidOperationException("Tenant context missing for downstream request");
        }

        if (request.RequestUri is { } originalUri)
        {
            var baseUri = new Uri(tenant.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
            var downstreamUri = new Uri(baseUri, originalUri.PathAndQuery.TrimStart('/'));
            request.RequestUri = downstreamUri;
        }

        request.Headers.Remove("GenerationVersion");
        request.Headers.Remove("IntegrationID");
        request.Headers.Remove("ArbitraryCode");
        request.Headers.Remove("EncArbitraryCode");

        request.Headers.TryAddWithoutValidation("GenerationVersion", tenant.Sepidar.GenerationVersion);
        request.Headers.TryAddWithoutValidation("IntegrationID", tenant.Sepidar.IntegrationId);

        var arbitraryCode = Guid.NewGuid().ToString();
        var encArbitraryCode = _crypto.EncryptArbitraryCode(arbitraryCode, tenant.Crypto);
        request.Headers.TryAddWithoutValidation("ArbitraryCode", arbitraryCode);
        request.Headers.TryAddWithoutValidation("EncArbitraryCode", encArbitraryCode);

        if (request.Headers.Contains("Authorization"))
        {
            request.Headers.Authorization = null;
        }

        try
        {
            var token = await _auth.EnsureTokenAsync(tenant, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to ensure JWT for tenant {TenantId}", tenant.TenantId);
            throw;
        }

        _logger.LogDebug("Forwarding request for tenant {TenantId} to {Uri}", tenant.TenantId, request.RequestUri);

        var correlationId = _httpContextAccessor.HttpContext?.Items[CorrelationIdMiddleware.HeaderName] as string;
        if (!string.IsNullOrWhiteSpace(correlationId))
        {
            request.Headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, correlationId);
        }

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
