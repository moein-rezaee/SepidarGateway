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
        var tenant_options = _tenantAccessor.CurrentTenant?.Options;
        if (tenant_options is null)
        {
            throw new InvalidOperationException("Tenant context missing for downstream request");
        }

        if (request.RequestUri is { } original_uri)
        {
            var base_uri = new Uri(tenant_options.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
            var downstream_uri = new Uri(base_uri, original_uri.PathAndQuery.TrimStart('/'));
            request.RequestUri = downstream_uri;
        }

        request.Headers.Remove("GenerationVersion");
        request.Headers.Remove("IntegrationID");
        request.Headers.Remove("ArbitraryCode");
        request.Headers.Remove("EncArbitraryCode");

        request.Headers.TryAddWithoutValidation("GenerationVersion", tenant_options.Sepidar.GenerationVersion);
        request.Headers.TryAddWithoutValidation("IntegrationID", tenant_options.Sepidar.IntegrationId);

        var arbitrary_code = Guid.NewGuid().ToString();
        var encrypted_code = _crypto.EncryptArbitraryCode(arbitrary_code, tenant_options.Crypto);
        request.Headers.TryAddWithoutValidation("ArbitraryCode", arbitrary_code);
        request.Headers.TryAddWithoutValidation("EncArbitraryCode", encrypted_code);

        if (request.Headers.Contains("Authorization"))
        {
            request.Headers.Authorization = null;
        }

        try
        {
            var jwt_token = await _auth.EnsureTokenAsync(tenant_options, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(jwt_token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt_token);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to ensure JWT for tenant {TenantId}", tenant_options.TenantId);
            throw;
        }

        _logger.LogDebug("Forwarding request for tenant {TenantId} to {Uri}", tenant_options.TenantId, request.RequestUri);

        var correlation_id = _httpContextAccessor.HttpContext?.Items[CorrelationIdMiddleware.HeaderName] as string;
        if (!string.IsNullOrWhiteSpace(correlation_id))
        {
            request.Headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, correlation_id);
        }

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
