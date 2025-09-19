using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
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

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage Request, CancellationToken CancellationToken)
    {
        var TenantOptions = _tenantAccessor.CurrentTenant?.Options;
        if (TenantOptions is null)
        {
            throw new InvalidOperationException("Tenant context missing for downstream request");
        }

        if (Request.RequestUri is { } OriginalUri)
        {
            var BaseUri = new Uri(TenantOptions.Sepidar.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
            var DownstreamUri = new Uri(BaseUri, OriginalUri.PathAndQuery.TrimStart('/'));

            if (!string.IsNullOrWhiteSpace(TenantOptions.Sepidar.GenerationVersion))
            {
                var UriBuilder = new UriBuilder(DownstreamUri);
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

                    QueryBuilder.Add("api-version", TenantOptions.Sepidar.GenerationVersion);
                    UriBuilder.Query = QueryBuilder.ToQueryString().Value?.TrimStart('?') ?? string.Empty;
                    DownstreamUri = UriBuilder.Uri;
                }
            }

            Request.RequestUri = DownstreamUri;
        }

        Request.Headers.Remove("GenerationVersion");
        Request.Headers.Remove("IntegrationID");
        Request.Headers.Remove("ArbitraryCode");
        Request.Headers.Remove("EncArbitraryCode");

        Request.Headers.TryAddWithoutValidation("GenerationVersion", TenantOptions.Sepidar.GenerationVersion);
        Request.Headers.TryAddWithoutValidation("IntegrationID", TenantOptions.Sepidar.IntegrationId);

        var ArbitraryCode = Guid.NewGuid().ToString();
        var EncryptedCode = _crypto.EncryptArbitraryCode(ArbitraryCode, TenantOptions.Crypto);
        Request.Headers.TryAddWithoutValidation("ArbitraryCode", ArbitraryCode);
        Request.Headers.TryAddWithoutValidation("EncArbitraryCode", EncryptedCode);

        if (Request.Headers.Contains("Authorization"))
        {
            Request.Headers.Authorization = null;
        }

        try
        {
            var JwtToken = await _auth.EnsureTokenAsync(TenantOptions, CancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(JwtToken))
            {
                Request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", JwtToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to ensure JWT for tenant {TenantId}", TenantOptions.TenantId);
            throw;
        }

        _logger.LogDebug("Forwarding request for tenant {TenantId} to {Uri}", TenantOptions.TenantId, Request.RequestUri);

        var CorrelationId = _httpContextAccessor.HttpContext?.Items[CorrelationIdMiddleware.HeaderName] as string;
        if (!string.IsNullOrWhiteSpace(CorrelationId))
        {
            Request.Headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, CorrelationId);
        }

        return await base.SendAsync(Request, CancellationToken).ConfigureAwait(false);
    }
}
