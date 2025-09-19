namespace SepidarGateway.Observability;

public sealed class CorrelationIdMiddleware
{
    public const string HeaderName = "X-Correlation-ID";

    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext Context)
    {
        var CorrelationId = Context.Request.Headers.TryGetValue(HeaderName, out var HeaderValue) && !string.IsNullOrWhiteSpace(HeaderValue)
            ? HeaderValue.ToString()
            : Guid.NewGuid().ToString();

        Context.Items[HeaderName] = CorrelationId;
        Context.Response.OnStarting(() =>
        {
            Context.Response.Headers[HeaderName] = CorrelationId;
            return Task.CompletedTask;
        });

        using (_logger.BeginScope(new Dictionary<string, object>
               {
                   [HeaderName] = CorrelationId
               }))
        {
            await _next(Context);
        }
    }
}
