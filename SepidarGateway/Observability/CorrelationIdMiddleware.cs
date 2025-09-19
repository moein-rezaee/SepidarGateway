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

    public async Task InvokeAsync(HttpContext context)
    {
        var correlation_id = context.Request.Headers.TryGetValue(HeaderName, out var header_value) && !string.IsNullOrWhiteSpace(header_value)
            ? header_value.ToString()
            : Guid.NewGuid().ToString();

        context.Items[HeaderName] = correlation_id;
        context.Response.OnStarting(() =>
        {
            context.Response.Headers[HeaderName] = correlation_id;
            return Task.CompletedTask;
        });

        using (_logger.BeginScope(new Dictionary<string, object>
               {
                   [HeaderName] = correlation_id
               }))
        {
            await _next(context);
        }
    }
}
