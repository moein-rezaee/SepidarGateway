using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.OpenApi.Models;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;
using SepidarGateway.Handlers;
using SepidarGateway.Middleware;
using SepidarGateway.Observability;
using SepidarGateway.Services;
using SepidarGateway.Tenancy;
using SepidarGateway.Swagger;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

builder.Services.AddOptions<GatewayOptions>()
    .Bind(builder.Configuration.GetSection("Gateway"))
    .ValidateDataAnnotations();

builder.Services.AddSingleton<ITenantResolver, TenantResolver>();
builder.Services.AddSingleton<ITenantContextAccessor, TenantContextAccessor>();
builder.Services.AddSingleton<ISepidarCrypto, SepidarCryptoService>();
builder.Services.AddSingleton<ISepidarAuth, SepidarAuthService>();
builder.Services.AddSingleton<SepidarHeaderHandler>();
builder.Services.AddSingleton<ICorsPolicyProvider, TenantCorsPolicyProvider>();
builder.Services.AddHostedService<TenantLifecycleHostedService>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddMemoryCache();
builder.Services.AddHttpClient("SepidarAuth");

builder.Services.AddCors(options =>
{
    options.AddPolicy("TenantPolicy", policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

builder.Services.AddHealthChecks();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc(SwaggerConstants.DocumentName, new OpenApiInfo
    {
        Title = "Sepidar Gateway",
        Version = "v1",
        Description = "Gateway-as-a-device facade for Sepidar E-Commerce Web Service."
    });

    options.DocumentFilter<GatewayRoutesDocumentFilter>();

    options.AddSecurityDefinition(SwaggerConstants.TenantIdScheme, new OpenApiSecurityScheme
    {
        Description = "Tenant identifier header when host or path-based matching is not used.",
        In = ParameterLocation.Header,
        Name = "X-Tenant-ID",
        Type = SecuritySchemeType.ApiKey
    });

    options.AddSecurityDefinition(SwaggerConstants.ApiKeyScheme, new OpenApiSecurityScheme
    {
        Description = "Client API key required when the tenant enables API-key authentication.",
        In = ParameterLocation.Header,
        Name = "X-API-Key",
        Type = SecuritySchemeType.ApiKey
    });
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        return new ValueTask(context.HttpContext.Response.WriteAsync("Too many requests", token));
    };

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        var tenant = httpContext.RequestServices.GetRequiredService<ITenantContextAccessor>().CurrentTenant?.Options;
        var limits = tenant?.Limits ?? new TenantLimitOptions();
        var partitionKey = tenant?.TenantId ?? "default";
        var permits = Math.Max(1, limits.RequestsPerMinute);
        return RateLimitPartition.GetTokenBucketLimiter(partitionKey, _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = permits,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = Math.Max(0, limits.QueueLimit),
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            TokensPerPeriod = permits,
            AutoReplenishment = true
        });
    });
});

builder.Services.AddOcelot(builder.Configuration)
    .AddDelegatingHandler<SepidarHeaderHandler>(true);

var app = builder.Build();

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<TenantContextMiddleware>();
app.UseMiddleware<ClientAuthorizationMiddleware>();
app.UseCors("TenantPolicy");
app.UseRateLimiter();

app.MapHealthChecks("/health/live");
app.MapHealthChecks("/health/ready");

app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.RoutePrefix = "swagger";
    options.DocumentTitle = "Sepidar Gateway";
    options.SwaggerEndpoint("/swagger/sepidar/swagger.json", "Sepidar Gateway v1");
    options.DisplayRequestDuration();
    options.EnableTryItOutByDefault();
});

await app.UseOcelot();

await app.RunAsync();

public partial class Program;
