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

var app_builder = WebApplication.CreateBuilder(args);

app_builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{app_builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

app_builder.Services.AddOptions<GatewayOptions>()
    .Bind(app_builder.Configuration.GetSection("Gateway"))
    .ValidateDataAnnotations();

app_builder.Services.AddSingleton<ITenantResolver, TenantResolver>();
app_builder.Services.AddSingleton<ITenantContextAccessor, TenantContextAccessor>();
app_builder.Services.AddSingleton<ISepidarCrypto, SepidarCryptoService>();
app_builder.Services.AddSingleton<ISepidarAuth, SepidarAuthService>();
app_builder.Services.AddSingleton<SepidarHeaderHandler>();
app_builder.Services.AddSingleton<ICorsPolicyProvider, TenantCorsPolicyProvider>();
app_builder.Services.AddHostedService<TenantLifecycleHostedService>();

app_builder.Services.AddHttpContextAccessor();
app_builder.Services.AddMemoryCache();
app_builder.Services.AddHttpClient("SepidarAuth");

app_builder.Services.AddCors(cors_options =>
{
    cors_options.AddPolicy("TenantPolicy", cors_policy => cors_policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

app_builder.Services.AddHealthChecks();

app_builder.Services.AddEndpointsApiExplorer();
app_builder.Services.AddSwaggerGen(swagger_options =>
{
    swagger_options.SwaggerDoc(SwaggerConstants.DocumentName, new OpenApiInfo
    {
        Title = "Sepidar Gateway",
        Version = "v1",
        Description = "Gateway-as-a-device facade for Sepidar E-Commerce Web Service."
    });

    swagger_options.DocumentFilter<GatewayRoutesDocumentFilter>();

    swagger_options.AddSecurityDefinition(SwaggerConstants.TenantIdScheme, new OpenApiSecurityScheme
    {
        Description = "Tenant identifier header when host or path-based matching is not used.",
        In = ParameterLocation.Header,
        Name = "X-Tenant-ID",
        Type = SecuritySchemeType.ApiKey
    });

    swagger_options.AddSecurityDefinition(SwaggerConstants.ApiKeyScheme, new OpenApiSecurityScheme
    {
        Description = "Client API key required when the tenant enables API-key authentication.",
        In = ParameterLocation.Header,
        Name = "X-API-Key",
        Type = SecuritySchemeType.ApiKey
    });
});

app_builder.Services.AddRateLimiter(rate_options =>
{
    rate_options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    rate_options.OnRejected = (rate_context, cancellation_token) =>
    {
        rate_context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        return new ValueTask(rate_context.HttpContext.Response.WriteAsync("Too many requests", cancellation_token));
    };

    rate_options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(http_context =>
    {
        var tenant_options = http_context.RequestServices.GetRequiredService<ITenantContextAccessor>().CurrentTenant?.Options;
        var tenant_limits = tenant_options?.Limits ?? new TenantLimitOptions();
        var partition_key = tenant_options?.TenantId ?? "default";
        var token_permits = Math.Max(1, tenant_limits.RequestsPerMinute);
        return RateLimitPartition.GetTokenBucketLimiter(partition_key, _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = token_permits,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = Math.Max(0, tenant_limits.QueueLimit),
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            TokensPerPeriod = token_permits,
            AutoReplenishment = true
        });
    });
});

app_builder.Services.AddOcelot(app_builder.Configuration)
    .AddDelegatingHandler<SepidarHeaderHandler>(true);

var gateway_app = app_builder.Build();

gateway_app.UseMiddleware<CorrelationIdMiddleware>();
gateway_app.UseMiddleware<TenantContextMiddleware>();
gateway_app.UseMiddleware<ClientAuthorizationMiddleware>();
gateway_app.UseCors("TenantPolicy");
gateway_app.UseRateLimiter();

gateway_app.MapHealthChecks("/health/live");
gateway_app.MapHealthChecks("/health/ready");

gateway_app.UseSwagger();
gateway_app.UseSwaggerUI(swagger_ui_options =>
{
    swagger_ui_options.RoutePrefix = "swagger";
    swagger_ui_options.DocumentTitle = "Sepidar Gateway";
    swagger_ui_options.SwaggerEndpoint("/swagger/sepidar/swagger.json", "Sepidar Gateway v1");
    swagger_ui_options.DisplayRequestDuration();
    swagger_ui_options.EnableTryItOutByDefault();
});

await gateway_app.UseOcelot();

await gateway_app.RunAsync();

public partial class Program;
