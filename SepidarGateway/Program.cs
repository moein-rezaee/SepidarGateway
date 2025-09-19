using System;
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

var AppBuilder = WebApplication.CreateBuilder(args);

AppBuilder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{AppBuilder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables()
    .AddGatewayEnvironmentOverrides();

AppBuilder.Services.AddOptions<GatewayOptions>()
    .Bind(AppBuilder.Configuration.GetSection("Gateway"))
    .ValidateDataAnnotations();

AppBuilder.Services.AddSingleton<ITenantResolver, TenantResolver>();
AppBuilder.Services.AddSingleton<ITenantContextAccessor, TenantContextAccessor>();
AppBuilder.Services.AddSingleton<ISepidarCrypto, SepidarCryptoService>();
AppBuilder.Services.AddSingleton<ISepidarAuth, SepidarAuthService>();
AppBuilder.Services.AddSingleton<SepidarHeaderHandler>();
AppBuilder.Services.AddSingleton<ICorsPolicyProvider, TenantCorsPolicyProvider>();
AppBuilder.Services.AddHostedService<TenantLifecycleHostedService>();

AppBuilder.Services.AddHttpContextAccessor();
AppBuilder.Services.AddMemoryCache();
AppBuilder.Services.AddHttpClient("SepidarAuth");

AppBuilder.Services.AddCors(cors_options =>
{
    cors_options.AddPolicy("TenantPolicy", cors_policy => cors_policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

AppBuilder.Services.AddHealthChecks();

AppBuilder.Services.AddEndpointsApiExplorer();
AppBuilder.Services.AddSwaggerGen(swagger_options =>
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

AppBuilder.Services.AddRateLimiter(rate_options =>
{
    rate_options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    rate_options.OnRejected = (rate_context, cancellation_token) =>
    {
        rate_context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        return new ValueTask(rate_context.HttpContext.Response.WriteAsync("Too many requests", cancellation_token));
    };

    rate_options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        var TenantOptions = httpContext.RequestServices.GetRequiredService<ITenantContextAccessor>().CurrentTenant?.Options;
        var TenantLimits = TenantOptions?.Limits ?? new TenantLimitOptions();
        var PartitionKey = TenantOptions?.TenantId ?? "default";
        var TokenPermits = Math.Max(1, TenantLimits.RequestsPerMinute);
        return RateLimitPartition.GetTokenBucketLimiter(PartitionKey, _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = TokenPermits,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = Math.Max(0, TenantLimits.QueueLimit),
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            TokensPerPeriod = TokenPermits,
            AutoReplenishment = true
        });
    });
});

AppBuilder.Services.AddOcelot(AppBuilder.Configuration)
    .AddDelegatingHandler<SepidarHeaderHandler>(true);

var GatewayApp = AppBuilder.Build();

GatewayApp.UseMiddleware<CorrelationIdMiddleware>();
GatewayApp.UseMiddleware<TenantContextMiddleware>();
GatewayApp.UseMiddleware<ClientAuthorizationMiddleware>();
GatewayApp.UseCors("TenantPolicy");
GatewayApp.UseRateLimiter();

GatewayApp.MapGet("/health/live", () => Results.Json(new { status = "Live" }));
GatewayApp.MapGet("/health/ready", () => Results.Json(new { status = "Ready" }));

GatewayApp.MapGet("/", () => Results.Redirect("/swagger"));

GatewayApp.Use(async (request_context, next_handler) =>
{
    var RequestPath = request_context.Request.Path.Value;
    if (!string.IsNullOrEmpty(RequestPath)
        && RequestPath.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase)
        && !RequestPath.StartsWith("/swagger", StringComparison.Ordinal))
    {
        var NormalizedPath = "/swagger" + RequestPath[8..];
        var RedirectTarget = string.Concat(NormalizedPath, request_context.Request.QueryString.Value);
        request_context.Response.Redirect(RedirectTarget);
        return;
    }

    await next_handler().ConfigureAwait(false);
});

GatewayApp.UseSwagger();
GatewayApp.UseSwaggerUI(swaggerUiOptions =>
{
    swaggerUiOptions.RoutePrefix = "swagger";
    swaggerUiOptions.DocumentTitle = "Sepidar Gateway";
    swaggerUiOptions.SwaggerEndpoint("/swagger/sepidar/swagger.json", "Sepidar Gateway v1");
    swaggerUiOptions.DisplayRequestDuration();
    swaggerUiOptions.EnableTryItOutByDefault();
});

await GatewayApp.UseOcelot();

await GatewayApp.RunAsync();

public partial class Program;
