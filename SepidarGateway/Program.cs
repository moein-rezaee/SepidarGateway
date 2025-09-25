using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using SepidarGateway.Contracts;
using SepidarGateway.Auth;
using SepidarGateway.Configuration;
using SepidarGateway.Crypto;
using SepidarGateway.Handlers;
using SepidarGateway.Observability;
using SepidarGateway.Services;
using SepidarGateway.Swagger;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

builder.Services.AddOptions<GatewayOptions>()
    .Bind(builder.Configuration.GetSection("Gateway"))
    .ValidateDataAnnotations();

builder.Services.AddSingleton<ISepidarCrypto, SepidarCryptoService>();
builder.Services.AddSingleton<ISepidarAuth, SepidarAuthService>();
builder.Services.AddSingleton<SepidarHeaderHandler>();
builder.Services.AddSingleton<ISepidarGatewayService, SepidarGatewayService>();

builder.Services.AddHttpContextAccessor();

builder.Services.AddHttpClient("SepidarAuth")
    .ConfigurePrimaryHttpMessageHandler(CreateSepidarHandler);

builder.Services.AddHttpClient(SepidarGatewayService.ProxyClientName)
    .ConfigurePrimaryHttpMessageHandler(CreateSepidarHandler)
    .AddHttpMessageHandler<SepidarHeaderHandler>();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(swagger =>
{
    swagger.SwaggerDoc(SwaggerConstants.DocumentName, new OpenApiInfo
    {
        Title = "Sepidar Gateway",
        Version = "v1",
        Description = "Clean reverse proxy facade for Sepidar E-Commerce Web Service."
    });

    swagger.DocumentFilter<GatewayRoutesDocumentFilter>();

    swagger.ResolveConflictingActions(descriptions => descriptions.First());

    swagger.AddSecurityDefinition("SepidarToken", new OpenApiSecurityScheme
    {
        Description = "Optional Sepidar token override (without 'Bearer').",
        In = ParameterLocation.Header,
        Name = "X-Sepidar-Token",
        Type = SecuritySchemeType.ApiKey
    });
});

var app = builder.Build();

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseCors();
app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint($"/swagger/{SwaggerConstants.DocumentName}/swagger.json", "Sepidar Gateway");
    options.RoutePrefix = "swagger";
    options.DisplayRequestDuration();
});

var optionsMonitor = app.Services.GetRequiredService<IOptionsMonitor<GatewayOptions>>();
var gatewayOptions = optionsMonitor.CurrentValue;
var configuredVersions = (gatewayOptions.Settings.SupportedVersions ?? Array.Empty<string>())
    .Select(version => version?.Trim('/') ?? string.Empty)
    .Where(version => !string.IsNullOrWhiteSpace(version))
    .Distinct(StringComparer.OrdinalIgnoreCase)
    .ToArray();

if (configuredVersions.Length == 0)
{
    configuredVersions = new[] { string.Empty };
}

foreach (var version in configuredVersions)
{
    var prefix = string.IsNullOrEmpty(version) ? string.Empty : "/" + version;
    MapHealthEndpoints(app, prefix);
    MapDeviceEndpoints(app, prefix);
    MapProxyRoutes(app, gatewayOptions.Routes, prefix);
}

app.MapGet("/", () => Results.Redirect("/swagger"));

app.Run();

static HttpMessageHandler CreateSepidarHandler(IServiceProvider services)
{
    var options = services.GetRequiredService<IOptionsMonitor<GatewayOptions>>().CurrentValue.Settings;
    var handler = new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
    };

    if (options?.Sepidar.UseProxy != true)
    {
        handler.Proxy = null;
        handler.UseProxy = false;
        return handler;
    }

    var proxyUrl = options?.Sepidar.ProxyUrl;
    if (!string.IsNullOrWhiteSpace(proxyUrl) && Uri.TryCreate(proxyUrl, UriKind.Absolute, out var proxyUri))
    {
        var proxy = new WebProxy(proxyUri)
        {
            BypassProxyOnLocal = false
        };

        if (!string.IsNullOrWhiteSpace(options?.Sepidar.ProxyUserName))
        {
            proxy.Credentials = new NetworkCredential(options!.Sepidar.ProxyUserName, options.Sepidar.ProxyPassword);
        }

        handler.Proxy = proxy;
        handler.UseProxy = true;
    }
    else
    {
        handler.Proxy = WebRequest.DefaultWebProxy;
        handler.UseProxy = handler.Proxy is not null;
    }

    return handler;
}

static void MapHealthEndpoints(IEndpointRouteBuilder app, string? versionPrefix)
{
    var prefix = string.IsNullOrEmpty(versionPrefix) ? string.Empty : versionPrefix!.TrimEnd('/');
    var group = app.MapGroup($"{prefix}/Health");

    group.MapGet("/Live", () => Results.Json(new { Status = "Live" }))
        .WithTags("Health")
        .WithSummary("Liveness probe for the gateway host");

    group.MapGet("/Ready", async (ISepidarGatewayService service, CancellationToken ct) =>
        {
            var authorized = await service.EnsureAuthorizationAsync(ct).ConfigureAwait(false);
            return Results.Json(new { Status = authorized ? "Ready" : "Degraded", Authorized = authorized });
        })
        .WithTags("Health")
        .WithSummary("Readiness probe validating Sepidar authorization");
}

static void MapDeviceEndpoints(IEndpointRouteBuilder app, string? versionPrefix)
{
    var prefix = string.IsNullOrEmpty(versionPrefix) ? string.Empty : versionPrefix!.TrimEnd('/');
    var group = app.MapGroup($"{prefix}/Device");

    group.MapPost("/Register", async (DeviceRegisterRequestDto request, ISepidarGatewayService service, CancellationToken ct) =>
    {
        try
        {
            var response = await service.RegisterDeviceAsync(request, ct).ConfigureAwait(false);
            var statusCode = response.StatusCode == 0 ? StatusCodes.Status200OK : response.StatusCode;

            if (string.IsNullOrEmpty(response.Body))
            {
                return Results.StatusCode(statusCode);
            }

            var contentType = string.IsNullOrWhiteSpace(response.ContentType)
                ? "application/json"
                : response.ContentType;

            return TypedResults.Content(response.Body, contentType, Encoding.UTF8, statusCode);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (ArgumentNullException)
        {
            return Results.BadRequest(new { error = "Missing 'deviceSerial'" });
        }
    })
    .WithTags("SepidarGateway")
    .WithSummary("Register Sepidar device using configured credentials");

    group.MapPost("/Login", async (DeviceLoginRequestDto request, ISepidarGatewayService service, CancellationToken ct) =>
    {
        var response = await service.LoginAsync(request, ct).ConfigureAwait(false);
        return Results.Ok(response);
    })
    .WithTags("SepidarGateway")
    .WithSummary("Login to Sepidar and return token details");

    group.MapGet("/Authorize", async (ISepidarGatewayService service, CancellationToken ct) =>
    {
        var authorized = await service.EnsureAuthorizationAsync(ct).ConfigureAwait(false);
        return Results.Ok(new { Authorized = authorized });
    })
    .WithTags("SepidarGateway")
    .WithSummary("Check Sepidar authorization status");
}

static void MapProxyRoutes(IEndpointRouteBuilder app, IReadOnlyCollection<GatewayRoute> routes, string? versionPrefix)
{
    if (routes is null || routes.Count == 0)
    {
        return;
    }

    foreach (var route in routes)
    {
        if (string.IsNullOrWhiteSpace(route.Path))
        {
            continue;
        }

        var methods = route.Methods?.Count > 0
            ? route.Methods
            : new List<string> { HttpMethod.Get.Method };

        var normalized = NormalizePath(route.Path);
        var basePattern = CombinePrefix(versionPrefix, normalized);
        var catchAllPattern = basePattern.EndsWith("/") ? basePattern + "{**catchAll}" : basePattern + "/{**catchAll}";

        foreach (var method in methods)
        {
            app.MapMethods(basePattern, new[] { method }, async (HttpContext context, ISepidarGatewayService service, CancellationToken ct) =>
            {
                var forwardPath = ResolveForwardPath(context.Request.Path.Value ?? string.Empty, versionPrefix);
                await service.ProxyAsync(context, forwardPath, ct).ConfigureAwait(false);
            })
            .ExcludeFromDescription();

            app.MapMethods(catchAllPattern, new[] { method }, async (HttpContext context, string catchAll, ISepidarGatewayService service, CancellationToken ct) =>
            {
                _ = catchAll;
                var forwardPath = ResolveForwardPath(context.Request.Path.Value ?? string.Empty, versionPrefix);
                await service.ProxyAsync(context, forwardPath, ct).ConfigureAwait(false);
            })
            .ExcludeFromDescription();
        }
    }
}

static string NormalizePath(string path)
{
    if (string.IsNullOrWhiteSpace(path))
    {
        return "/";
    }

    var trimmed = path.Trim();
    if (!trimmed.StartsWith('/'))
    {
        trimmed = "/" + trimmed;
    }

    return trimmed.TrimEnd('/');
}

static string CombinePrefix(string? prefix, string path)
{
    var normalizedPrefix = string.IsNullOrEmpty(prefix) ? string.Empty : prefix!.TrimEnd('/');
    if (string.IsNullOrEmpty(normalizedPrefix))
    {
        return path;
    }

    if (path.Equals("/", StringComparison.Ordinal))
    {
        return normalizedPrefix;
    }

    return normalizedPrefix + path;
}

static string ResolveForwardPath(string requestPath, string? versionPrefix)
{
    if (string.IsNullOrWhiteSpace(requestPath))
    {
        return "/";
    }

    if (string.IsNullOrEmpty(versionPrefix))
    {
        return requestPath;
    }

    var prefix = versionPrefix.TrimEnd('/');
    if (!prefix.StartsWith('/'))
    {
        prefix = "/" + prefix;
    }

    if (requestPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
    {
        var trimmed = requestPath[prefix.Length..];
        return string.IsNullOrEmpty(trimmed) ? "/" : trimmed;
    }

    return requestPath;
}

public partial class Program;
