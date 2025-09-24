using System.Net;
using System.Net.Http;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Options;
using SepidarGateway.Contracts;
using Microsoft.OpenApi.Models;
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
app.UseStaticFiles();
app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/sepidar/swagger.json", "Sepidar Gateway");
    options.RoutePrefix = "swagger";
    options.DocumentTitle = "Sepidar Gateway API";
    options.DisplayRequestDuration();
    options.EnableDeepLinking();
});

const string StoplightHtml = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Sepidar Gateway Docs</title>
    <link rel="stylesheet" href="/stoplight-elements.css" />
    <script src="/stoplight-elements.js"></script>
    <style>
      body {
        margin: 0;
        font-family: var(--sl-font-sans, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
        background-color: #0f172a;
      }

      elements-api {
        min-height: 100vh;
      }
    </style>
  </head>
  <body>
    <elements-api
      api-description-url="/swagger/sepidar/swagger.json"
      router="hash"
      layout="sidebar"
      try-it="true"
      hide-download-button="false"
    ></elements-api>
  </body>
</html>
""";

app.MapGet("/health/live", () => Results.Json(new { status = "Live" }));
app.MapGet("/health/ready", async (ISepidarGatewayService service, CancellationToken ct) =>
{
    var authorized = await service.EnsureAuthorizationAsync(ct).ConfigureAwait(false);
    return Results.Json(new { status = authorized ? "Ready" : "Degraded", authorized });
});

MapDeviceEndpoints(app, null);

var optionsMonitor = app.Services.GetRequiredService<IOptionsMonitor<GatewayOptions>>();
var gatewayOptions = optionsMonitor.CurrentValue;
if (gatewayOptions.Settings.SupportedVersions?.Length > 0)
{
    foreach (var version in gatewayOptions.Settings.SupportedVersions)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            continue;
        }

        var prefix = "/" + version.Trim();
        MapDeviceEndpoints(app, prefix);
        MapProxyRoutes(app, gatewayOptions.Routes, prefix);
    }
}

MapProxyRoutes(app, gatewayOptions.Routes, null);

IResult RenderStoplight() => Results.Content(StoplightHtml, "text/html");

app.MapGet("/docs", RenderStoplight);
app.MapGet("/", () => Results.Redirect("/swagger"));

app.MapFallback("/docs/{*path}", () => Results.Redirect("/docs"));

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

static void MapDeviceEndpoints(IEndpointRouteBuilder app, string? versionPrefix)
{
    var prefix = string.IsNullOrEmpty(versionPrefix) ? string.Empty : versionPrefix!.TrimEnd('/');
    var group = app.MapGroup($"{prefix}/device");

    group.MapPost("/register", async (DeviceRegisterRequestDto request, ISepidarGatewayService service, CancellationToken ct) =>
    {
        await service.RegisterDeviceAsync(request, ct).ConfigureAwait(false);
        return Results.Ok(new { ok = true });
    })
    .WithSummary("Register Sepidar device using configured credentials");

    group.MapPost("/login", async (DeviceLoginRequestDto request, ISepidarGatewayService service, CancellationToken ct) =>
    {
        var response = await service.LoginAsync(request, ct).ConfigureAwait(false);
        return Results.Ok(response);
    })
    .WithSummary("Login to Sepidar and return token details");

    group.MapGet("/authorize", async (ISepidarGatewayService service, CancellationToken ct) =>
    {
        var authorized = await service.EnsureAuthorizationAsync(ct).ConfigureAwait(false);
        return Results.Ok(new { authorized });
    })
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
