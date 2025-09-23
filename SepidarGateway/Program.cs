using System.Net;
using System.Net.Http;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
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

// Single-customer mode: no tenant resolver/context needed
AppBuilder.Services.AddSingleton<ISepidarCrypto, SepidarCryptoService>();
AppBuilder.Services.AddSingleton<ISepidarAuth, SepidarAuthService>();
AppBuilder.Services.AddSingleton<SepidarHeaderHandler>();
AppBuilder.Services.AddSingleton<ICorsPolicyProvider, TenantCorsPolicyProvider>();
AppBuilder.Services.AddHostedService<TenantLifecycleHostedService>();

AppBuilder.Services.AddHttpContextAccessor();
AppBuilder.Services.AddMemoryCache();
AppBuilder.Services.AddHttpClient("SepidarAuth")
    .ConfigureHttpMessageHandlerBuilder(builder =>
    {
        var options = builder.Services.GetRequiredService<IOptionsMonitor<GatewayOptions>>();
        var tenant = options.CurrentValue.Tenant;
        var sepidar = tenant?.Sepidar;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        };

        var useProxy = sepidar?.UseProxy ?? true;
        if (!useProxy)
        {
            handler.Proxy = null;
            handler.UseProxy = false;
        }
        else
        {
            var proxyUrl = sepidar?.ProxyUrl;
            if (!string.IsNullOrWhiteSpace(proxyUrl) && Uri.TryCreate(proxyUrl, UriKind.Absolute, out var proxyUri))
            {
                var proxy = new WebProxy(proxyUri)
                {
                    BypassProxyOnLocal = false
                };

                var proxyUser = sepidar?.ProxyUserName;
                var proxyPassword = sepidar?.ProxyPassword;
                if (!string.IsNullOrWhiteSpace(proxyUser))
                {
                    proxy.Credentials = new NetworkCredential(proxyUser, proxyPassword);
                }

                handler.Proxy = proxy;
                handler.UseProxy = true;
            }
            else
            {
                handler.Proxy = WebRequest.DefaultWebProxy;
                handler.UseProxy = handler.Proxy is not null;
            }
        }

        builder.PrimaryHandler = handler;
    });

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

    // Single-customer mode: no tenant id header needed

    swagger_options.AddSecurityDefinition(SwaggerConstants.ApiKeyScheme, new OpenApiSecurityScheme
    {
        Description = "Client API key required when the tenant enables API-key authentication.",
        In = ParameterLocation.Header,
        Name = "X-API-Key",
        Type = SecuritySchemeType.ApiKey
    });

    // Optional manual Sepidar token override for Swagger (gateway will add Bearer automatically when not provided)
    swagger_options.AddSecurityDefinition("SepidarToken", new OpenApiSecurityScheme
    {
        Description = "Optional Sepidar token override (without 'Bearer').",
        In = ParameterLocation.Header,
        Name = "X-Sepidar-Token",
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
        var tenant = httpContext.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<GatewayOptions>>().CurrentValue.Tenant;
        var TenantLimits = tenant?.Limits ?? new TenantLimitOptions();
        var PartitionKey = tenant?.TenantId ?? "default";
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

// Ensure Ocelot reads routes from root "Routes" by copying from "Ocelot:Routes" if needed
EnsureOcelotRoutes(AppBuilder.Configuration);

AppBuilder.Services.AddOcelot(AppBuilder.Configuration)
    .AddDelegatingHandler<SepidarHeaderHandler>(true);

var GatewayApp = AppBuilder.Build();

GatewayApp.UseMiddleware<CorrelationIdMiddleware>();
GatewayApp.UseMiddleware<ClientAuthorizationMiddleware>();
GatewayApp.UseCors("TenantPolicy");
GatewayApp.UseRateLimiter();

GatewayApp.Use(async (context, next) =>
{
    var RequestPath = context.Request.Path.Value ?? string.Empty;

    if (RequestPath.Equals("/health/live", StringComparison.OrdinalIgnoreCase))
    {
        await context.Response.WriteAsJsonAsync(new { status = "Live" }).ConfigureAwait(false);
        return;
    }

    if (RequestPath.Equals("/health/ready", StringComparison.OrdinalIgnoreCase))
    {
        await context.Response.WriteAsJsonAsync(new { status = "Ready" }).ConfigureAwait(false);
        return;
    }

    if (RequestPath.Equals("/", StringComparison.Ordinal))
    {
        context.Response.Redirect("/swagger/", permanent: false);
        return;
    }

    if (RequestPath.Equals("/swagger", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.Redirect("/swagger/", permanent: false);
        return;
    }

    if (!RequestPath.StartsWith("/swagger", StringComparison.Ordinal) &&
        RequestPath.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase))
    {
        var Suffix = RequestPath.Length > "/swagger".Length
            ? RequestPath["/swagger".Length..]
            : string.Empty;
        var RedirectTarget = string.IsNullOrEmpty(Suffix) ? "/swagger/" : "/swagger" + Suffix;

        context.Response.Redirect(RedirectTarget, permanent: false);
        return;
    }

    await next().ConfigureAwait(false);
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

// Diagnostics: Auth/Registration status per tenant
GatewayApp.MapGet("/health/auth", async (IServiceProvider sp, CancellationToken ct) =>
{
    var options = sp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions>>().CurrentValue;
    var auth = sp.GetRequiredService<SepidarGateway.Auth.ISepidarAuth>();
    var tenant = options.Tenant;
    var entry = new Dictionary<string, object?>
    {
        ["TenantId"] = tenant.TenantId
    };
    try
    {
        await auth.EnsureDeviceRegisteredAsync(tenant, ct);
        entry["Registered"] = true;
    }
    catch (Exception ex)
    {
        entry["Registered"] = false;
        entry["RegisterError"] = ex.Message;
    }

    try
    {
        var token = await auth.EnsureTokenAsync(tenant, ct);
        entry["Token"] = string.IsNullOrWhiteSpace(token) ? null : $"{token[..Math.Min(10, token.Length)]}...";
    }
    catch (Exception ex)
    {
        entry["Token"] = null;
        entry["LoginError"] = ex.Message;
    }

    return Results.Json(entry);
});

// Admin endpoints for runtime crypto injection when device already registered
var adminGroup = GatewayApp.MapGroup("/admin");

adminGroup.MapGet("/tenant", (HttpContext http, Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    var t = opt.CurrentValue.Tenant;
    var res = new
    {
        t.TenantId,
        HasRsa = !string.IsNullOrWhiteSpace(t.Crypto.RsaPublicKeyXml) ||
                 (!string.IsNullOrWhiteSpace(t.Crypto.RsaModulusBase64) && !string.IsNullOrWhiteSpace(t.Crypto.RsaExponentBase64))
    };
    return Results.Json(res);
});

// Public, simple endpoints: accept minimal input and do all heavy-lifting in background
var deviceGroup = GatewayApp.MapGroup("/device").WithTags("Device");

// Register by only providing deviceSerial (other fields optional). No admin key required.
deviceGroup.MapPost("/register", async (
    SepidarGateway.Contracts.DeviceRegisterRequestDto req,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt,
    SepidarGateway.Auth.ISepidarAuth auth,
    CancellationToken ct) =>
{
    if (req is null || string.IsNullOrWhiteSpace(req.DeviceSerial))
    {
        return Results.BadRequest(new { error = "Missing 'deviceSerial'" });
    }

    var tenant = opt.CurrentValue.Tenant;
    tenant.Sepidar.DeviceSerial = req.DeviceSerial.Trim();
    tenant.Sepidar.IntegrationId = DeriveIntegrationId(tenant.Sepidar.DeviceSerial);
    if (string.IsNullOrWhiteSpace(tenant.Sepidar.IntegrationId))
    {
        return Results.BadRequest(new { error = "Unable to derive IntegrationID from deviceSerial" });
    }
    tenant.Sepidar.RegisterPayloadMode = "IntegrationOnly";

    try
    {
        await auth.EnsureDeviceRegisteredAsync(tenant, ct);
        return Results.Json(new
        {
            ok = true,
            deviceSerial = tenant.Sepidar.DeviceSerial,
            integrationId = tenant.Sepidar.IntegrationId,
            rsa = new
            {
                tenant.Crypto.RsaPublicKeyXml,
                tenant.Crypto.RsaModulusBase64,
                tenant.Crypto.RsaExponentBase64
            }
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { ok = false, error = ex.Message });
    }
});

// Login by providing only username/password; gateway does MD5 and RSA headers itself
deviceGroup.MapPost("/login", async (
    SepidarGateway.Contracts.DeviceLoginRequestDto req,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt,
    SepidarGateway.Auth.ISepidarAuth auth,
    CancellationToken ct) =>
{
    var tenant = opt.CurrentValue.Tenant;
    if (!string.IsNullOrWhiteSpace(req?.UserName)) tenant.Credentials.UserName = req!.UserName!.Trim();
    if (!string.IsNullOrWhiteSpace(req?.Password)) tenant.Credentials.Password = req!.Password!.Trim();

    try
    {
        var login = await auth.LoginAsync(tenant, ct);
        return Results.Json(new { ok = true, token = login.Token, login });
    }
    catch (Exception ex)
    {
        return Results.Json(new { ok = false, error = ex.Message });
    }
});

adminGroup.MapPost("/tenant/crypto", async (
    HttpContext http,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt,
    SepidarGateway.Auth.ISepidarAuth auth,
    CancellationToken ct) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    var body = await System.Text.Json.JsonSerializer.DeserializeAsync<Dictionary<string, string?>>(http.Request.Body, cancellationToken: ct) ?? new();
    var tenant = opt.CurrentValue.Tenant;

    if (body.TryGetValue("RsaPublicKeyXml", out var xml) && !string.IsNullOrWhiteSpace(xml))
    {
        tenant.Crypto.RsaPublicKeyXml = xml;
        tenant.Crypto.RsaModulusBase64 = null;
        tenant.Crypto.RsaExponentBase64 = null;
    }
    else if (body.TryGetValue("RsaModulusBase64", out var mod) && !string.IsNullOrWhiteSpace(mod) &&
             body.TryGetValue("RsaExponentBase64", out var exp) && !string.IsNullOrWhiteSpace(exp))
    {
        tenant.Crypto.RsaPublicKeyXml = null;
        tenant.Crypto.RsaModulusBase64 = mod;
        tenant.Crypto.RsaExponentBase64 = exp;
    }
    else
    {
        return Results.BadRequest(new { error = "Provide RsaPublicKeyXml or both RsaModulusBase64 and RsaExponentBase64" });
    }

    try
    {
        await auth.EnsureDeviceRegisteredAsync(tenant, ct);
        var token = await auth.EnsureTokenAsync(tenant, ct);
        return Results.Json(new { ok = true, tokenPreview = string.IsNullOrWhiteSpace(token) ? null : token[..Math.Min(10, token.Length)] + "..." });
    }
    catch (Exception ex)
    {
        return Results.Json(new { ok = false, error = ex.Message });
    }
});

// Register device end-to-end using current or provided settings
adminGroup.MapPost("/register/auto", async (
    HttpContext http,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt,
    SepidarGateway.Auth.ISepidarAuth auth,
    CancellationToken ct) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    using var reader = new StreamReader(http.Request.Body);
    var bodyText = await reader.ReadToEndAsync(ct);
    var body = string.IsNullOrWhiteSpace(bodyText)
        ? new Dictionary<string, string?>()
        : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string?>>(bodyText) ?? new();

    var tenant = opt.CurrentValue.Tenant;
    if (body.TryGetValue("deviceSerial", out var ds) && !string.IsNullOrWhiteSpace(ds)) tenant.Sepidar.DeviceSerial = ds.Trim();
    if (body.TryGetValue("integrationId", out var iid) && !string.IsNullOrWhiteSpace(iid)) tenant.Sepidar.IntegrationId = iid.Trim();
    if (string.IsNullOrWhiteSpace(tenant.Sepidar.IntegrationId) && !string.IsNullOrWhiteSpace(tenant.Sepidar.DeviceSerial)) tenant.Sepidar.IntegrationId = DeriveIntegrationId(tenant.Sepidar.DeviceSerial);
    if (body.TryGetValue("baseUrl", out var bu) && !string.IsNullOrWhiteSpace(bu)) tenant.Sepidar.BaseUrl = bu.Trim();
    if (body.TryGetValue("generationVersion", out var gv) && !string.IsNullOrWhiteSpace(gv)) tenant.Sepidar.GenerationVersion = gv.Trim();
    if (body.TryGetValue("apiVersion", out var av) && !string.IsNullOrWhiteSpace(av)) tenant.Sepidar.ApiVersion = av.Trim();
    if (body.TryGetValue("registerPayloadMode", out var rpm) && !string.IsNullOrWhiteSpace(rpm)) tenant.Sepidar.RegisterPayloadMode = rpm.Trim();

    try
    {
        await auth.EnsureDeviceRegisteredAsync(tenant, ct);
        return Results.Json(new
        {
            ok = true,
            tenant = tenant.TenantId,
            deviceSerial = tenant.Sepidar.DeviceSerial,
            integrationId = tenant.Sepidar.IntegrationId,
            rsa = new
            {
                tenant.Crypto.RsaPublicKeyXml,
                tenant.Crypto.RsaModulusBase64,
                tenant.Crypto.RsaExponentBase64
            }
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { ok = false, error = ex.Message });
    }
});

// Login and return token; username/password optional (plain). If omitted, uses configured credentials.
adminGroup.MapPost("/login/auto", async (
    HttpContext http,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt,
    SepidarGateway.Auth.ISepidarAuth auth,
    CancellationToken ct) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    using var reader = new StreamReader(http.Request.Body);
    var bodyText = await reader.ReadToEndAsync(ct);
    var body = string.IsNullOrWhiteSpace(bodyText)
        ? new Dictionary<string, string?>()
        : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string?>>(bodyText) ?? new();

    var tenant = opt.CurrentValue.Tenant;
    var clone = System.Text.Json.JsonSerializer.Deserialize<SepidarGateway.Configuration.TenantOptions>(
        System.Text.Json.JsonSerializer.Serialize(tenant))!;
    if (body.TryGetValue("userName", out var u) && !string.IsNullOrWhiteSpace(u)) clone.Credentials.UserName = u.Trim();
    if (body.TryGetValue("password", out var p) && !string.IsNullOrWhiteSpace(p)) clone.Credentials.Password = p.Trim();

    try
    {
        var login = await auth.LoginAsync(clone, ct);
        return Results.Json(new { ok = true, token = login.Token, login });
    }
    catch (Exception ex)
    {
        return Results.Json(new { ok = false, error = ex.Message });
    }
});

// Set register path at runtime (not persisted)
adminGroup.MapPost("/tenant/register-path", (
    HttpContext http,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    using var reader = new StreamReader(http.Request.Body);
    var bodyText = reader.ReadToEndAsync().GetAwaiter().GetResult();
    var body = string.IsNullOrWhiteSpace(bodyText)
        ? new Dictionary<string, string?>()
        : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string?>>(bodyText) ?? new();

    if (!body.TryGetValue("path", out var path) || string.IsNullOrWhiteSpace(path))
    {
        return Results.BadRequest(new { error = "Missing 'path'" });
    }
    var tenant = opt.CurrentValue.Tenant;
    tenant.Sepidar.RegisterPath = path.Trim();
    return Results.Json(new { ok = true, tenant = tenant.TenantId, registerPath = tenant.Sepidar.RegisterPath });
});

// Try register against a provided path, copy RSA to active tenant on success
adminGroup.MapPost("/register/test", async (
    HttpContext http,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt,
    SepidarGateway.Auth.ISepidarAuth auth,
    CancellationToken ct) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    using var reader = new StreamReader(http.Request.Body);
    var bodyText = await reader.ReadToEndAsync(ct);
    var body = string.IsNullOrWhiteSpace(bodyText)
        ? new Dictionary<string, string?>()
        : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string?>>(bodyText) ?? new();

    if (!body.TryGetValue("path", out var path) || string.IsNullOrWhiteSpace(path))
    {
        return Results.BadRequest(new { error = "Missing 'path'" });
    }

    var tenant = opt.CurrentValue.Tenant;
    var clone = System.Text.Json.JsonSerializer.Deserialize<SepidarGateway.Configuration.TenantOptions>(
        System.Text.Json.JsonSerializer.Serialize(tenant))!;
    clone.Sepidar.RegisterPath = path.Trim();

    try
    {
        await auth.EnsureDeviceRegisteredAsync(clone, ct);
        // On success, copy RSA back
        tenant.Crypto.RsaPublicKeyXml = clone.Crypto.RsaPublicKeyXml;
        tenant.Crypto.RsaModulusBase64 = clone.Crypto.RsaModulusBase64;
        tenant.Crypto.RsaExponentBase64 = clone.Crypto.RsaExponentBase64;
        tenant.Sepidar.RegisterPath = clone.Sepidar.RegisterPath;
        return Results.Json(new { ok = true, registerPath = tenant.Sepidar.RegisterPath, hasRsa = !string.IsNullOrWhiteSpace(tenant.Crypto.RsaPublicKeyXml) || (!string.IsNullOrWhiteSpace(tenant.Crypto.RsaModulusBase64) && !string.IsNullOrWhiteSpace(tenant.Crypto.RsaExponentBase64)) });
    }
    catch (Exception ex)
    {
        return Results.Json(new { ok = false, error = ex.Message, tried = clone.Sepidar.RegisterPath });
    }
});

// Set base URL at runtime (not persisted)
adminGroup.MapPost("/tenant/baseurl", (
    HttpContext http,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    using var reader = new StreamReader(http.Request.Body);
    var bodyText = reader.ReadToEndAsync().GetAwaiter().GetResult();
    var body = string.IsNullOrWhiteSpace(bodyText)
        ? new Dictionary<string, string?>()
        : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string?>>(bodyText) ?? new();
    if (!body.TryGetValue("url", out var url) || string.IsNullOrWhiteSpace(url))
    {
        return Results.BadRequest(new { error = "Missing 'url'" });
    }
    var tenant = opt.CurrentValue.Tenant;
    tenant.Sepidar.BaseUrl = url.Trim();
    return Results.Json(new { ok = true, baseUrl = tenant.Sepidar.BaseUrl });
});

// Update Sepidar settings at runtime (integrationId, deviceSerial, versions, paths)
adminGroup.MapPost("/tenant/sepidar", async (
    HttpContext http,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    using var reader = new StreamReader(http.Request.Body);
    var bodyText = await reader.ReadToEndAsync();
    var body = string.IsNullOrWhiteSpace(bodyText)
        ? new Dictionary<string, string?>()
        : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string?>>(bodyText) ?? new();
    var t = opt.CurrentValue.Tenant;
    if (body.TryGetValue("integrationId", out var integrationId) && !string.IsNullOrWhiteSpace(integrationId))
        t.Sepidar.IntegrationId = integrationId.Trim();
    if (body.TryGetValue("deviceSerial", out var deviceSerial) && !string.IsNullOrWhiteSpace(deviceSerial))
        t.Sepidar.DeviceSerial = deviceSerial.Trim();
    // Auto-derive IntegrationId from first 4 chars of DeviceSerial when not explicitly provided
    if (string.IsNullOrWhiteSpace(t.Sepidar.IntegrationId) && !string.IsNullOrWhiteSpace(t.Sepidar.DeviceSerial))
        t.Sepidar.IntegrationId = DeriveIntegrationId(t.Sepidar.DeviceSerial);
    if (body.TryGetValue("generationVersion", out var gen) && !string.IsNullOrWhiteSpace(gen)) t.Sepidar.GenerationVersion = gen.Trim();
    if (body.TryGetValue("apiVersion", out var api) && !string.IsNullOrWhiteSpace(api)) t.Sepidar.ApiVersion = api.Trim();
    if (body.TryGetValue("registerPath", out var rp) && !string.IsNullOrWhiteSpace(rp)) t.Sepidar.RegisterPath = rp.Trim();
    if (body.TryGetValue("loginPath", out var lp) && !string.IsNullOrWhiteSpace(lp)) t.Sepidar.LoginPath = lp.Trim();
    if (body.TryGetValue("isAuthorizedPath", out var iap) && !string.IsNullOrWhiteSpace(iap)) t.Sepidar.IsAuthorizedPath = iap.Trim();
    if (body.TryGetValue("registerPayloadMode", out var rpm) && !string.IsNullOrWhiteSpace(rpm)) t.Sepidar.RegisterPayloadMode = rpm.Trim();
    if (body.TryGetValue("deviceTitle", out var dt) && !string.IsNullOrWhiteSpace(dt)) t.Sepidar.DeviceTitle = dt.Trim();
    return Results.Json(new
    {
        ok = true,
        t.TenantId,
        t.Sepidar.BaseUrl,
        t.Sepidar.IntegrationId,
        t.Sepidar.DeviceSerial,
        t.Sepidar.GenerationVersion,
        t.Sepidar.ApiVersion,
        t.Sepidar.RegisterPath,
        t.Sepidar.LoginPath,
        t.Sepidar.IsAuthorizedPath,
        t.Sepidar.RegisterPayloadMode,
        t.Sepidar.DeviceTitle
    });
});

// Scan candidate register endpoints; returns status for each
adminGroup.MapPost("/register/scan", async (
    HttpContext http,
    Microsoft.Extensions.Options.IOptionsMonitor<SepidarGateway.Configuration.GatewayOptions> opt,
    IHttpClientFactory httpFactory,
    CancellationToken ct) =>
{
    if (!IsAdminAuthorized(http)) return Results.StatusCode(StatusCodes.Status401Unauthorized);
    using var reader = new StreamReader(http.Request.Body);
    var bodyText = await reader.ReadToEndAsync(ct);
    var body = string.IsNullOrWhiteSpace(bodyText)
        ? new Dictionary<string, object?>()
        : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object?>>(bodyText) ?? new();

    var tenant = opt.CurrentValue.Tenant;
    var baseUrl = tenant.Sepidar.BaseUrl.TrimEnd('/') + "/";
    var hc = httpFactory.CreateClient("SepidarAuth");
    var candidateList = new List<string>
    {
        "api/Devices/Register/",
        "api/Device/Register/",
        "api/Device/RegisterDevice/",
        "api/Devices/RegisterDevice/",
        "api/RegisterDevice/",
        "api/Register/",
        "api/Device/RegisterApp/",
        "api/Devices/RegisterApp/",
        "api/Device/RegisterECommerce/",
        "api/Devices/RegisterECommerce/",
        "api/Device/RegisterDeviceWithIntegration/",
        "api/Devices/RegisterDeviceWithIntegration/"
    };
    if (body.TryGetValue("paths", out var pathsObj) && pathsObj is System.Text.Json.JsonElement je && je.ValueKind == System.Text.Json.JsonValueKind.Array)
    {
        foreach (var el in je.EnumerateArray())
        {
            if (el.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                var p = el.GetString();
                if (!string.IsNullOrWhiteSpace(p)) candidateList.Add(p!);
            }
        }
    }

    var results = new List<object>();
    foreach (var raw in candidateList)
    {
        foreach (var variant in new[] { raw, raw.TrimEnd('/') })
        {
            var path = variant.TrimStart('/');
            var uri = new Uri(new Uri(baseUrl, UriKind.Absolute), path);
            using var req = new HttpRequestMessage(HttpMethod.Get, uri);
            req.Headers.TryAddWithoutValidation("GenerationVersion", tenant.Sepidar.GenerationVersion);
            req.Headers.TryAddWithoutValidation("IntegrationID", tenant.Sepidar.IntegrationId);
            if (!string.IsNullOrWhiteSpace(tenant.Sepidar.ApiVersion))
            {
                req.Headers.TryAddWithoutValidation("api-version", tenant.Sepidar.ApiVersion);
            }
            try
            {
                using var resp = await hc.SendAsync(req, ct);
                results.Add(new { path = path, status = (int)resp.StatusCode });
            }
            catch (Exception ex)
            {
                results.Add(new { path = path, error = ex.Message });
            }
        }
    }

    return Results.Json(results);
});

// Only run Ocelot for API paths; let other endpoints (health, swagger) bypass Ocelot
GatewayApp.MapWhen(
    context => context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase),
    branch =>
    {
        // Synchronously wait because MapWhen callback is not async
        branch.UseOcelot().GetAwaiter().GetResult();
    });

await GatewayApp.RunAsync();

static void EnsureOcelotRoutes(ConfigurationManager configuration)
{
    var destRoutes = configuration.GetSection("Routes");
    var srcRoutes = configuration.GetSection("Ocelot:Routes");
    if (destRoutes.Exists())
    {
        // Still ensure placeholders on existing destination
        var overridesExisting = new Dictionary<string, string?>();
        var i = 0;
        foreach (var r in destRoutes.GetChildren())
        {
            if (!r.GetSection("DownstreamHostAndPorts").Exists())
            {
                overridesExisting[$"Routes:{i}:DownstreamHostAndPorts:0:Host"] = "localhost";
                overridesExisting[$"Routes:{i}:DownstreamHostAndPorts:0:Port"] = "80";
            }
            if (!r.GetSection("DownstreamScheme").Exists())
            {
                overridesExisting[$"Routes:{i}:DownstreamScheme"] = "http";
            }
            i++;
        }
        if (overridesExisting.Count > 0) configuration.AddInMemoryCollection(overridesExisting);
        return;
    }

    if (!srcRoutes.Exists()) return;

    var overrides = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    var index = 0;
    foreach (var child in srcRoutes.GetChildren())
    {
        CopySection(child, $"Routes:{index}", overrides);

        // Ensure placeholders so Ocelot config is valid
        if (!child.GetSection("DownstreamHostAndPorts").Exists())
        {
            overrides[$"Routes:{index}:DownstreamHostAndPorts:0:Host"] = "localhost";
            overrides[$"Routes:{index}:DownstreamHostAndPorts:0:Port"] = "80";
        }
        if (!child.GetSection("DownstreamScheme").Exists())
        {
            overrides[$"Routes:{index}:DownstreamScheme"] = "http";
        }
        index++;
    }
    if (overrides.Count > 0) configuration.AddInMemoryCollection(overrides);
}

static void CopySection(IConfigurationSection source, string destBase, Dictionary<string, string?> dict)
{
    var children = source.GetChildren();
    if (!children.Any())
    {
        dict[destBase] = source.Value;
        return;
    }

    foreach (var child in children)
    {
        var key = string.IsNullOrEmpty(child.Key) ? destBase : $"{destBase}:{child.Key}";
        CopySection(child, key, dict);
    }
}

static bool IsAdminAuthorized(HttpContext ctx)
{
    var adminKey = Environment.GetEnvironmentVariable("GW_ADMIN_KEY") ?? Environment.GetEnvironmentVariable("GW_ADMINKEY");
    if (string.IsNullOrEmpty(adminKey))
    {
        return true; // no key configured
    }
    return ctx.Request.Headers.TryGetValue("X-Admin-Key", out var provided) && string.Equals(provided.ToString(), adminKey, StringComparison.Ordinal);
}

static string DeriveIntegrationId(string serial)
{
    if (string.IsNullOrWhiteSpace(serial))
    {
        return string.Empty;
    }

    var digits = new string(serial.Where(char.IsDigit).ToArray());
    if (digits.Length == 0)
    {
        return string.Empty;
    }

    if (digits.Length >= 4)
    {
        return digits.Substring(0, 4);
    }

    return digits.PadRight(4, '0');
}

public partial class Program;
