# Sepidar Gateway

Sepidar Gateway is a multi-tenant API Gateway-as-a-Device built on **.NET 9** and **Ocelot**. It encapsulates the "Sepidar E-Commerce Web Service v1.0.0" device registration, authentication, and header requirements while exposing a uniform gateway to internal clients such as web, mobile, and back-office services.

## Key capabilities

- ✅ **Gateway-as-a-Device** – the gateway registers as a single Sepidar device per tenant, manages RSA/AES crypto, and caches JWTs.
- ✅ **Multi-tenancy** – tenant resolution via host, header, or path base; tenant-specific CORS, rate limits, and API keys.
- ✅ **Mandatory header injection** – `GenerationVersion`, `IntegrationID`, `ArbitraryCode`, `EncArbitraryCode`, and bearer tokens added via a delegating handler.
- ✅ **Observability & resilience** – correlation IDs, health checks, rate limiting, and background token validation out of the box.
- ✅ **Container ready** – Dockerfile and docker-compose for running the gateway against Sepidar.

## Project structure

```
SepidarGateway.sln
├── SepidarGateway/            # ASP.NET Core minimal API gateway
│   ├── Auth/                  # Device registration & login orchestration
│   ├── Configuration/         # Strongly typed options
│   ├── Crypto/                # AES & RSA helpers
│   ├── Handlers/              # Ocelot delegating handlers
│   ├── Middleware/            # Correlation ID, tenant, and client auth middleware
│   ├── Observability/         # Correlation ID helpers and diagnostics
│   ├── Services/              # Background lifecycle services
│   └── Tenancy/               # Tenant resolver and context
└── docker-compose.yml         # Gateway container configuration
```

## Configuration

All customer/tenant customization lives in configuration files or environment variables – **no tenant specific data is hard-coded**.

### `appsettings.json`

- پیکربندی آمادهٔ تولید برای آدرس `http://178.131.66.32:7373` و کاربر `robat` را در `Gateway:Tenants[0]` قرار داده‌ایم.
- تمام مسیرهای اصلی `/api/...` به صورت پیش‌فرض در `Gateway:Ocelot:Routes` درج شده‌اند.
- همان ساختار `Ocelot` در ریشه نیز نگهداری شده تا بتوانید در زمان استقرار از طریق متغیرهای ENV آن را بازنویسی کنید.

### Tenant configuration schema

```jsonc
{
  "Gateway": {
    "Tenants": [
      {
        "TenantId": "main-tenant",
        "Match": {
          "Header": { "HeaderName": "X-Tenant-ID", "HeaderValues": ["main-tenant"] },
          "Hostnames": ["gateway.internal"],
          "PathBase": "/t/main"
        },
        "Sepidar": {
          "BaseUrl": "http://178.131.66.32:7373",
          "IntegrationId": "10006c18",
          "DeviceSerial": "10006c18",
          "GenerationVersion": "101"
        },
        "Credentials": {
          "UserName": "robat",
          "PasswordMd5": "7294a8e1350ed4228c575b9ab855de30"
        },
        "Crypto": {},
        "Jwt": { "CacheSeconds": 1800, "PreAuthCheckSeconds": 300 },
        "Clients": { "ApiKeys": [] },
        "Limits": { "RequestsPerMinute": 120, "QueueLimit": 100, "RequestTimeoutSeconds": 60 }
      }
    ]
  }
}
```

> الگوی کامل همراه با توضیحات فارسی برای جایگزینی مقادیر در [`SepidarGateway/appsettings.TenantSample.json`](SepidarGateway/appsettings.TenantSample.json) قرار دارد.

### مقادیری که باید برای هر مشتری آماده و جایگزین کنید

| مقدار | محل تنظیم | مقدار فعلی در سورس | از کجا تهیه شود |
| --- | --- | --- | --- |
| `TenantId` | `Gateway:Tenants[].TenantId` و `Gateway__Tenants__0__TenantId` | `main-tenant` | شناسه داخلی که در لاگ‌ها و سیاست‌ها استفاده می‌شود |
| رزولوشن تننت | `Gateway:Tenants[].Match` یا متغیرهای ENV متناظر | Header `X-Tenant-ID = main-tenant` + Host `gateway.internal` + Path `/t/main` | بر اساس معماری شما (Host، Header یا PathBase) |
| `Sepidar.BaseUrl` | کانفیگ یا ENV | `http://178.131.66.32:7373` | آدرس سرور Sepidar مشتری |
| `Sepidar.IntegrationId` | کانفیگ یا ENV | `10006c18` | از سریال دستگاه (کد رجیستر) استخراج می‌شود |
| `Sepidar.DeviceSerial` | کانفیگ یا ENV | `10006c18` | سریال دستگاه ثبت‌شده در Sepidar |
| `Sepidar.GenerationVersion` | کانفیگ یا ENV | `101` | مقدار `api version` اعلام‌شده توسط Sepidar |
| `Credentials.UserName` | کانفیگ یا ENV | `robat` | نام کاربری Sepidar |
| `Credentials.PasswordMd5` | کانفیگ یا ENV | `7294a8e1350ed4228c575b9ab855de30` | هش MD5 پسورد (مثال: `printf "89757" | md5sum`) |
| `Crypto.RsaPublicKeyXml` | کانفیگ یا ENV | تهی (در شروع) | پس از اولین `RegisterDevice` در پاسخ Sepidar ذخیره کنید |
| `Jwt.CacheSeconds` و `PreAuthCheckSeconds` | کانفیگ یا ENV | `1800` و `300` | بر اساس سیاست تمدید توکن قابل تغییر است |
| `Limits.RequestsPerMinute`، `QueueLimit`، `RequestTimeoutSeconds` | کانفیگ یا ENV | `120`، `100`، `60` | با سیاست نرخ‌دهی داخلی هماهنگ کنید |

### گام‌های آماده‌سازی کانفیگ برای مشتری جدید

1. فایل `SepidarGateway/appsettings.TenantSample.json` را کپی کنید و در فایل محیطی خود (مثل `appsettings.Production.json`) قرار دهید.
2. مقادیر ستون «مقدار فعلی در سورس» را با داده‌های مشتری جدید جایگزین کنید. اگر از Docker استفاده می‌کنید، همان مقادیر را در `docker-compose.yml` نیز بروزرسانی کنید (راهنما کنار هر خط نوشته شده است).
3. اولین بار که گیت‌وی اجرا می‌شود و عملیات `RegisterDevice` موفق باشد، مقادیر `RsaPublicKeyXml`، `RsaModulusBase64` و `RsaExponentBase64` در لاگ چاپ می‌شود؛ آن‌ها را در بخش `Crypto` ذخیره کنید تا دفعه بعد نیازی به رجیستر مجدد نباشد.
4. در صورت نیاز، API Key یا تنظیمات CORS را برای مشتری فعال کنید (آرایه‌ها را خالی گذاشته‌ایم تا اختیاری باشند).

## اجرای محلی و تست اولیه

```bash
# Restore & build
export PATH="$HOME/.dotnet:$PATH"
dotnet build

# Run the gateway (locally on port 8080)
cd SepidarGateway
ASPNETCORE_URLS=http://localhost:8080 dotnet run
```

With the bundled configuration the gateway will listen on `http://localhost:8080`. یک درخواست ساده از کلاینت داخلی به شکل زیر است:

```http
GET /api/Customers HTTP/1.1
Host: localhost:8080
X-Tenant-ID: main-tenant
```

پس از بالا آمدن سرویس، برای اطمینان از صحت اجرا این گام‌ها را انجام دهید:

1. سلامت گیت‌وی را بررسی کنید: `curl http://localhost:8080/health/ready` باید وضعیت `Healthy` برگرداند.
2. یک درخواست واقعی به سپیدار بفرستید (مثال همگام‌سازی نسخه):
   ```bash
   curl -H "X-Tenant-ID: main-tenant" http://localhost:8080/api/General/GenerationVersion/
   ```
   اگر مقادیر کانفیگ درست باشد، پاسخ 200 با مقدار نسخه (`101`) برمی‌گردد؛ در صورت خطای 412 نسخه سپیدار را بررسی و به‌روزرسانی کنید.
3. در لاگ‌های گیت‌وی مطمئن شوید عملیات `RegisterDevice` تنها بار اول انجام شده و سپس JWT کش می‌شود.

گیت‌وی تمامی هدرهای اجباری Sepidar (`GenerationVersion`, `IntegrationID`, `ArbitraryCode`, `EncArbitraryCode`) و توکن احراز هویت را قبل از ارسال به مقصد `http://178.131.66.32:7373` اضافه می‌کند.

### Swagger & API explorer

- Swagger UI در نشانی [`http://localhost:8080/swagger`](http://localhost:8080/swagger) در دسترس است.
- مستندات OpenAPI مستقیماً از `Gateway:Ocelot:Routes` ساخته می‌شود؛ هر مسیری که در کانفیگ اضافه کنید، بلافاصله در Swagger دیده می‌شود.
- در پنجره Authorize فقط هدر `X-Tenant-ID` (مثال: `main-tenant`) را وارد کنید تا درخواست‌های "Try it out" از طریق همان تننت ارسال شود.
- تب "Schemas" فهرست پاسخ‌های متداول Sepidar (`200`، `401`، `412`) را نشان می‌دهد تا رفتار خطاها مشخص باشد.

## Docker

```bash
# Build the gateway image
docker build -t sepidar-gateway .

# Start the container on port 8080
docker compose up --build
```

- `Dockerfile` targets `mcr.microsoft.com/dotnet/aspnet:9.0-alpine` and exposes port **8080**.
- `docker-compose.yml` starts only the gateway container and uses the production Sepidar endpoint (`http://178.131.66.32:7373`).
- Override any environment variable in `docker-compose.yml` to run the gateway for an additional customer.

## Security notes

- اگر برای مشتری‌ای API Key تعریف کردید، کلاینت داخلی باید `X-API-Key` متناظر را ارسال کند؛ در غیر این صورت این هدر اختیاری است.
- سیاست‌های CORS برای هر تننت جداگانه اعمال می‌شود.
- مقادیر حساس (IntegrationID، سریال، رمزها، کلید RSA) را حتماً از طریق ENV یا Secret Store تأمین کنید و در سورس کنترل قرار ندهید.

## Further customization

- Extend `Gateway:Ocelot:Routes` to enumerate every documented endpoint, or override `Ocelot__Routes` at deployment time.
- Implement mTLS by replacing `ClientAuthorizationMiddleware` if desired.
- Tune rate limiting by adjusting `Tenants[].Limits`.

Enjoy building on top of Sepidar Gateway! 🎉
