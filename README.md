# Sepidar Gateway

Sepidar Gateway is a multi-tenant API Gateway-as-a-Device built on **.NET 9** and **Ocelot**. It encapsulates the "Sepidar E-Commerce Web Service v1.0.0" device registration, authentication, and header requirements while exposing a uniform gateway to internal clients such as web, mobile, and back-office services.

## Key capabilities

- ✅ **Gateway-as-a-Device** – the gateway registers as a single Sepidar device per tenant, manages RSA/AES crypto, and caches JWTs.
- ✅ **Multi-tenancy** – tenant resolution via host, header, or path base; tenant-specific CORS, rate limits, and API keys.
- ✅ **Mandatory header injection** – `GenerationVersion`, `IntegrationID`, `ArbitraryCode`, `EncArbitraryCode`, and bearer tokens added via a delegating handler.
- ✅ **Observability & resilience** – correlation IDs, health checks, rate limiting, and background token validation out of the box.
- ✅ **Container ready** – Dockerfile and docker-compose for running the gateway plus a mock Sepidar backend.

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
├── SepidarGateway.Tests/      # Unit & integration tests (xUnit + WireMock.Net)
└── docker-compose.yml         # Gateway + mock Sepidar
```

## Configuration

All customer/tenant customization lives in configuration files or environment variables – **no tenant specific data is hard-coded**.

### `appsettings.json`

- Includes a sample tenant (`Gateway:Tenants[0]`) you can copy for each customer.
- Lists default Ocelot routes for `/api/...` endpoints.
- Mirrors the `Ocelot` section at the root so Ocelot can load its configuration while still being overridden through `Gateway:Ocelot`.

### Tenant configuration schema

```jsonc
{
  "Gateway": {
    "Tenants": [
      {
        "TenantId": "tenant-code",
        "Match": {
          "Hostnames": ["tenant.example.com"],
          "Header": { "HeaderName": "X-Tenant-ID", "HeaderValues": ["tenant-code"] },
          "PathBase": "/t/tenant-code"
        },
        "Sepidar": {
          "BaseUrl": "http://sepidar.internal:7373",
          "IntegrationId": "<derived integration id>",
          "DeviceSerial": "<device serial>",
          "GenerationVersion": "1.0.0"
        },
        "Credentials": { "UserName": "gateway", "PasswordMd5": "<md5 hash>" },
        "Crypto": { "RsaPublicKeyXml": "<RSA XML after registration>" },
        "Jwt": { "CacheSeconds": 3600, "PreAuthCheckSeconds": 300 },
        "Clients": { "ApiKeys": ["<internal service key>"] },
        "Limits": { "RequestsPerMinute": 600, "QueueLimit": 100, "RequestTimeoutSeconds": 120 },
        "Cors": { "AllowedOrigins": ["https://tenant.app"], "AllowCredentials": true }
      }
    ],
    "Ocelot": {
      "Routes": [
        { "UpstreamPathTemplate": "/api/Customers", "DownstreamPathTemplate": "/api/Customers", "UpstreamHttpMethod": ["GET", "POST"] },
        { "UpstreamPathTemplate": "/api/{everything}", "DownstreamPathTemplate": "/api/{everything}", "UpstreamHttpMethod": ["GET", "POST", "PUT", "DELETE", "PATCH"] }
      ]
    }
  }
}
```

> A ready-to-copy template is provided in [`SepidarGateway/appsettings.TenantSample.json`](SepidarGateway/appsettings.TenantSample.json).

### Add a new tenant in three steps

1. Duplicate the sample tenant object in `appsettings.{Environment}.json` (or set the equivalent `Gateway__Tenants__{i}__...` environment variables).
2. Update the Sepidar credentials, serial number, and matching strategy (host/header/path).
3. Provide the RSA public key obtained from the `RegisterDevice` flow (first run logs the key so you can copy it into configuration or a secret store).

No code changes are required – configuration reloads are supported.

## Step-by-step: configure and run the gateway

1. **Install .NET 9 SDK.** If you do not already have it, use `dotnet-install.sh` or the official Microsoft installers.
2. **Copy the sample configuration.** Duplicate `SepidarGateway/appsettings.TenantSample.json` into `appsettings.Development.json` (or another environment-specific file) and adjust the tenant entry for each customer.
3. **Fill in the required tenant values.** Use the reference in the next section to gather the correct Integration ID, serial number, credentials, and API keys.
4. **Optionally move secrets to environment variables.** Every setting can be provided as `Gateway__Tenants__{index}__...` environment variables when deploying.
5. **Restore and build.** From the repository root run `dotnet build`.
6. **Run the gateway.** Change into the `SepidarGateway` folder and execute `dotnet run`. The gateway starts on `http://localhost:5000` unless you override `ASPNETCORE_URLS`.
7. **Capture the RSA key the first time.** If `Gateway:Tenants[].Crypto` is empty, the first successful registration logs the RSA key information. Copy `RsaPublicKeyXml`, `RsaModulusBase64`, and `RsaExponentBase64` into configuration for future runs.
8. **Point your internal clients at the gateway.** They send requests to `/api/...` on the gateway host with the tenant identifier (host/header/path) and an optional `X-API-Key` if you configured API keys.

## Where to get each configuration value

| Setting | Where it comes from | Notes |
| --- | --- | --- |
| `TenantId` | Your own short identifier for the customer | Used in logs and rate-limiter partitioning. |
| `Match.Hostnames[]` | Public/private hostnames you control | Requests whose `Host` header matches use this tenant. Leave empty if not matching by host. |
| `Match.Header.HeaderName` & `HeaderValues[]` | Internal client contract | Provide the header name/value pair your internal callers will send (default `X-Tenant-ID`). |
| `Match.PathBase` | Gateway URL design | Optional base path prefix such as `/t/<tenant>`. Leave `/` to disable path-based matching. |
| `Sepidar.BaseUrl` | Sepidar E-Commerce API endpoint provided by Sepidar | Use the base address (e.g. `https://sepidar.company.local`) that exposes `/api/...`. |
| `Sepidar.IntegrationId` | Supplied by Sepidar when your device serial is provisioned | In Sepidar’s documentation the Integration ID is derived from the registered device; request it from Sepidar support if unknown. |
| `Sepidar.DeviceSerial` | The Sepidar device serial assigned to your integration | Appears in the Sepidar portal or paperwork for the registered device. |
| `Sepidar.GenerationVersion` | Result of `GET api/General/GenerationVersion/` on Sepidar | Keep in sync; the gateway forwards it on each request and treats 412 as a version mismatch. |
| `Credentials.UserName` | Sepidar service account | Create or reuse a dedicated Sepidar user for the gateway. |
| `Credentials.PasswordMd5` | MD5 hash of the Sepidar user password | Generate with e.g. `echo -n "<password>" | md5sum` and copy the hex string (uppercase or lowercase accepted). |
| `Crypto.RsaPublicKeyXml`/`RsaModulusBase64`/`RsaExponentBase64` | Returned by `POST api/Devices/Register/` | Leave empty on the first run; once registration succeeds copy the logged values back into configuration or secrets. |
| `Jwt.CacheSeconds` & `PreAuthCheckSeconds` | Your desired token caching policy | Determines how long the JWT is reused and when `/api/IsAuthorized/` is polled. |
| `Clients.ApiKeys[]` | Keys you issue to internal callers | Optional – if populated, callers must send `X-API-Key` with one of these values. |
| `Limits.*` | Your throttling requirements | Controls per-tenant rate limiting and request timeout. |
| `Cors.*` | Front-end origins that should call the gateway | Configure origins/headers/methods per tenant; leave arrays empty to block browser origins. |
| `Gateway.Ocelot.Routes` | Mapping of Sepidar endpoints | Extend or override with every Sepidar API route you need to expose. |

## Running locally

```bash
# Restore & build
export PATH="$HOME/.dotnet:$PATH"
dotnet build

# Run the gateway
cd SepidarGateway
dotnet run
```

The gateway listens on `http://localhost:5000` by default. An internal client only needs to call the gateway:

```http
GET /api/Customers HTTP/1.1
Host: localhost:5000
X-Tenant-ID: sample
X-API-Key: local-development-key
```

The gateway will ensure the Sepidar headers (`GenerationVersion`, `IntegrationID`, `ArbitraryCode`, `EncArbitraryCode`) and bearer token are attached before proxying the request.

## Docker

A production-ready image is provided:

```bash
# Build the gateway image
docker build -t sepidar-gateway .

# Run gateway + mock Sepidar
docker compose up --build
```

- `Dockerfile` targets `mcr.microsoft.com/dotnet/aspnet:9.0-alpine` and exposes port **5000**.
- `docker-compose.yml` wires the gateway to a mock Sepidar service, sets environment overrides for a sample tenant, and defines `/health/live` + `/health/ready` health checks.

## Testing

```bash
# Run all unit + integration tests
export PATH="$HOME/.dotnet:$PATH"
dotnet test
```

Test coverage includes:

- AES/RSA registration crypto round-trip.
- Arbitrary code RSA encryption for the `EncArbitraryCode` header.
- JWT caching & re-use (`SepidarAuthService`).
- Tenant resolution via header/path combinations.
- Integration test using WireMock.Net validating forwarded Sepidar headers and authorization.

## Security notes

- Internal clients must present a valid `X-API-Key` per tenant.
- CORS policies are evaluated per tenant.
- Sensitive secrets (integration IDs, RSA keys, passwords) should be provided via environment variables or secret stores – never commit them to source control.

## Further customization

- Extend `Gateway:Ocelot:Routes` to enumerate every documented endpoint, or override `Ocelot__Routes` at deployment time.
- Implement mTLS by replacing `ClientAuthorizationMiddleware` if desired.
- Tune rate limiting by adjusting `Tenants[].Limits`.

Enjoy building on top of Sepidar Gateway! 🎉
