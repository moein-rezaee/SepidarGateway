# Sepidar Gateway

Sepidar Gateway is a multi-tenant API Gateway-as-a-Device built on **.NET 9**, **Ocelot**, and **Serilog**. It encapsulates the "Sepidar E-Commerce Web Service v1.0.0" device registration, authentication, and header requirements while exposing a uniform gateway to internal clients such as web, mobile, and back-office services.

## Key capabilities

- ✅ **Gateway-as-a-Device** – the gateway registers as a single Sepidar device per tenant, manages RSA/AES crypto, and caches JWTs.
- ✅ **Multi-tenancy** – tenant resolution via host, header, or path base; tenant-specific CORS, rate limits, and API keys.
- ✅ **Mandatory header injection** – `GenerationVersion`, `IntegrationID`, `ArbitraryCode`, `EncArbitraryCode`, and bearer tokens added via a delegating handler.
- ✅ **Observability & resilience** – Serilog JSON logs, correlation IDs, health checks, rate limiting, and background token validation.
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
│   ├── Observability/         # Logging helpers
│   ├── Services/              # Background lifecycle services
│   └── Tenancy/               # Tenant resolver and context
├── SepidarGateway.Tests/      # Unit & integration tests (xUnit + WireMock.Net)
└── docker-compose.yml         # Gateway + mock Sepidar
```

## Configuration

All customer/tenant customization lives in configuration files or environment variables – **no tenant specific data is hard-coded**.

### `appsettings.json`

- Defines Serilog sinks and a sample tenant (`Gateway:Tenants[0]`).
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
3. Provide the RSA public key obtained from the `RegisterDevice` flow (first run stores the key in configuration or environment secret stores).

No code changes are required – configuration reloads are supported.

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
