# OAuth2 Server

[![CI/CD](https://github.com/HarryKodden/oauth2-server/actions/workflows/ci.yml/badge.svg)](https://github.com/HarryKodden/oauth2-server/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/HarryKodden/oauth2-server)](https://goreportcard.com/report/github.com/HarryKodden/oauth2-server)
[![Go Reference](https://pkg.go.dev/badge/github.com/HarryKodden/oauth2-server.svg)](https://pkg.go.dev/github.com/HarryKodden/oauth2-server)
[![Go Version](https://img.shields.io/badge/go-1.23-blue.svg)](https://golang.org/dl/)
[![Docker Image](https://img.shields.io/docker/v/harrykodden/oauth2-server?sort=semver)](https://hub.docker.com/r/harrykodden/oauth2-server)
[![GitHub release](https://img.shields.io/github/release/HarryKodden/oauth2-server.svg)](https://github.com/HarryKodden/oauth2-server/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A feature-rich OAuth2 and OpenID Connect server focused on API capabilities, supporting multiple flows, dynamic client registration, token exchange, audience management, and introspection.

## Key Features

### 📱 Device Code Flow (RFC 8628)
- User initiates flow on device
- Device displays user code and verification URL
- User visits URL on another device to authorize
- Device polls for token completion

### 🔄 Token Exchange (RFC 8693)
- Secure service-to-service token delegation
- Supports audience-specific tokens
- **Supports `requested_token_type`**: Request a `refresh_token` or `access_token` as the result of a token exchange

### 🔧 Dynamic Client Registration (RFC 7591)
- Programmatic client registration at runtime via API
- Specify `audience` during registration

### ♻️ Refresh Tokens
- Configurable token lifespans per token type
- Secure token rotation

### 🎯 Audience Support
- Specify `audience` during client registration and token requests
- Tokens include an `aud` claim (array of strings) in both the token and introspection response
- Audience is validated on token issuance and refresh

### 🔒 OAuth 2.0 Attestation-Based Client Authentication
- **Enterprise Security**: Hardware-backed client authentication for mobile and IoT devices
- **Trust Levels**: Configurable trust requirements based on attestation strength
- **Multiple Methods**: Support for JWT-based and TLS certificate-based attestation
- **Standards Compliance**: Follows draft-ietf-oauth-attestation-based-client-auth-07

### OAuth2 Grant Types
- ✅ Authorization Code
- ✅ Client Credentials
- ✅ Device Code
- ✅ Token Exchange
- ✅ Refresh Token

### RFC Compliance
- ✅ **RFC 6749** - OAuth 2.0 Authorization Framework
- ✅ **RFC 8628** - Device Authorization Grant
- ✅ **RFC 8693** - Token Exchange
- ✅ **RFC 7591** - Dynamic Client Registration
- ✅ **RFC 8414** - Authorization Server Metadata
- ✅ **OpenID Connect Core 1.0**
- ✅ **draft-ietf-oauth-attestation-based-client-auth-07** - OAuth 2.0 Attestation-Based Client Authentication

### Production Features
- ✅ Kubernetes native
- ✅ Security hardening
- ✅ Horizontal scaling
- ✅ Health checks
- ✅ Monitoring ready
- ✅ Ingress support

## Project Structure

- **cmd/server/main.go**: Entry point of the application. Initializes the server and sets up routes and middleware.
- **internal/auth/**: Authentication and authorization logic for OAuth2 flows.
- **internal/attestation/**: OAuth 2.0 Attestation-Based Client Authentication implementation.
- **internal/flows/**: Implements various OAuth2 flows.
- **internal/handlers/**: Defines HTTP handlers for API endpoints.
- **internal/models/**: Data models used in the application.
- **internal/store/**: Storage and retrieval of data.
- **internal/utils/**: Utility functions.
- **pkg/config/**: Configuration management.
- **helm/oauth2-server/**: Kubernetes Helm chart for deployment.
- **static/**: Static web assets (minimal, if any).
- **docker-compose.yml**: Docker Compose configuration for local development.
- **Dockerfile**: Container image definition.
- **Makefile**: Build and development automation.
- **go.mod** / **go.sum**: Go module dependencies.

## Features

- **OAuth2 Authorization Flows**: Authorization Code, Client Credentials, Device Authorization, Refresh Token, Token Exchange
- **Attestation-Based Authentication**: Hardware-backed client authentication with JWT and TLS certificate support
- **Security**: JWT-based tokens, PKCE, HTTPS, proxy-aware, rate limiting, CORS
- **Management**: Dynamic client registration via API (with audience support)
- **Token Introspection**: `/introspect` endpoint returns all standard fields, including `aud` as a JSON array
- **Token Statistics**: `/token/stats` endpoint provides statistics about issued, active, revoked, and expired tokens

## Setup Instructions

### Local Development

```bash
git clone <repository-url>
cd oauth2-server
go mod tidy
docker-compose up
# or
make run
# or
go run cmd/server/main.go
```

### Kubernetes Deployment

```bash
kubectl create namespace oauth2-server
helm install oauth2-server ./helm/oauth2-server -n oauth2-server --set config.server.baseUrl="https://your-domain.com" --set config.jwt.secret="your-jwt-secret"
```

## Configuration

See `values.yaml` and `docker-compose.yml` for configuration options.

## OAuth 2.0 Attestation-Based Client Authentication

This server implements OAuth 2.0 Attestation-Based Client Authentication as specified in [draft-ietf-oauth-attestation-based-client-auth-07](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/). This provides enterprise-grade security for mobile applications, IoT devices, and other clients that can provide cryptographic proof of their integrity and authenticity.

### Overview

Attestation-based authentication allows clients to authenticate using hardware-backed cryptographic attestations instead of traditional client secrets. This is particularly valuable for:

- **Mobile Applications**: Apps running on devices with hardware security modules (HSM) or secure enclaves
- **IoT Devices**: Hardware devices with embedded secure elements or TPMs
- **High-Security Environments**: Applications requiring cryptographic proof of client integrity

### Supported Attestation Methods

#### 1. JWT-Based Attestation (`attest_jwt_client_auth`)

Clients authenticate using signed JWT tokens that contain attestation claims:

```json
{
  "iss": "attestor-service",
  "sub": "client_id",
  "aud": ["https://oauth2-server.example.com"],
  "iat": 1699275600,
  "exp": 1699279200,
  "cnf": {
    "jwk": { "kty": "RSA", "n": "...", "e": "AQAB" }
  },
  "att_type": "android_safetynet",
  "att_level": "high",
  "att_hardware_backed": true,
  "att_device_integrity": "verified"
}
```

#### 2. TLS Certificate-Based Attestation (`attest_tls_client_auth`)

Clients authenticate using X.509 client certificates with attestation extensions:

```bash
# Example client certificate request with attestation
curl -X POST https://oauth2-server.example.com/oauth/token \
  --cert client-cert.pem \
  --key client-key.pem \
  -d "grant_type=client_credentials&client_id=attested-client"
```

### Configuration

Enable attestation in your `config.yaml`:

```yaml
attestation:
  enabled: true
  clients:
    - client_id: "mobile-banking-app"
      allowed_methods:
        - "attest_jwt_client_auth"
        - "attest_tls_client_auth"
      trust_anchors:
        - |
          -----BEGIN CERTIFICATE-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
          -----END CERTIFICATE-----
      required_level: "high"
    
    - client_id: "iot-sensor-network"
      allowed_methods:
        - "attest_tls_client_auth"
      trust_anchors:
        - |
          -----BEGIN CERTIFICATE-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
          -----END CERTIFICATE-----
      required_level: "medium"
```

### Client Configuration

Clients using attestation must be configured with attestation settings:

```yaml
clients:
  - id: "mobile-banking-app"
    name: "Mobile Banking Application"
    grant_types: ["client_credentials", "authorization_code"]
    token_endpoint_auth_method: "attest_jwt_client_auth"
    attestation_config:
      client_id: "mobile-banking-app"
      allowed_methods: ["attest_jwt_client_auth"]
      trust_anchors: ["attestation-ca-cert"]
      required_level: "high"
```

### Trust Levels

The system supports three trust levels based on attestation strength:

- **`high`**: Hardware-backed keys, secure enclaves, verified boot chains
- **`medium`**: Software-based attestation with device integrity checks
- **`low`**: Basic attestation without hardware backing

### Discovery Support

The OAuth2 discovery endpoint automatically advertises supported attestation methods:

```bash
curl https://oauth2-server.example.com/.well-known/oauth-authorization-server | jq '.token_endpoint_auth_methods_supported'
```

```json
[
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
  "client_secret_jwt",
  "none",
  "attest_jwt_client_auth",
  "attest_tls_client_auth"
]
```

### Usage Examples

#### JWT Attestation

```bash
# Generate or obtain an attestation JWT
ATTESTATION_JWT="eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlCLi4uIl19.eyJpc3MiOi..."

# Use in token request
curl -X POST https://oauth2-server.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=${ATTESTATION_JWT}"
```

#### TLS Certificate Attestation

```bash
# Use client certificate for attestation
curl -X POST https://oauth2-server.example.com/oauth/token \
  --cert client-attestation.crt \
  --key client-attestation.key \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=iot-device-001"
```

### Security Considerations

1. **Certificate Validation**: All attestation certificates are validated against configured trust anchors
2. **Revocation Checking**: Certificate revocation status is verified when possible
3. **Timestamp Validation**: Attestation timestamps are checked for freshness
4. **Hardware Requirements**: High trust levels require hardware-backed key storage
5. **Audit Logging**: All attestation attempts are logged for security monitoring

### Monitoring and Metrics

Attestation events are tracked in Prometheus metrics:

```promql
# Attestation verification attempts
oauth2_attestation_verifications_total{client_id="mobile-app", method="jwt", result="success"}

# Trust level distribution
oauth2_attestation_trust_level{level="high", client_id="mobile-app"}

# Verification latency
oauth2_attestation_verification_duration_seconds{method="jwt"}
```

### Development and Testing

For development and testing, a mock verifier is available:

```yaml
attestation:
  enabled: true
  clients:
    - client_id: "test-client"
      allowed_methods: ["mock"]
      trust_anchors: ["mock-anchor"]
      required_level: "medium"
```

The mock verifier accepts any token and always returns a successful verification result.

## API Endpoints

### OAuth2/OIDC Endpoints

| Endpoint | Method | Description | RFC |
|----------|--------|-------------|-----|
| `/auth` | GET | Authorization endpoint | RFC 6749 |
| `/oauth/authorize` | GET | Authorization endpoint (PKCE, browser/curl) | RFC 6749 |
| `/oauth/token` | POST | Token endpoint (all grant types, including device code and token exchange) | RFC 6749, 8628, 8693 |
| `/device/authorize` | POST | Device authorization | RFC 8628 |
| `/device` | GET | Device verification UI | RFC 8628 |
| `/device/verify` | POST | Device code verification | RFC 8628 |
| `/device/consent` | POST | Device consent | RFC 8628 |
| `/oauth/introspect` | POST | Token introspection (returns `aud` as array) | RFC 7662 |
| `/oauth/revoke` | POST | Token revocation | RFC 6749 |
| `/userinfo` | GET | UserInfo endpoint (requires Authorization header) | OIDC Core |
| `/register` | POST | Dynamic client registration (with audience) |
| `/claims` | GET | Claims display (interactive) |
| `/callback` | GET | OAuth2 callback for demo |
| `/demo` | GET | Interactive PKCE demo page |

### Discovery & Health

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/oauth-authorization-server` | GET | OAuth2 server metadata |
| `/.well-known/openid-configuration` | GET | OIDC configuration |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/health` | GET | Health check |
| `/stats` | GET | Server statistics |
| `/` | GET | Minimal server info and stats (no docs UI) |

## Usage Guidelines
### Unified Login & Authorization UI

Both the device code flow and authorization code flow use a unified, modern login/authorization page. This page adapts to the flow and provides a seamless user experience for browser and device flows.

See `templates/unified_auth.html` for the implementation.

### Interactive Demo Page & Test Users

The `/demo` endpoint provides an interactive PKCE demo for browser and cURL flows. It includes:
- Example test users for quick login
- Step-by-step flow visualization
- Claims display and callback integration

See `templates/demo.html` for details.

### Claims Display & Callback

The `/claims` endpoint displays the claims of the authenticated user interactively. The `/callback` endpoint is used for OAuth2 browser flows and demo integration.

### UserInfo Endpoint

The `/userinfo` endpoint returns OIDC claims for the authenticated user. **Requires an `Authorization: Bearer <access_token>` header**. Used by the demo and claims display pages.


### Client Registration

Use the `/register` endpoint to register OAuth2 clients:

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://myapp.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "audience": ["client_id_of_backend"],
    "scope": "openid profile email"
  }'
```

### Token Exchange for Refresh Token

```bash
curl -X POST http://localhost:8080/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=<refresh_token>" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:refresh_token" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:refresh_token" \
  -d "audience=<target_audience>"
```

### Introspect a Token

```bash
curl -X POST http://localhost:8080/introspect \
  -d "token=<access_or_refresh_token>"
```

**Response:**
```json
{
  "active": true,
  "client_id": "client_xyz",
  "scope": "openid offline_access",
  "token_type": "access_token",
  "exp": 1753869233,
  "iat": 1753865633,
  "aud": ["client_abc", "client_xyz"],
  "iss": "http://localhost:8080",
  "sub": "user-001"
}
```

### Token Statistics

```bash
curl http://localhost:8080/token/stats
```

**Response:**
```json
{
  "active_tokens": 5,
  "expired_tokens": 2,
  "revoked_tokens": 1,
  "total_tokens": 8,
  "by_type": {
    "access_token": { "active": 3, "expired": 1, "revoked": 0, "total": 4 },
    "refresh_token": { "active": 2, "expired": 1, "revoked": 1, "total": 4 }
  },
  "request_time": "2025-07-30T12:00:00Z"
}
```

## Minimal Root Page

The root endpoint `/` returns only server information and statistics in JSON format.  
There is **no documentation UI** or client management UI.

---

**Built with ❤️ using [Fosite](https://github.com/ory/fosite) - The security first OAuth2 & OpenID Connect framework