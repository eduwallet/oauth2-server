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

### 🆔 OpenID 4 Verifiable Credentials
- **issuer_state Support**: Full implementation of `issuer_state` parameter for verifiable credential issuance flows
- **State Persistence**: Maintains authorization state through OAuth2 proxy flows
- **UserInfo Integration**: Returns `issuer_state` in userinfo responses when present in original authorization request

### 🔒 OAuth 2.0 Attestation-Based Client Authentication
- **Enterprise Security**: Hardware-backed client authentication for mobile and IoT devices
- **Trust Levels**: Configurable trust requirements based on attestation strength
- **Multiple Methods**: Support for JWT-based and TLS certificate-based attestation
- **Proxy Mode Support**: Attestation verification in proxy flows before upstream communication
- **Comprehensive Debugging**: Detailed logging for attestation verification steps
- **Standards Compliance**: Follows draft-ietf-oauth-attestation-based-client-auth-07

### 🛡️ Trust Anchor Management
- **Dynamic Certificate Upload**: Upload X.509 trust anchor certificates via API
- **Certificate Validation**: Automatic PEM format and X.509 validation
- **Name-Based Resolution**: Reference trust anchors by name in client configurations
- **Secure Storage**: Isolated certificate storage with access controls
- **CRUD Operations**: Create, read, update, delete trust anchor certificates

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
- ✅ **OpenID 4 Verifiable Credential Issuance 1.0** - `issuer_state` parameter support

### Extensions
- 🛡️ **Trust Anchor Management API** - Dynamic certificate management for attestation validation

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
- **internal/attestation/**: OAuth 2.0 Attestation-Based Client Authentication implementation with JWT and TLS certificate verification, comprehensive debugging, and proxy mode support.
- **internal/flows/**: Implements various OAuth2 flows.
- **internal/handlers/**: Defines HTTP handlers for API endpoints including trust anchor management and dynamic client registration.
- **internal/models/**: Data models used in the application.
- **internal/store/**: Storage and retrieval of data.
- **internal/utils/**: Utility functions.
- **pkg/config/**: Configuration management.
- **helm/oauth2-server/**: Kubernetes Helm chart for deployment.
- **.env.example**: Environment variables template for proxy mode and server configuration.
- **static/**: Static web assets (minimal, if any).
- **docker-compose.yml**: Docker Compose configuration for local development.
- **Dockerfile**: Container image definition.
- **Makefile**: Build and development automation.
- **go.mod** / **go.sum**: Go module dependencies.

## Features

- **OAuth2 Authorization Flows**: Authorization Code, Client Credentials, Device Authorization, Refresh Token, Token Exchange
- **Attestation-Based Authentication**: Hardware-backed client authentication with JWT and TLS certificate support, proxy mode verification, and comprehensive debugging
- **Trust Anchor Management**: Dynamic upload and management of X.509 trust anchor certificates for attestation validation
- **OpenID 4 Verifiable Credentials**: Full `issuer_state` parameter support for verifiable credential issuance flows
- **Security**: JWT-based tokens, PKCE, HTTPS, proxy-aware, rate limiting, CORS
- **Management**: Dynamic client registration via API (with audience support and attestation configuration)
- **Token Introspection**: `/introspect` endpoint returns all standard fields, including `aud` as a JSON array
- **Token Statistics**: `/token/stats` endpoint provides statistics about issued, active, revoked, and expired tokens

## Setup Instructions

### Local Development

```bash
git clone <repository-url>
cd oauth2-server

# Copy environment configuration
cp .env.example .env
# Edit .env with your configuration

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

### Environment Variables

The server supports configuration via environment variables for security-sensitive settings:

#### Upstream Provider Configuration (Proxy Mode)

When these environment variables are set, the server runs in proxy mode and ignores user details from `config.yaml`:

```bash
# Required for proxy mode
UPSTREAM_PROVIDER_URL=https://accounts.google.com
UPSTREAM_CLIENT_ID=your-client-id
UPSTREAM_CLIENT_SECRET=your-client-secret
UPSTREAM_CALLBACK_URL=http://localhost:8080/callback
```

**Security Note**: Upstream provider configuration has been moved from `config.yaml` to environment variables only to prevent storing sensitive credentials in configuration files.

#### Other Environment Variables

```bash
# Server configuration
PUBLIC_BASE_URL=https://your-domain.com
PORT=8080
HOST=localhost

# Security
JWT_SIGNING_KEY=your-jwt-secret

# Logging
LOG_LEVEL=debug
LOG_FORMAT=json
ENABLE_AUDIT=true

# Proxy settings
TRUST_PROXY_HEADERS=true
FORCE_HTTPS=false
```

### Configuration Files

See `values.yaml` and `docker-compose.yml` for additional configuration options.

**Trust Anchor Storage**: Trust anchor certificates are stored in `/tmp/trust-anchors/` directory with `.pem` file extensions. Ensure this directory is writable by the server process and consider mounting it as a persistent volume in production deployments.

### Proxy Mode

When upstream provider environment variables are configured, the server operates in proxy mode:

1. **Client Authentication**: Accepts requests from downstream clients
2. **Token Issuance**: Issues proxy-controlled access tokens instead of passing through upstream tokens
3. **UserInfo Proxying**: Maps proxy tokens back to upstream tokens for userinfo requests
4. **Security**: Upstream tokens are never exposed to downstream clients

**Token Flow in Proxy Mode:**
- Downstream client requests token → Server validates with upstream → Server issues proxy token
- Downstream client calls userinfo with proxy token → Server maps to upstream token → Server proxies userinfo call

This provides an additional security layer where upstream access tokens are never exposed to client applications.

## OAuth 2.0 Attestation-Based Client Authentication

This server implements OAuth 2.0 Attestation-Based Client Authentication as specified in [draft-ietf-oauth-attestation-based-client-auth-07](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/). This provides enterprise-grade security for mobile applications, IoT devices, and other clients that can provide cryptographic proof of their integrity and authenticity.

### Overview

Attestation-based authentication allows clients to authenticate using hardware-backed cryptographic attestations instead of traditional client secrets. This is particularly valuable for:

- **Mobile Applications**: Apps running on devices with hardware security modules (HSM) or secure enclaves
- **IoT Devices**: Hardware devices with embedded secure elements or TPMs
- **High-Security Environments**: Applications requiring cryptographic proof of client integrity

### Supported Attestation Methods

#### 1. JWT-Based Attestation (`attest_jwt_client_auth`)

Clients authenticate using signed JWT tokens that contain attestation claims and X.509 certificate chains:

```json
{
  "alg": "ES256",
  "x5c": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."],
  "typ": "JWT"
}
```

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
  experimental: true
  trust_anchors:
    - name: "hsm_ca"
      type: "hsm"
      certificate_path: "/tmp/certs/hsm_ca.pem"
      enabled: true
      description: "HSM root CA certificate"
  
  clients:
    - client_id: "hsm-attestation-wallet-demo"
      allowed_methods: ["attest_jwt_client_auth"]
      trust_anchors: ["hsm_ca"]
      required_level: "high"
    
    - client_id: "mobile-banking-app"
      allowed_methods: ["attest_jwt_client_auth", "attest_tls_client_auth"]
      trust_anchors: ["mobile_ca"]
      required_level: "high"
```

### Proxy Mode Attestation Verification

When running in proxy mode, attestation verification occurs **before** proxying requests to upstream providers:

1. **Client Authentication**: Downstream client sends token request with attestation
2. **Attestation Verification**: Server verifies JWT assertion and certificate chain
3. **Proxy Only After Success**: Only successful attestation allows upstream communication
4. **Clean Proxying**: Attestation parameters are removed before upstream requests

**Security Flow:**
- **Downstream (HSM Demo)**: `client_id` + JWT client assertion attestation
- **Upstream (Google OAuth2)**: `client_id` + `client_secret` (standard OAuth2)

### Client Configuration

Clients using attestation must be configured as public clients with attestation settings:

```yaml
clients:
  - id: "hsm-attestation-wallet-demo"
    name: "HSM Attestation Wallet Demo"
    public: true
    token_endpoint_auth_method: "none"
    grant_types: ["authorization_code", "refresh_token"]
    attestation_config:
      client_id: "hsm-attestation-wallet-demo"
      allowed_methods: ["attest_jwt_client_auth"]
      trust_anchors: ["hsm_ca"]
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

### HSM Attestation Demo

The included HSM attestation wallet demo showcases real-world attestation authentication:

**Demo Components:**
- **HSM Demo App**: Browser-based wallet application (`examples/hsm-attestation-wallet/`)
- **Docker Setup**: Complete environment with certificate generation and HSM simulation
- **Real Attestation**: Uses JWT client assertions with X.509 certificate chains

**Demo Flow:**
1. **Certificate Generation**: Docker container generates HSM CA and client certificates
2. **JWT Creation**: Demo app creates signed JWT with attestation claims and certificate chain
3. **Attestation Verification**: Server validates JWT signature and certificate chain
4. **Proxy Authentication**: Only after successful attestation, request proxies to upstream Google OAuth2

**Running the Demo:**

```bash
# Start the complete demo environment
docker compose up

# Access the demo app at http://localhost:8001
# The app will demonstrate attestation-based authentication
```

**Demo Configuration:**
```yaml
# HSM demo client configuration
clients:
  - id: "hsm-attestation-wallet-demo"
    name: "HSM Attestation Wallet Demo"
    public: true
    token_endpoint_auth_method: "none"
    grant_types: ["authorization_code", "refresh_token"]
    attestation_config:
      client_id: "hsm-attestation-wallet-demo"
      allowed_methods: ["attest_jwt_client_auth"]
      trust_anchors: ["/tmp/certs/hsm_ca.pem"]
      required_level: "high"
```

## OpenID 4 Verifiable Credential Issuance Support

The server implements `issuer_state` parameter support as specified in [OpenID 4 Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-issuer_state).

#### issuer_state Parameter

The `issuer_state` parameter allows credential issuers to maintain state across the OAuth2 authorization flow:

- **Authorization Request**: Include `issuer_state` in the authorization URL
- **State Persistence**: Server maintains the original `issuer_state` through proxy flows
- **UserInfo Response**: Returns `issuer_state` in userinfo responses when present in original authorization request
- **Proxy Mode**: Properly handles `issuer_state` in upstream provider proxy scenarios

#### Usage Example

```bash
# Authorization request with issuer_state
GET /auth?response_type=code&client_id=vc-wallet&redirect_uri=https://wallet.example.com/callback&scope=openid&issuer_state=abc123def456

# UserInfo response includes issuer_state
{
  "sub": "user123",
  "iss": "https://oauth2-server.example.com",
  "aud": "vc-wallet",
  "issuer_state": "abc123def456",
  "iat": 1640995200,
  "exp": 1640998800
}
```

#### Proxy Mode issuer_state Handling

When running in proxy mode, the server:

1. **Captures issuer_state**: Extracts `issuer_state` from downstream authorization requests
2. **Persists State**: Stores mapping between authorization codes and `issuer_state`
3. **Returns in UserInfo**: Includes `issuer_state` in userinfo responses for the authenticated user
4. **Clean State Management**: Properly manages state cleanup after token exchange

This enables verifiable credential wallets and issuers to maintain session state across complex OAuth2 proxy architectures.

### Security Considerations

1. **Certificate Validation**: All attestation certificates are validated against configured trust anchors
2. **Revocation Checking**: Certificate revocation status is verified when possible
3. **Timestamp Validation**: Attestation timestamps are checked for freshness
4. **Hardware Requirements**: High trust levels require hardware-backed key storage
5. **Audit Logging**: All attestation attempts are logged for security monitoring
6. **Proxy Mode Security**: Attestation verification occurs before upstream communication

### Debugging and Monitoring

The attestation system provides comprehensive debug logging for troubleshooting:

```bash
# JWT attestation verification logs
[DEBUG] JWT attestation verification starting for client: hsm-attestation-wallet-demo
[DEBUG] Leaf certificate parsed successfully - Subject: ..., Issuer: ...
[DEBUG] JWT signature verification successful
[DEBUG] Subject validation successful
[DEBUG] Attestation verification completed successfully

# Proxy mode attestation logs
[PROXY] Attestation required for client: hsm-attestation-wallet-demo
[PROXY] Attestation verification successful for client: hsm-attestation-wallet-demo
[PROXY] Removed attestation parameters from request before proxying
```

### Monitoring and Metrics

Attestation events are tracked in Prometheus metrics:

```promql
# Attestation verification attempts
oauth2_attestation_verifications_total{client_id="hsm-demo", method="jwt", result="success"}

# Trust level distribution
oauth2_attestation_trust_level{level="high", client_id="hsm-demo"}

# Verification latency
oauth2_attestation_verification_duration_seconds{method="jwt"}
```

## Trust Anchor Management

The server provides a REST API for managing trust anchor certificates used in attestation-based client authentication. Trust anchors are X.509 certificates that serve as root certificates for validating client attestation chains.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/trust-anchor/` | GET | List all available trust anchors |
| `/trust-anchor/{name}` | POST | Upload a trust anchor certificate |
| `/trust-anchor/{name}` | DELETE | Delete a trust anchor certificate |

### Upload Trust Anchor

Upload an X.509 certificate in PEM format as a trust anchor:

```bash
curl -X POST http://localhost:8080/trust-anchor/hsm-ca \
  -F "certificate=@hsm-ca.pem"
```

**Response:**
```json
{
  "name": "hsm-ca",
  "path": "/tmp/trust-anchors/hsm-ca.pem",
  "status": "uploaded"
}
```

### List Trust Anchors

Get a list of all uploaded trust anchor names:

```bash
curl http://localhost:8080/trust-anchor/
```

**Response:**
```json
{
  "trust_anchors": ["hsm-ca", "mobile-ca", "iot-ca"]
}
```

### Delete Trust Anchor

Remove a trust anchor certificate:

```bash
curl -X DELETE http://localhost:8080/trust-anchor/hsm-ca
```

**Response:**
```json
{
  "name": "hsm-ca",
  "status": "deleted"
}
```

### Certificate Requirements

- **Format**: PEM-encoded X.509 certificate
- **Validation**: Automatic X.509 parsing and validation
- **Size Limit**: Maximum 1MB per certificate
- **Storage**: Certificates are stored in `/tmp/trust-anchors/` with `.pem` extension
- **Naming**: Trust anchor names must be valid filenames (no path traversal allowed)

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

## API Endpoints

### OAuth2/OIDC Endpoints

| Endpoint | Method | Description | RFC |
|----------|--------|-------------|-----|
| `/authorize` | GET | Authorization endpoint | RFC 6749 |
| `/token` | POST | Token endpoint (all grant types, including device code and token exchange) | RFC 6749, 8628, 8693 |
| `/device/authorize` | POST | Device authorization | RFC 8628 |
| `/device` | GET | Device verification UI | RFC 8628 |
| `/device/verify` | POST | Device code verification | RFC 8628 |
| `/device/consent` | POST | Device consent | RFC 8628 |
| `/introspect` | POST | Token introspection (returns `aud` as array) | RFC 7662 |
| `/revoke` | POST | Token revocation | RFC 6749 |
| `/userinfo` | GET | UserInfo endpoint (requires Authorization header) | OIDC Core |
| `/register` | POST | Dynamic client registration (with audience and attestation support) |
| `/claims` | GET | Claims display (interactive) |
| `/callback` | GET | OAuth2 callback for demo |

### Trust Anchor Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/trust-anchor/` | GET | List all available trust anchors |
| `/trust-anchor/{name}` | POST | Upload a trust anchor certificate |
| `/trust-anchor/{name}` | DELETE | Delete a trust anchor certificate |

### Discovery & Health

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/oauth-authorization-server` | GET | OAuth2 server metadata |
| `/.well-known/openid-configuration` | GET | OIDC configuration |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/health` | GET | Health check |
| `/stats` | GET | Server statistics |
| `/status` | GET | Server status |
| `/version` | GET | Version information |

## Usage Guidelines
### Unified Login & Authorization UI

Both the device code flow and authorization code flow use a unified, modern login/authorization page. This page adapts to the flow and provides a seamless user experience for browser and device flows.

See `templates/unified_auth.html` for the implementation.

### Claims Display & Callback

The `/claims` endpoint displays the claims of the authenticated user interactively. The `/callback` endpoint is used for OAuth2 browser flows and demo integration.

### UserInfo Endpoint

The `/userinfo` endpoint returns OIDC claims for the authenticated user. **Requires an `Authorization: Bearer <access_token>` header**. Used by the demo and claims display pages. **Returns `issuer_state` in responses when present in the original authorization request** (OpenID 4 Verifiable Credentials support).


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

#### Client Registration with Attestation Configuration

Register a client with attestation-based authentication:

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "HSM Attestation Wallet",
    "token_endpoint_auth_method": "attest_jwt_client_auth",
    "grant_types": ["authorization_code", "refresh_token"],
    "redirect_uris": ["https://wallet.example.com/callback"],
    "scope": "openid profile",
    "attestation_config": {
      "client_id": "hsm-wallet-client",
      "allowed_methods": ["attest_jwt_client_auth"],
      "trust_anchors": ["hsm-ca"],
      "required_level": "high"
    }
  }'
```

**Response:**
```json
{
  "client_id": "generated-client-id",
  "client_secret": null,
  "client_secret_expires_at": 0,
  "registration_access_token": null,
  "registration_client_uri": null,
  "client_id_issued_at": 1699275600,
  "redirect_uris": ["https://wallet.example.com/callback"],
  "token_endpoint_auth_method": "attest_jwt_client_auth",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "client_name": "HSM Attestation Wallet",
  "scope": "openid profile",
  "audience": ["generated-client-id"],
  "attestation_config": {
    "client_id": "hsm-wallet-client",
    "allowed_methods": ["attest_jwt_client_auth"],
    "trust_anchors": ["/tmp/trust-anchors/hsm-ca.pem"],
    "required_level": "high"
  }
}
```

**Note**: Trust anchor names in the `attestation_config.trust_anchors` array are automatically resolved to their file paths during registration. The uploaded trust anchor "hsm-ca" becomes "/tmp/trust-anchors/hsm-ca.pem" in the stored configuration.

### Complete Attestation Setup Workflow

1. **Upload Trust Anchor Certificate**:
   ```bash
   curl -X POST http://localhost:8080/trust-anchor/hsm-ca \
     -F "certificate=@hsm-ca.pem"
   ```

2. **Register Client with Attestation Configuration**:
   ```bash
   curl -X POST http://localhost:8080/register \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "HSM Wallet App",
       "token_endpoint_auth_method": "attest_jwt_client_auth",
       "grant_types": ["authorization_code"],
       "redirect_uris": ["https://wallet.example.com/callback"],
       "attestation_config": {
         "allowed_methods": ["attest_jwt_client_auth"],
         "trust_anchors": ["hsm-ca"],
         "required_level": "high"
       }
     }'
   ```

3. **Client Uses Attestation for Authentication**:
   ```bash
   # Client creates JWT with attestation claims and certificate chain
   curl -X POST https://oauth2-server.example.com/token \
     -d "grant_type=authorization_code" \
     -d "code=auth_code" \
     -d "redirect_uri=https://wallet.example.com/callback" \
     -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
     -d "client_assertion=${ATTESTATION_JWT}"
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

## API Endpoint Protection

The server provides configurable protection for sensitive management endpoints. By default, these endpoints are **disabled** for security reasons.

#### Protected Endpoints

- **`/register`** - Dynamic client registration
- **`/trust-anchor/*`** - Trust anchor certificate management

#### Configuration

Enable and protect these endpoints using environment variables:

```bash
# Enable the endpoints (disabled by default)
ENABLE_REGISTRATION_API=true
ENABLE_TRUST_ANCHOR_API=true

# Set API key for authentication
API_KEY=your-secure-api-key-here
```

Or in `config.yaml`:

```yaml
security:
  enable_registration_api: true
  enable_trust_anchor_api: true
  api_key: "your-secure-api-key-here"
```

#### API Key Authentication

When enabled, these endpoints require an `X-API-Key` header:

```bash
# Example: Register a client
curl -X POST http://localhost:8080/register \
  -H "X-API-Key: your-secure-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": ["https://example.com/callback"]}'

# Example: Upload trust anchor
curl -X POST http://localhost:8080/trust-anchor/ca-cert \
  -H "X-API-Key: your-secure-api-key-here" \
  -F "certificate=@ca.pem"
```

#### Security Recommendations

1. **Keep Disabled by Default**: These endpoints are disabled by default for security
2. **Use Strong API Keys**: Generate long, random API keys (32+ characters)
3. **Network Restrictions**: Consider restricting access to these endpoints at the network level
4. **Monitor Usage**: Enable audit logging to track API usage
5. **Regular Rotation**: Rotate API keys regularly

**Warning**: These endpoints allow modification of server configuration. Only enable them when necessary and protect them appropriately.