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
- **Proxy Mode Support**: Forwards device authorization requests to upstream providers with proper code mapping and token exchange

### 🔄 Token Exchange (RFC 8693)
- Secure service-to-service token delegation
- Supports audience-specific tokens
- **Supports `requested_token_type`**: Request a `refresh_token` or `access_token` as the result of a token exchange

### 🔐 Pushed Authorization Requests (PAR) (RFC 9126)
- **Secure Request Pushing**: Clients can push authorization requests securely before redirecting users
- **Request URI Support**: Generated request URIs for secure parameter transmission
- **Proxy Mode Support**: PAR requests are properly forwarded to upstream providers in proxy mode
- **Standards Compliance**: Full RFC 9126 implementation with proper expiration and validation

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
- **Privileged Client Audience Inclusion**: Attestation-enabled clients automatically get privileged clients added to their audience for token introspection access
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
- ✅ Pushed Authorization Requests (PAR)

### RFC Compliance
- ✅ **RFC 6749** - OAuth 2.0 Authorization Framework
- ✅ **RFC 8628** - Device Authorization Grant
- ✅ **RFC 8693** - Token Exchange
- ✅ **RFC 9126** - OAuth 2.0 Pushed Authorization Requests
- ✅ **RFC 7591** - Dynamic Client Registration
- ✅ **RFC 8414** - Authorization Server Metadata
- ✅ **OpenID Connect Core 1.0**
- ✅ **draft-ietf-oauth-attestation-based-client-auth-07** - OAuth 2.0 Attestation-Based Client Authentication
- ✅ **OpenID 4 Verifiable Credential Issuance 1.0** - `issuer_state` parameter support

### Extensions
- 🛡️ **Trust Anchor Management API** - Dynamic certificate management for attestation validation
- 🔐 **Privileged Client Audience Inclusion** - Automatic audience management for attestation-enabled clients enabling privileged client token introspection

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
- **internal/handlers/**: Defines HTTP handlers for API endpoints including trust anchor management, dynamic client registration, and pushed authorization requests (removed unused secret_manager.go file).
- **internal/models/**: Data models used in the application.
- **internal/store/**: Storage and retrieval of data.
- **internal/utils/**: Core utility functions for JWT operations, token handling, and string manipulation (cleaned of unused functions during deadcode removal).
- **pkg/config/**: Configuration management.
- **helm/oauth2-server/**: Kubernetes Helm chart for deployment.
- **.env.example**: Environment variables template for proxy mode and server configuration.
- **tests/**: Comprehensive test suite for OAuth2 flows, attestation features, and privileged client functionality
  - `test_attestation_privileged_audience.sh`: Validates privileged client audience inclusion for attestation-enabled clients
  - `test_introspection_jwt_client_assertion.sh`: Validates JWT client assertion authentication for token introspection
  - `test_refresh_token_basic.sh`: Basic refresh token functionality testing
  - `test_refresh_token_exchange.sh`: Advanced refresh token exchange testing

## Features

- **OAuth2 Authorization Flows**: Authorization Code, Client Credentials, Device Authorization, Refresh Token, Token Exchange, Pushed Authorization Requests (PAR)
- **Attestation-Based Authentication**: Hardware-backed client authentication with JWT and TLS certificate support, proxy mode verification, and comprehensive debugging
- **Trust Anchor Management**: Dynamic upload and management of X.509 trust anchor certificates for attestation validation
- **OpenID 4 Verifiable Credentials**: Full `issuer_state` parameter support for verifiable credential issuance flows
- **Security**: JWT-based tokens, PKCE, HTTPS, proxy-aware, rate limiting, CORS
- **Management**: Dynamic client registration via API (with audience support and attestation configuration)
- **Token Introspection**: `/introspect` endpoint returns all standard fields, including `aud` as a JSON array and attestation metadata for attested clients
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

## Command Line Options

The OAuth2 server supports several command line options for configuration and information:

### Options

- `--config`, `-c` (string): Path to configuration file (default: "config.yaml")
- `--version`, `-v`: Show version information
- `--help`, `-h`: Show help information

### Environment Variables

See the [Environment Variables](#environment-variables-reference) section below for a complete list of supported environment variables.

- `CONFIG_FILE`: Path to configuration file (overrides `--config`/`-c`)

### Examples

```bash
# Start server with default configuration
./bin/oauth2-server

# Use custom configuration file
./bin/oauth2-server --config custom.yaml
./bin/oauth2-server -c custom.yaml

# Show version information
./bin/oauth2-server --version
./bin/oauth2-server -v

# Show help
./bin/oauth2-server --help
./bin/oauth2-server -h

# Using environment variable
CONFIG_FILE=/path/to/config.yaml ./bin/oauth2-server
```

CIMD (Client-Initiated Metadata Discovery): see [docs/CIMD.md](docs/CIMD.md) for details and a runnable example in `examples/cimd` (run `examples/cimd/serve.sh` and enable `CIMD_ENABLED=true` to test local registration).

## Deployment

For detailed deployment instructions including Kubernetes Helm charts and configuration options, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Code Quality & Deadcode Management

This project maintains high code quality standards and actively removes unused (dead) code to improve maintainability and reduce complexity.

### Deadcode Checking

Use the `check-deadcode` Makefile target to identify and remove unused functions:

```bash
# Check for dead code in the entire codebase
make check-deadcode

# This will install and run the deadcode tool from golang.org/x/tools/cmd/deadcode
```

**Note**: Some functions may appear as "unreachable" in the deadcode output but are actually used through interfaces, reflection, or conditional logic that static analysis cannot detect. Always verify before removing functions.

## Version Management

For detailed information about version management processes, release procedures, and versioning guidelines, see [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md).

## Testing

For comprehensive testing documentation including test scripts, validation procedures, and expected results, see [docs/TESTING.md](docs/TESTING.md).

You can test all test cases with command **make test**

```
$ make test
🔨 Building OAuth2 server...
go build -ldflags "-s -w" -o bin/oauth2-server cmd/server/main.go
✅ Build completed: bin/oauth2-server
🧪 Starting automated test suite with test isolation...
Testing test_attestation_auth.sh                 ... ✅ PASSED
Testing test_attestation_integration.sh          ... ✅ PASSED
Testing test_attestation_privileged_audience.sh  ... ✅ PASSED
Testing test_auth_code_pkce.sh                   ... ✅ PASSED
Testing test_authorization_introspection.sh      ... ✅ PASSED
Testing test_client_registration.sh              ... ✅ PASSED
Testing test_complete_flow.sh                    ... ✅ PASSED
Testing test_device_flow.sh                      ... ✅ PASSED
Testing test_introspection_jwt_client_assertion.sh ... ✅ PASSED
Testing test_introspection.sh                    ... ✅ PASSED
Testing test_oauth2_flow.sh                      ... ✅ PASSED
Testing test_privileged_introspection.sh         ... ✅ PASSED
Testing test_proxy_attestation_client.sh         ... ✅ PASSED
Testing test_proxy_authorization_introspection.sh ... ✅ PASSED
Testing test_proxy_device_flow.sh                ... ✅ PASSED
Testing test_proxy_full_authentication_flow.sh   ... ✅ PASSED
Testing test_proxy_public_client_flow.sh         ... ✅ PASSED
Testing test_proxy_pushed_authorize_request.sh   ... ✅ PASSED
Testing test_proxy_token_exchange.sh             ... ✅ PASSED
Testing test_proxy_userinfo.sh                   ... ✅ PASSED
Testing test_public_client_flow.sh               ... ✅ PASSED
Testing test_pushed_authorize_request.sh         ... ✅ PASSED
Testing test_refresh_token_basic.sh              ... ✅ PASSED
Testing test_refresh_token_exchange.sh           ... ✅ PASSED
Testing test_scope_handling.sh                   ... ✅ PASSED
Testing test_token_exchange.sh                   ... ✅ PASSED
Testing test_userinfo.sh                         ... ✅ PASSED
Testing test_validation.sh                       ... ✅ PASSED

════════════════════════════════════════════════════════════════
📊 Test Summary: 28 passed, 0 failed
════════════════════════════════════════════════════════════════
✅ All tests passed!
```

## Configuration

For detailed configuration options including environment variables, configuration files, and proxy mode setup, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Environment Variables Reference

The OAuth2 server supports comprehensive configuration through environment variables. These override values from `config.yaml`.

### Server Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PUBLIC_BASE_URL` | string | - | Public base URL for the OAuth2 server (used in tokens and discovery endpoints) |
| `PORT` | int | 8080 | Server port |

### Logging Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `LOG_LEVEL` | string | info | Logging level (`debug`, `info`, `warn`, `error`) |
| `LOG_FORMAT` | string | json | Log format (`json` or `text`) |
| `ENABLE_AUDIT_LOGGING` | bool | false | Enable audit logging for security events |

### Database Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_TYPE` | string | sqlite | Database type (`sqlite`, `postgres`, `mysql`, `memory`) |
| `DATABASE_PATH` | string | ./oauth2.db | Database file path (for sqlite) or connection string |

### Proxy/Network Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `TRUST_PROXY_HEADERS` | bool | true | Trust proxy headers (X-Forwarded-*, etc.) when behind reverse proxy |
| `FORCE_HTTPS` | bool | false | Force HTTPS redirects |
| `TRUSTED_PROXIES` | string | - | Comma-separated list of trusted proxy IP addresses or CIDR ranges |

### Upstream Provider Configuration (Proxy Mode)

**Security Note**: When these are set, the server runs in proxy mode. Store these securely (e.g., Kubernetes secrets).

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `UPSTREAM_PROVIDER_URL` | string | - | Upstream OAuth2 provider URL (e.g., `https://accounts.google.com`) |
| `UPSTREAM_CLIENT_ID` | string | - | Client ID for the upstream provider |
| `UPSTREAM_CLIENT_SECRET` | string | - | Client secret for the upstream provider |
| `UPSTREAM_CALLBACK_URL` | string | - | Callback URL for the upstream provider (should point to this server) |

### Security Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `JWT_SIGNING_KEY` | string | - | JWT signing key (use a strong, random key in production) |
| `ENCRYPTION_KEY` | string | - | 32-byte key for encrypting sensitive data (required; must be 32 chars) |
| `TOKEN_EXPIRY_SECONDS` | int | 3600 | Access token expiry time in seconds (default: 1 hour) |
| `REFRESH_TOKEN_EXPIRY_SECONDS` | int | 86400 | Refresh token expiry time in seconds (default: 24 hours) |
| `DEVICE_CODE_EXPIRY_SECONDS` | int | 600 | Device code lifetime in seconds |
| `AUTHORIZATION_CODE_EXPIRY_SECONDS` | int | 600 | Authorization code lifetime in seconds |
| `REQUIRE_HTTPS` | bool | false | Require HTTPS for all OAuth2 endpoints |
| `ENABLE_PKCE` | bool | true | Enable PKCE (Proof Key for Code Exchange) support |
| `ALLOW_SYNTHETIC_ID_TOKEN` | bool | false | If upstream omits `id_token`, allow proxy to mint one (use with caution) |
| `API_KEY` | string | - | API key for protected endpoints (registration, trust anchor management) |
| `ENABLE_REGISTRATION_API` | bool | false | Enable dynamic client registration API |
| `ENABLE_TRUST_ANCHOR_API` | bool | false | Enable trust anchor management API for attestation |
| `PRIVILEGED_CLIENT_ID` | string | - | Client ID used for privileged server operations |

### Dynamic Client Configuration

Clients can be configured via environment variables using the following pattern:

| Pattern | Description | Example |
|---------|-------------|---------|
| `CLIENT_<ID>_SECRET` | Client secret (required) | `CLIENT_WEBAPP_SECRET=my-secret` |
| `CLIENT_<ID>_NAME` | Client display name | `CLIENT_WEBAPP_NAME="My Web App"` |
| `CLIENT_<ID>_REDIRECT_URIS` | Comma-separated redirect URIs | `CLIENT_WEBAPP_REDIRECT_URIS=https://app.example.com/callback,http://localhost:3000/callback` |
| `CLIENT_<ID>_GRANT_TYPES` | Comma-separated grant types | `CLIENT_WEBAPP_GRANT_TYPES=authorization_code,refresh_token` |
| `CLIENT_<ID>_RESPONSE_TYPES` | Comma-separated response types | `CLIENT_WEBAPP_RESPONSE_TYPES=code` |
| `CLIENT_<ID>_SCOPES` | Comma-separated scopes | `CLIENT_WEBAPP_SCOPES=openid,profile,email` |

**Example:**
```bash
CLIENT_WEBAPP_SECRET=super-secret-key
CLIENT_WEBAPP_NAME="My Web Application"
CLIENT_WEBAPP_REDIRECT_URIS=https://app.example.com/callback
CLIENT_WEBAPP_GRANT_TYPES=authorization_code,refresh_token
CLIENT_WEBAPP_SCOPES=openid,profile,email
```

### Dynamic User Configuration

Users can be configured via environment variables using the following pattern:

| Pattern | Description | Example |
|---------|-------------|---------|
| `USER_<ID>_USERNAME` | Username (required) | `USER_ADMIN_USERNAME=admin` |
| `USER_<ID>_PASSWORD` | User password | `USER_ADMIN_PASSWORD=secure-password` |
| `USER_<ID>_EMAIL` | User email | `USER_ADMIN_EMAIL=admin@example.com` |
| `USER_<ID>_NAME` | User display name | `USER_ADMIN_NAME="Administrator"` |

**Example:**
```bash
USER_ADMIN_USERNAME=admin
USER_ADMIN_PASSWORD=secure-password-123
USER_ADMIN_EMAIL=admin@example.com
USER_ADMIN_NAME="System Administrator"
```

### Environment Variable Precedence

1. **Environment variables** (highest priority)
2. Configuration file specified by `CONFIG_FILE` or `--config`
3. Default `config.yaml` in current directory
4. Built-in defaults (lowest priority)

### Configuration Examples

#### Minimal Production Setup
```bash
PUBLIC_BASE_URL=https://auth.example.com
JWT_SIGNING_KEY=your-256-bit-secret-key
DATABASE_TYPE=postgres
DATABASE_PATH=postgres://user:pass@localhost/oauth2db
API_KEY=your-api-key-for-management-endpoints
ENABLE_REGISTRATION_API=true
LOG_LEVEL=info
LOG_FORMAT=json
```

#### Proxy Mode Setup
```bash
PUBLIC_BASE_URL=https://oauth-proxy.example.com
UPSTREAM_PROVIDER_URL=https://accounts.google.com
UPSTREAM_CLIENT_ID=your-client-id.apps.googleusercontent.com
UPSTREAM_CLIENT_SECRET=your-client-secret
UPSTREAM_CALLBACK_URL=https://oauth-proxy.example.com/callback
JWT_SIGNING_KEY=your-jwt-signing-key
API_KEY=your-api-key
```

#### Development Setup
```bash
PORT=8080
DATABASE_TYPE=memory
LOG_LEVEL=debug
LOG_FORMAT=text
ENABLE_AUDIT_LOGGING=true
REQUIRE_HTTPS=false
ENABLE_REGISTRATION_API=true
ENABLE_TRUST_ANCHOR_API=true
API_KEY=dev-api-key-change-me
```

## OAuth 2.0 Attestation-Based Client Authentication

For detailed information about OAuth 2.0 Attestation-Based Client Authentication, including setup, configuration, and usage examples, see [docs/ATTESTATION.md](docs/ATTESTATION.md).

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

## API Documentation

For detailed API documentation including all endpoints, authentication methods, and usage examples, see [docs/API.md](docs/API.md).

---

**Built with ❤️ using [Fosite](https://github.com/ory/fosite) - The security first OAuth2 & OpenID Connect framework

