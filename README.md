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

## Configuration

For detailed configuration options including environment variables, configuration files, and proxy mode setup, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

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

