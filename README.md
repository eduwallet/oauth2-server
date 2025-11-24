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
- **internal/handlers/**: Defines HTTP handlers for API endpoints including trust anchor management and dynamic client registration (removed unused secret_manager.go file).
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

- **OAuth2 Authorization Flows**: Authorization Code, Client Credentials, Device Authorization, Refresh Token, Token Exchange
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

### Kubernetes Deployment

```bash
kubectl create namespace oauth2-server
helm install oauth2-server ./helm/oauth2-server -n oauth2-server --set config.server.baseUrl="https://your-domain.com" --set config.jwt.secret="your-jwt-secret"
```

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

### Running Tests

```bash
# Run all tests
make test

# Run specific test script
make test-script SCRIPT=test_attestation_privileged_audience.sh

# Run tests with coverage
make test-coverage
```

### Test Scripts

The `tests/` directory contains comprehensive automated test scripts for validating various OAuth2/OIDC flows, attestation-based authentication, and advanced features. Each test script includes detailed validation steps and expected results.

#### `test_attestation_privileged_audience.sh` - Privileged Client Audience Inclusion Test

Validates that attestation-enabled clients automatically receive privileged clients in their audience for token introspection capabilities.

```bash
# Run the privileged audience inclusion test
make test-script SCRIPT=test_attestation_privileged_audience.sh
```

**Test Flow:**
1. **Client Registration**: Registers an attestation-enabled client with trust anchor configuration
2. **Grant Type Verification**: Confirms `client_credentials` grant type is automatically added
3. **Audience Verification**: Validates privileged client (`server-owned-client`) is included in audience array
4. **Token Acquisition**: Obtains access token for the privileged client
5. **Introspection Validation**: Confirms privileged client can successfully introspect attestation client tokens

**Expected Results:**
- ✅ Attestation client registration succeeds with trust anchor
- ✅ `client_credentials` grant type automatically added to grant types
- ✅ Privileged client included in the client's audience array
- ✅ Privileged client token acquisition works
- ✅ Audience-based token introspection functions correctly

#### `test_introspection_jwt_client_assertion.sh` - JWT Client Assertion Introspection Test

Validates JWT client assertion authentication for RFC 7662 token introspection with privileged client access.

```bash
# Run the JWT client assertion introspection test
make test-script SCRIPT=test_introspection_jwt_client_assertion.sh
```

**Test Flow:**
1. **Trust Anchor Upload**: Uploads X.509 trust anchor certificate for attestation validation
2. **Client Registration**: Registers attestation-enabled client with JWT client assertion authentication
3. **JWT Assertion Creation**: Generates signed JWT with attestation claims and certificate chain
4. **Token Acquisition**: Obtains access token using JWT client assertion authentication
5. **Privileged Client Setup**: Acquires privileged client token for introspection access
6. **Token Introspection**: Validates privileged client can introspect attestation client tokens
7. **Response Verification**: Confirms introspection response includes attestation metadata

**Expected Results:**
- ✅ Trust anchor certificate upload succeeds
- ✅ Attestation client registration with JWT assertion method works
- ✅ JWT assertion generation with attestation claims succeeds
- ✅ Token acquisition using JWT client assertion authentication works
- ✅ Privileged client token acquisition for introspection succeeds
- ✅ Token introspection by privileged client functions correctly
- ✅ Introspection response includes attestation metadata for attested tokens

#### `test_auth_code_pkce.sh` - Authorization Code Flow with PKCE

Tests the complete OAuth2 authorization code flow with Proof Key for Code Exchange (PKCE) security enhancement.

```bash
# Run the PKCE authorization code flow test
make test-script SCRIPT=test_auth_code_pkce.sh
```

**Test Flow:**
1. **Client Registration**: Registers a client with authorization code grant type
2. **PKCE Setup**: Generates code verifier and challenge using S256 method
3. **Authorization Request**: Initiates authorization request with PKCE parameters
4. **User Authentication**: Simulates user login and consent
5. **Code Exchange**: Exchanges authorization code for tokens using PKCE verification
6. **Token Validation**: Verifies access token and refresh token are valid

**Expected Results:**
- ✅ Client registration succeeds
- ✅ PKCE code challenge and verifier generated correctly
- ✅ Authorization code obtained successfully
- ✅ Token exchange with PKCE verification succeeds
- ✅ Access and refresh tokens are valid and functional

#### `test_client_registration.sh` - Dynamic Client Registration

Validates the OAuth2 Dynamic Client Registration Protocol (RFC 7591) implementation.

```bash
# Run the dynamic client registration test
make test-script SCRIPT=test_client_registration.sh
```

**Test Flow:**
1. **Client Registration Request**: Sends registration request with client metadata
2. **Registration Processing**: Server processes and validates registration data
3. **Client ID Assignment**: Generates unique client identifier
4. **Metadata Storage**: Stores client configuration and credentials
5. **Registration Response**: Returns client configuration with registration access token
6. **Client Validation**: Verifies registered client can authenticate and obtain tokens

**Expected Results:**
- ✅ Client registration request accepted
- ✅ Unique client ID generated and returned
- ✅ Client metadata properly stored
- ✅ Registration access token provided for future updates
- ✅ Registered client can successfully authenticate

#### `test_complete_flow.sh` - Complete OAuth2 Authorization Code Flow

Tests the full OAuth2 authorization code grant flow from start to finish.

```bash
# Run the complete OAuth2 flow test
make test-script SCRIPT=test_complete_flow.sh
```

**Test Flow:**
1. **Client Setup**: Registers client with authorization code grant type
2. **Authorization Request**: Initiates authorization request with required parameters
3. **User Authentication**: Simulates user login process
4. **Consent Grant**: User grants consent for requested scopes
5. **Authorization Code**: Server issues authorization code
6. **Token Exchange**: Client exchanges code for access and refresh tokens
7. **Token Usage**: Validates tokens work for protected resource access
8. **Refresh Token**: Tests token renewal using refresh token

**Expected Results:**
- ✅ Authorization request processed successfully
- ✅ User authentication and consent completed
- ✅ Authorization code issued and valid
- ✅ Token exchange succeeds with proper validation
- ✅ Access token works for resource access
- ✅ Refresh token enables token renewal

#### `test_device_flow.sh` - Device Authorization Grant

Tests the OAuth2 Device Authorization Grant (RFC 8628) for input-constrained devices.

```bash
# Run the device authorization grant test
make test-script SCRIPT=test_device_flow.sh
```

**Test Flow:**
1. **Device Authorization Request**: Device requests authorization without user interaction
2. **User Code Generation**: Server generates user code and verification URI
3. **User Interaction**: User visits verification URI and enters device code
4. **Device Polling**: Device polls token endpoint for authorization status
5. **Token Issuance**: Server issues tokens once user completes authorization
6. **Token Validation**: Verifies issued tokens are valid and functional

**Expected Results:**
- ✅ Device authorization request accepted
- ✅ User code and verification URI generated
- ✅ User verification process works
- ✅ Device polling succeeds after user authorization
- ✅ Access and refresh tokens issued correctly
- ✅ Tokens are valid for resource access

#### `test_introspection.sh` - Token Introspection

Validates RFC 7662 Token Introspection endpoint functionality.

```bash
# Run the token introspection test
make test-script SCRIPT=test_introspection.sh
```

**Test Flow:**
1. **Token Acquisition**: Obtains access token through client credentials flow
2. **Introspection Request**: Client requests token introspection with proper authentication
3. **Token Validation**: Server validates token and client authorization
4. **Metadata Retrieval**: Returns comprehensive token metadata and claims
5. **Response Verification**: Validates introspection response contains correct information
6. **Inactive Token Test**: Tests introspection of expired/revoked tokens

**Expected Results:**
- ✅ Token introspection request authenticated
- ✅ Active token returns full metadata
- ✅ Token claims and scopes correctly reported
- ✅ Inactive tokens properly identified
- ✅ Client authorization enforced

#### `test_oauth2_flow.sh` - Basic OAuth2 Flows

Tests fundamental OAuth2 grant types and basic server functionality.

```bash
# Run the basic OAuth2 flows test
make test-script SCRIPT=test_oauth2_flow.sh
```

**Test Flow:**
1. **Client Credentials Flow**: Tests machine-to-machine authentication
2. **Authorization Code Setup**: Prepares for authorization code flow testing
3. **Token Validation**: Verifies token format and basic claims
4. **Scope Handling**: Tests scope parameter processing
5. **Error Handling**: Validates proper error responses for invalid requests
6. **Endpoint Discovery**: Confirms OAuth2 discovery endpoints work

**Expected Results:**
- ✅ Client credentials grant succeeds
- ✅ Token format and claims are valid
- ✅ Scope parameters processed correctly
- ✅ Error responses follow OAuth2 standards
- ✅ Discovery endpoints return proper metadata

#### `test_privileged_introspection.sh` - Privileged Client Introspection

Tests privileged client capabilities for introspecting tokens from other clients.

```bash
# Run the privileged introspection test
make test-script SCRIPT=test_privileged_introspection.sh
```

**Test Flow:**
1. **Privileged Client Setup**: Configures privileged client with admin credentials
2. **Regular Client Token**: Obtains token from regular client
3. **Privileged Introspection**: Privileged client introspects regular client token
4. **Access Verification**: Confirms privileged client can access token metadata
5. **Security Validation**: Ensures proper authorization controls are enforced
6. **Audit Logging**: Verifies introspection attempts are logged

**Expected Results:**
- ✅ Privileged client authentication succeeds
- ✅ Cross-client token introspection works
- ✅ Token metadata accessible to privileged client
- ✅ Security boundaries maintained
- ✅ Introspection events properly logged

#### `test_public_client_flow.sh` - Public Client Flows

Tests OAuth2 flows for public clients (no client secret).

```bash
# Run the public client flows test
make test-script SCRIPT=test_public_client_flow.sh
```

**Test Flow:**
1. **Public Client Registration**: Registers client without secret
2. **PKCE Requirement**: Ensures PKCE is enforced for public clients
3. **Authorization Code Flow**: Completes flow with PKCE but no client secret
4. **Token Exchange**: Exchanges code for tokens without client authentication
5. **Security Validation**: Confirms proper security measures for public clients
6. **Scope Limitation**: Tests scope restrictions for public clients

**Expected Results:**
- ✅ Public client registration succeeds
- ✅ PKCE enforcement for public clients
- ✅ Authorization flow completes without client secret
- ✅ Token exchange works for public clients
- ✅ Security measures properly implemented

#### `test_scope_handling.sh` - Scope Validation and Handling

Tests OAuth2 scope parameter processing and validation.

```bash
# Run the scope handling test
make test-script SCRIPT=test_scope_handling.sh
```

**Test Flow:**
1. **Scope Request**: Client requests specific scopes in authorization/token requests
2. **Scope Validation**: Server validates requested scopes against allowed scopes
3. **Scope Grant**: User/consent process includes scope approval
4. **Token Scopes**: Issued tokens contain granted scopes
5. **Scope Enforcement**: Protected resources enforce token scopes
6. **Scope Reduction**: Tests scope reduction in token exchange scenarios

**Expected Results:**
- ✅ Scope parameters parsed correctly
- ✅ Invalid scopes rejected appropriately
- ✅ Token scopes match granted scopes
- ✅ Resource access respects token scopes
- ✅ Scope reduction works in token exchange

#### `test_token_exchange.sh` - Token Exchange Functionality

Tests RFC 8693 OAuth2 Token Exchange implementation.

```bash
# Run the token exchange test
make test-script SCRIPT=test_token_exchange.sh
```

**Test Flow:**
1. **Subject Token Acquisition**: Obtains initial access token as subject
2. **Token Exchange Request**: Requests new token using subject token
3. **Exchange Processing**: Server validates and processes exchange request
4. **New Token Issuance**: Issues new token with specified parameters
5. **Token Validation**: Verifies exchanged token has correct claims and scopes
6. **Delegation Chain**: Tests token exchange delegation scenarios

**Expected Results:**
- ✅ Token exchange request accepted
- ✅ Subject token validation succeeds
- ✅ New token issued with correct parameters
- ✅ Token claims properly transferred
- ✅ Delegation and impersonation work correctly

#### `test_refresh_token_basic.sh` - Basic Refresh Token Functionality

Tests fundamental refresh token operations and renewal.

```bash
# Run the basic refresh token test
make test-script SCRIPT=test_refresh_token_basic.sh
```

**Test Flow:**
1. **Client Registration**: Registers client with refresh token grant type
2. **Initial Token Acquisition**: Completes authorization code flow to get initial tokens
3. **Token Renewal**: Uses refresh token to obtain new access token
4. **Token Validation**: Verifies new token is valid and different from original
5. **Multiple Renewals**: Tests repeated refresh operations
6. **Refresh Token Persistence**: Confirms refresh token remains valid across renewals

**Expected Results:**
- ✅ Client registration with refresh token support succeeds
- ✅ Initial authorization code flow completes
- ✅ Refresh token issued alongside access token
- ✅ Token renewal using refresh token works
- ✅ New access tokens are valid and unique
- ✅ Refresh token remains valid for multiple uses

#### `test_refresh_token_exchange.sh` - Advanced Refresh Token Exchange

Tests complex refresh token exchange scenarios between multiple clients.

```bash
# Run the refresh token exchange test
make test-script SCRIPT=test_refresh_token_exchange.sh
```

**Test Flow:**
1. **Multi-Client Setup**: Registers multiple clients for cross-client scenarios
2. **Refresh Token Acquisition**: Obtains refresh tokens for different clients
3. **Token Exchange Request**: Uses refresh tokens as subjects in exchange requests
4. **Cross-Client Exchange**: Tests exchanging refresh tokens between different clients
5. **Audience Validation**: Verifies exchanged tokens have correct audience claims
6. **Token Functionality**: Confirms exchanged tokens work for intended purposes

**Expected Results:**
- ✅ Multiple client registration succeeds
- ✅ Refresh token acquisition works for all clients
- ✅ Token exchange with refresh token as subject succeeds
- ✅ Cross-client refresh token exchange functions correctly
- ✅ Exchanged tokens have proper audience configuration
- ✅ Exchanged tokens are functional for target audiences

#### `test_userinfo.sh` - UserInfo Endpoint Validation

Tests OpenID Connect UserInfo endpoint functionality.

```bash
# Run the UserInfo endpoint test
make test-script SCRIPT=test_userinfo.sh
```

**Test Flow:**
1. **OIDC Flow Completion**: Completes OpenID Connect authorization code flow
2. **Access Token Acquisition**: Obtains access token with openid scope
3. **UserInfo Request**: Requests user information using access token
4. **Claim Validation**: Verifies returned claims match authenticated user
5. **Scope Enforcement**: Tests that appropriate claims are returned based on scopes
6. **Security Validation**: Confirms proper token validation and authorization

**Expected Results:**
- ✅ OpenID Connect flow completes successfully
- ✅ Access token obtained with appropriate scopes
- ✅ UserInfo endpoint returns correct user claims
- ✅ Claims respect granted scopes
- ✅ Token validation and authorization enforced

#### `test_validation.sh` - Request Validation

Tests comprehensive input validation and error handling.

```bash
# Run the validation test
make test-script SCRIPT=test_validation.sh
```

**Test Flow:**
1. **Invalid Parameter Testing**: Tests various invalid request parameters
2. **Malformed Request Handling**: Validates server response to malformed requests
3. **Security Validation**: Tests protection against common attack vectors
4. **Error Response Format**: Verifies proper OAuth2 error response format
5. **Boundary Testing**: Tests edge cases and boundary conditions
6. **Input Sanitization**: Confirms proper input validation and sanitization

**Expected Results:**
- ✅ Invalid requests properly rejected
- ✅ Appropriate error responses returned
- ✅ Security vulnerabilities mitigated
- ✅ Error messages follow OAuth2 standards
- ✅ Input validation prevents malicious requests

#### `test_proxy_attestation_client.sh` - Proxy Mode Attestation

Tests attestation-based client authentication in proxy mode.

```bash
# Run the proxy attestation test
make test-script SCRIPT=test_proxy_attestation_client.sh
```

**Test Flow:**
1. **Proxy Configuration**: Sets up server in proxy mode with upstream provider
2. **Attestation Client Setup**: Registers client with attestation requirements
3. **Attestation Verification**: Client authenticates using attestation credentials
4. **Proxy Token Issuance**: Server issues proxy-controlled tokens
5. **Upstream Communication**: Validates proxying to upstream provider
6. **Token Mapping**: Tests mapping between proxy and upstream tokens

**Expected Results:**
- ✅ Proxy mode configuration succeeds
- ✅ Attestation verification works in proxy mode
- ✅ Proxy tokens issued correctly
- ✅ Upstream provider communication succeeds
- ✅ Token mapping functions properly

#### `test_auth_code_pkce.sh` - Additional Test Scripts

The following test scripts provide additional validation coverage:

- **`test_attestation_auth.sh`**: Comprehensive attestation authentication testing
- **`test_attestation_integration.sh`**: End-to-end attestation integration validation
- **`test_authorization_introspection.sh`**: Authorization-introspection endpoint testing
- **`test_complete_flow.sh`**: Full OAuth2 flow validation (detailed above)
- **`test_device_code.sh`**: Device code grant flow testing
- **`test_public_client_flow.sh`**: Public client authentication flows
- **`test_scope_handling.sh`**: OAuth2 scope parameter validation
- **`test_token_exchange.sh`**: RFC 8693 token exchange implementation
- **`test_trust_anchor.sh`**: Trust anchor certificate management testing

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

### Privileged Client Audience Inclusion

Attestation-enabled clients automatically receive privileged clients in their audience during dynamic registration, enabling token introspection by privileged clients. This feature ensures that privileged clients (configured as `server-owned-client` by default) can introspect tokens issued to attestation-enabled clients.

#### How It Works

1. **Client Registration**: When registering a client with `attestation_config`, the server automatically:
   - Adds `client_credentials` grant type if not present
   - Includes the privileged client ID in the client's audience array
   - Logs the privileged client inclusion for audit purposes

2. **Token Introspection**: Privileged clients can introspect tokens from attestation-enabled clients using the `/introspect` endpoint

3. **Configuration**: The privileged client ID is configurable via the `PRIVILEGED_CLIENT_ID` environment variable or `config.security.privilegedClientId` in configuration files

#### Example Registration

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
      "trust_anchors": ["hsm_ca"],
      "required_level": "high"
    }
  }'
```

**Response with Privileged Client Audience:**
```json
{
  "client_id": "generated-client-id",
  "client_secret_expires_at": 0,
  "grant_types": ["authorization_code", "client_credentials"],
  "audience": ["generated-client-id", "server-owned-client"],
  "attestation_config": {
    "client_id": "generated-client-id",
    "allowed_methods": ["attest_jwt_client_auth"],
    "trust_anchors": ["hsm_ca"],
    "required_level": "high"
  }
}
```

#### Privileged Client Token Introspection

```bash
# Get privileged client token
curl -X POST http://localhost:8080/token \
  -u "server-owned-client:server-admin-secret" \
  -d "grant_type=client_credentials&scope=admin"

# Introspect attestation client token
curl -X POST http://localhost:8080/introspect \
  -u "server-owned-client:server-admin-secret" \
  -d "token=<attestation_client_token>"
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
| `/introspect` | POST | Token introspection (returns `aud` as array, includes attestation metadata) | RFC 7662 |
| `/authorization-introspection` | POST | Combined token introspection and userinfo (cross-client access with audience validation) | RFC 7662 + OIDC |
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

Register a client with attestation-based authentication. **Attestation-enabled clients automatically receive privileged clients in their audience for token introspection access**:

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

**Response with Privileged Client Audience:**
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
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "response_types": ["code"],
  "client_name": "HSM Attestation Wallet",
  "scope": "openid profile",
  "audience": ["generated-client-id", "server-owned-client"],
  "attestation_config": {
    "client_id": "hsm-wallet-client",
    "allowed_methods": ["attest_jwt_client_auth"],
    "trust_anchors": ["/tmp/trust-anchors/hsm-ca.pem"],
    "required_level": "high"
  }
}
```

**Note**: The `client_credentials` grant type and privileged client (`server-owned-client`) are automatically added to attestation-enabled clients for token introspection capabilities.

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

### Authorization-Introspection Endpoint

The `/authorization-introspection` endpoint combines token introspection with userinfo data, enabling cross-client token access based on audience validation. This endpoint allows different clients to introspect tokens if they're in the token's client audience, providing a secure way for backend services to access user information from tokens issued to frontend clients.

**Key Features:**
- **Cross-Client Access**: Clients can introspect tokens from other clients if they're in the audience
- **Combined Response**: Returns both token details and userinfo in a single request
- **Audience Validation**: Enforces that requesting clients are authorized to access the token
- **Privileged Access**: Privileged clients can introspect any token

**Authentication:** Requires HTTP Basic authentication with client credentials.

**Request:**
```bash
curl -X POST http://localhost:8080/authorization-introspection \
  -u "backend-client:backend-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "access-token=<access_token>"
```

**Response:**
```json
{
  "token-details": {
    "active": true,
    "client_id": "web-app-client",
    "scope": "openid profile email",
    "token_type": "Bearer",
    "exp": 1763375669,
    "iat": 1763372069,
    "aud": ["api-service", "backend-client"],
    "iss": "http://localhost:8080",
    "sub": "user-001"
  },
  "user-info": {
    "sub": "user-001",
    "name": "John Doe",
    "email": "john.doe@example.com",
    "email_verified": true,
    "profile": "https://example.com/profile/john.doe"
  }
}
```

**Authorization Rules:**
1. **Audience Check**: The requesting client must be in the token's client audience
2. **Privileged Access**: Clients configured as privileged can introspect any token
3. **Same Client**: Clients can always introspect their own tokens

**Use Cases:**
- Backend services accessing user data from frontend-issued tokens
- API gateways validating and enriching requests with user information
- Microservices architectures with shared user contexts

### Introspect a Token

Token introspection requires HTTP Basic authentication with client credentials:

```bash
curl -X POST http://localhost:8080/introspect \
  -u "backend-client:backend-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=<access_or_refresh_token>"
```

**Response for regular tokens:**
```json
{
  "active": true,
  "client_id": "backend-client",
  "scope": "api:read",
  "token_type": "Bearer",
  "exp": 1763375669,
  "iat": 1763372069,
  "aud": ["api-service"],
  "iss": "http://localhost:8080",
  "sub": "backend-client",
  "username": "backend-client"
}
```

**Response for attested tokens (includes attestation metadata):**
```json
{
  "active": true,
  "client_id": "hsm-attestation-wallet-demo",
  "scope": "openid profile",
  "token_type": "Bearer",
  "exp": 1763375669,
  "iat": 1763372069,
  "aud": ["api-service"],
  "iss": "http://localhost:8080",
  "sub": "user-001",
  "username": "john.doe",
  "attestation": {
    "attestation_verified": true,
    "attestation_trust_level": "high",
    "attestation_issued_at": 1763372069,
    "attestation_expires_at": 1763375669,
    "attestation_key_id": "hsm_ae26b334",
    "hsm_backed": true,
    "bio_authenticated": false,
    "device_integrity": "verified"
  }
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

---

**Built with ❤️ using [Fosite](https://github.com/ory/fosite) - The security first OAuth2 & OpenID Connect framework

