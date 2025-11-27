# API Documentation

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/trust-anchor/` | GET | List all available trust anchors |
| `/trust-anchor/{name}` | POST | Upload a trust anchor certificate |
| `/trust-anchor/{name}` | DELETE | Delete a trust anchor certificate |

### Upload Trust Anchor

Upload an X.509 certificate in PEM format as a trust anchor:

```bash
curl -X POST http://localhost:8080/trust-anchor/hsm-ca \
  -H "X-API-Key: your-secure-api-key-here" \
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
curl http://localhost:8080/trust-anchor/ \
  -H "X-API-Key: your-secure-api-key-here" \
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
curl -X DELETE http://localhost:8080/trust-anchor/hsm-ca \
  -H "X-API-Key: your-secure-api-key-here" \
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
  -H "X-API-Key: your-secure-api-key-here" \
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
  -H "X-API-Key: your-secure-api-key-here" \
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
     -H "X-API-Key: your-secure-api-key-here" \
     -F "certificate=@hsm-ca.pem"
   ```

2. **Register Client with Attestation Configuration**:
   ```bash
   curl -X POST http://localhost:8080/register \
     -H "X-API-Key: your-secure-api-key-here" \
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
  "token_details": {
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
  "user_info": {
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