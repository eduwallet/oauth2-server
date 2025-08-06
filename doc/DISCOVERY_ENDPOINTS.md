# OAuth2 Discovery Endpoints

This document describes the OAuth2 and OpenID Connect discovery endpoints that have been added to the OAuth2 server.

## Available Discovery Endpoints

### 1. OAuth2 Authorization Server Discovery (RFC 8414)
**Endpoint:** `/.well-known/oauth-authorization-server`

Returns OAuth2 authorization server metadata including:
- `issuer`: Server base URL
- `authorization_endpoint`: Authorization endpoint URL
- `token_endpoint`: Token endpoint URL
- `introspection_endpoint`: Token introspection endpoint URL
- `device_authorization_endpoint`: Device authorization endpoint URL
- `jwks_uri`: JSON Web Key Set endpoint URL
- `response_types_supported`: Supported OAuth2 response types
- `grant_types_supported`: Supported OAuth2 grant types
- `token_endpoint_auth_methods_supported`: Supported client authentication methods
- `scopes_supported`: Available OAuth2 scopes
- `code_challenge_methods_supported`: PKCE code challenge methods

### 2. OpenID Connect Discovery
**Endpoint:** `/.well-known/openid-configuration`

Returns OpenID Connect configuration metadata including:
- All OAuth2 discovery metadata
- `userinfo_endpoint`: UserInfo endpoint URL
- `subject_types_supported`: Subject identifier types
- `id_token_signing_alg_values_supported`: Signing algorithms for ID tokens
- `claims_supported`: Available OpenID Connect claims

### 3. JSON Web Key Set (RFC 7517)
**Endpoint:** `/.well-known/jwks.json`

Returns the JSON Web Key Set containing public keys used for:
- JWT signature verification
- Token validation
- OpenID Connect ID token verification

**Note:** The current implementation includes demo keys. In production, replace with actual RSA/ECDSA public keys.

## Grant Types Supported

The server supports the following OAuth2 grant types:
- `authorization_code` - Standard authorization code flow
- `client_credentials` - Client credentials flow  
- `refresh_token` - Refresh token flow
- `urn:ietf:params:oauth:grant-type:device_code` - Device authorization grant (RFC 8628)
- `urn:ietf:params:oauth:grant-type:token-exchange` - Token exchange (RFC 8693)

## Testing Discovery Endpoints

### Using Make Commands
```bash
# Test all discovery endpoints (starts server automatically)
make test-discovery

# Check endpoints if server is already running
make check-discovery
```

### Manual Testing
```bash
# Start the server
make run

# In another terminal, test endpoints:
curl http://localhost:8080/.well-known/oauth-authorization-server
curl http://localhost:8080/.well-known/openid-configuration  
curl http://localhost:8080/.well-known/jwks.json
```

### Example Response
**OAuth2 Discovery Response:**
```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/oauth2/auth",
  "token_endpoint": "http://localhost:8080/oauth2/token",
  "introspection_endpoint": "http://localhost:8080/oauth2/introspect",
  "device_authorization_endpoint": "http://localhost:8080/device/code",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "response_types_supported": ["code", "token"],
  "grant_types_supported": [
    "authorization_code",
    "client_credentials", 
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

## Implementation Details

### Security Headers
All discovery endpoints include appropriate security headers:
- `Cache-Control: public, max-age=3600` - Cacheable for 1 hour
- `Content-Type: application/json`
- `Access-Control-Allow-Origin: *` (JWKS only) - For CORS support

### Configuration
Discovery endpoints automatically use configuration from `config.yaml`:
- `server.base_url` - Used as issuer if set
- Falls back to `http://host:port` format using `server.host` and `server.port`

### Standards Compliance
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata
- **RFC 7517**: JSON Web Key (JWK) 
- **OpenID Connect Discovery 1.0**: OpenID Connect configuration
- **RFC 8628**: OAuth 2.0 Device Authorization Grant
- **RFC 8693**: OAuth 2.0 Token Exchange

## Production Considerations

1. **JWKS Security**: Replace demo keys with actual cryptographic keys
2. **HTTPS**: Enable HTTPS for production deployments
3. **Caching**: Discovery endpoints are cached for 1 hour
4. **Base URL**: Set `server.base_url` in config for proper issuer identification
5. **CORS**: JWKS endpoint includes CORS headers for browser access
