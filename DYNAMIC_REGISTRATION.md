# Dynamic Client Registration (RFC 7591)

This document describes the OAuth2 Dynamic Client Registration implementation in the OAuth2 server.

## Overview

Dynamic Client Registration allows OAuth2 clients to register themselves with the authorization server without requiring manual configuration. This is particularly useful for:

- Multi-tenant applications
- Third-party integrations
- Development and testing environments
- Automated deployment scenarios

## Configuration

Dynamic registration is configured in the `config.yaml` file under the `security.dynamic_registration` section:

```yaml
security:
  dynamic_registration:
    enabled: true                           # Enable/disable dynamic registration
    require_initial_access_token: false     # Require initial access token
    initial_access_token: "demo-token"      # Token for protected registration
    default_token_lifetime: 3600            # Default token lifetime
    allowed_grant_types:                     # Permitted grant types
      - "authorization_code"
      - "client_credentials"
      - "refresh_token"
      - "urn:ietf:params:oauth:grant-type:device_code"
    allowed_response_types:                  # Permitted response types
      - "code"
      - "token"
    allowed_scopes:                          # Permitted scopes
      - "openid"
      - "profile"
      - "email"
      - "offline_access"
    require_redirect_uri: true               # Require redirect URIs
    client_secret_expiry_seconds: 0          # Client secret expiry (0 = never)
```

## Registration Endpoint

**Endpoint:** `POST /oauth2/register`

### Request Headers
- `Content-Type: application/json`
- `Authorization: Bearer <initial_access_token>` (if required)

### Request Body (RFC 7591)
```json
{
  "redirect_uris": ["https://client.example.org/callback"],
  "client_name": "My Application",
  "client_uri": "https://client.example.org",
  "logo_uri": "https://client.example.org/logo.png",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic",
  "contacts": ["admin@client.example.org"],
  "tos_uri": "https://client.example.org/tos",
  "policy_uri": "https://client.example.org/policy"
}
```

### Response (201 Created)
```json
{
  "client_id": "dynamically-generated-id",
  "client_secret": "dynamically-generated-secret",
  "client_id_issued_at": 1628784000,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://client.example.org/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "client_name": "My Application",
  "client_uri": "https://client.example.org",
  "logo_uri": "https://client.example.org/logo.png",
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic",
  "contacts": ["admin@client.example.org"],
  "tos_uri": "https://client.example.org/tos",
  "policy_uri": "https://client.example.org/policy",
  "registration_access_token": "reg-access-token",
  "registration_client_uri": "http://localhost:8080/oauth2/register/client-id"
}
```

## Discovery Integration

When dynamic registration is enabled, the discovery endpoints automatically include:

```json
{
  "registration_endpoint": "http://localhost:8080/oauth2/register"
}
```

This appears in both:
- `/.well-known/oauth-authorization-server` (RFC 8414)
- `/.well-known/openid-configuration`

## Security Considerations

### Initial Access Tokens
For production environments, enable `require_initial_access_token`:

```yaml
dynamic_registration:
  require_initial_access_token: true
  initial_access_token: "secure-random-token"
```

### Validation Rules
The server validates:
- Grant types against `allowed_grant_types`
- Response types against `allowed_response_types`
- Scopes against `allowed_scopes`
- Redirect URIs (intelligently based on grant types)

#### Intelligent Redirect URI Validation
The server now intelligently determines when redirect URIs are required:

**Redirect URIs Required For:**
- `authorization_code` grant type
- `implicit` grant type  
- `code` response type
- `token` response type
- `id_token` response type

**Redirect URIs NOT Required For:**
- `client_credentials` grant type
- `urn:ietf:params:oauth:grant-type:device_code` grant type
- `urn:ietf:params:oauth:grant-type:token-exchange` grant type
- Clients with empty `response_types` array

This allows backend services and device flow clients to register without redirect URIs, while still enforcing the requirement for web applications that need them.

### Client Authentication Methods
Supported methods:
- `client_secret_basic` - HTTP Basic authentication
- `client_secret_post` - Form parameter authentication
- `none` - Public clients (no authentication)

## Testing

### Using Make Commands
```bash
# Test dynamic registration (starts server automatically)
make test-dynamic-registration

# Check if registration endpoint is available (server must be running)
make check-dynamic-registration
```

### Manual Testing
```bash
# Basic registration request
curl -X POST http://localhost:8080/oauth2/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://client.example.org/callback"],
    "client_name": "Test Client",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile"
  }'

# With initial access token (if required)
curl -X POST http://localhost:8080/oauth2/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-initial-access-token" \
  -d '{
    "redirect_uris": ["https://client.example.org/callback"],
    "client_name": "Test Client",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile"
  }'
```

## Error Handling

### Common Error Responses

#### 400 Bad Request - Invalid Client Metadata
```json
{
  "error": "invalid_client_metadata",
  "error_description": "Grant type authorization_code_invalid is not allowed"
}
```

#### 401 Unauthorized - Missing/Invalid Initial Access Token
```json
{
  "error": "invalid_client_metadata", 
  "error_description": "Initial access token required"
}
```

#### 403 Forbidden - Registration Disabled
```json
{
  "error": "invalid_request",
  "error_description": "Dynamic client registration is not enabled"
}
```

## Implementation Details

### Client Storage
- Static clients: Loaded from `config.yaml`
- Dynamic clients: Stored in memory (configurable storage backend)
- Client lookup: Checks both static and dynamic clients

### Client ID Generation
- Uses cryptographically secure random string generation
- 32-character base64-encoded client IDs
- 64-character base64-encoded client secrets

### Registration Access Tokens
- Generated for each registered client
- Used for future client configuration updates
- Stored with client ID mapping

## Production Recommendations

1. **Enable Initial Access Tokens**
   ```yaml
   require_initial_access_token: true
   initial_access_token: "use-a-secure-random-token"
   ```

2. **Set Client Secret Expiry**
   ```yaml
   client_secret_expiry_seconds: 2592000  # 30 days
   ```

3. **Restrict Grant Types**
   ```yaml
   allowed_grant_types:
     - "authorization_code"
     # Remove client_credentials if not needed
   ```

4. **Limit Scopes**
   ```yaml
   allowed_scopes:
     - "profile"
     - "email"
     # Remove openid if not using OpenID Connect
   ```

5. **Implement Persistent Storage**
   - Replace in-memory storage with database
   - Add client management UI
   - Implement client secret rotation

6. **Add Rate Limiting**
   - Limit registration requests per IP
   - Implement abuse detection
   - Add monitoring and alerting

## Standards Compliance

- **RFC 7591**: OAuth 2.0 Dynamic Client Registration Protocol
- **RFC 7592**: OAuth 2.0 Dynamic Client Registration Management Protocol (future enhancement)
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata (discovery integration)

## Future Enhancements

1. **Client Management** (RFC 7592)
   - `GET /oauth2/register/{client_id}` - Read client configuration
   - `PUT /oauth2/register/{client_id}` - Update client configuration
   - `DELETE /oauth2/register/{client_id}` - Delete client

2. **Advanced Features**
   - Software statements (RFC 7591 Section 2.3)
   - Client authentication with JWT (RFC 7523)
   - Persistent storage backends
   - Client approval workflows
