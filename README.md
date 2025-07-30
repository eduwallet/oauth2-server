# OAuth2 Server

A feature-rich OAuth2 and OpenID Connect server supporting multiple flows, dynamic client registration, token exchange, audience management, and introspection.

## Key Features

### 📱 Device Code Flow (RFC 8628)
Perfect for devices with limited input capabilities (TVs, IoT devices, CLI tools):
- User initiates flow on device
- Device displays user code and verification URL
- User visits URL on another device to authorize
- Device polls for token completion
- Seamless authentication without complex input

### 🔄 Token Exchange (RFC 8693)
Enable secure service-to-service token delegation:
- Frontend client authenticates user
- Backend service exchanges frontend token for backend-specific token
- Maintains security boundaries between services
- Supports audience-specific tokens
- **Supports `requested_token_type`**: You can request a `refresh_token` or `access_token` as the result of a token exchange.

### 🔧 Dynamic Client Registration (RFC 7591)
Programmatic client registration at runtime:
- REST API for client management
- Specify `audience` during registration
- Web interface for testing and administration
- Support for various client types and configurations
- Real-time client updates without server restart

### ♻️ Refresh Tokens
For long-running applications:
- Configurable token lifespans per token type
- Automatic token renewal
- Secure token rotation
- Support for offline access scenarios

### 🎯 Audience Support
- Specify `audience` during client registration and token requests.
- Tokens include an `aud` claim (array of strings) in both the token and introspection response.
- Audience is validated on token issuance and refresh.
- Refresh tokens can be used by the original client or any client in the audience.

### 🎯 Two-Client Architecture
Clear separation of concerns:
- **Frontend Client**: User-facing authentication
- **Backend Client**: Service-to-service communication
- **Token Exchange**: Bridge between frontend and backend tokens
- Enhanced security through client-specific scopes

### OAuth2 Grant Types
- ✅ **Authorization Code** - Traditional web application flow
- ✅ **Client Credentials** - Service-to-service authentication
- ✅ **Device Code** - CLI and IoT device authentication
- ✅ **Token Exchange** - Cross-service token delegation
- ✅ **Refresh Token** - Long-running process support

### RFC Compliance
- ✅ **RFC 6749** - OAuth 2.0 Authorization Framework
- ✅ **RFC 8628** - Device Authorization Grant
- ✅ **RFC 8693** - Token Exchange
- ✅ **RFC 7591** - Dynamic Client Registration
- ✅ **RFC 8414** - Authorization Server Metadata
- ✅ **OpenID Connect Core 1.0**

### Production Features
- ✅ **Kubernetes native** - Designed for cloud deployment
- ✅ **Security hardening** - Non-root containers, read-only filesystem
- ✅ **Horizontal scaling** - HPA support for high availability
- ✅ **Health checks** - Liveness and readiness probes
- ✅ **Monitoring ready** - Prometheus metrics support
- ✅ **Ingress support** - TLS termination and routing

## Project Structure

- **cmd/server/main.go**: Entry point of the application. Initializes the server and sets up routes and middleware.
- **internal/auth/**: Contains authentication and authorization logic for OAuth2 flows.
- **internal/flows/**: Implements various OAuth2 flows using the fosite framework.
- **internal/handlers/**: Defines HTTP handlers for various endpoints.
  - `auth_handlers.go`: Handlers for authentication-related endpoints.
  - `device_handlers.go`: Handlers for device authorization endpoints.
  - `docs_handlers.go`: Handlers for documentation and client management API.
  - `token_handlers.go`: Handlers for token-related endpoints.
- **internal/middleware/**: HTTP middleware for request processing.
  - Authentication, CORS, logging, and security middleware.
- **internal/models/**: Defines data models used in the application.
  - `client.go`: Represents registered OAuth2 clients.
  - `device.go`: Represents devices for device authorization flow.
  - `token.go`: Token-related data structures.
  - `user.go`: User authentication models.
- **internal/store/**: Manages storage and retrieval of data using fosite interfaces.
  - `client_store.go`: Storage for OAuth2 client data.
  - `token_store.go`: Storage for access tokens, refresh tokens, and authorization codes.
- **internal/utils/**: Utility functions used throughout the application.
  - `generators.go`: Functions for generating random strings and tokens.
  - `uri.go`: URI resolution and validation utilities.
  - `validators.go`: Validation functions for requests and tokens.
- **pkg/config/**: Configuration management for the application.
  - `config.go`: Main configuration structure and loading.
  - `env.go`: Environment variable processing and validation.
- **helm/oauth2-server/**: Kubernetes Helm chart for deployment.
  - `Chart.yaml`: Helm chart metadata.
  - `values.yaml`: Default configuration values.
  - `templates/`: Kubernetes resource templates.
- **static/**: Static web assets for the OAuth2 server UI.
- **docker-compose.yml**: Docker Compose configuration for local development.
- **Dockerfile**: Container image definition.
- **Makefile**: Build and development automation.
- **go.mod**: Defines the module and its dependencies.
- **go.sum**: Contains checksums for the module's dependencies.

## Features

- **OAuth2 Authorization Flows**:
  - Authorization Code Flow with PKCE support
  - Client Credentials Flow
  - Device Authorization Flow
  - Refresh Token Flow
  - Token Exchange (RFC 8693)

- **Security Features**:
  - JWT-based tokens with configurable expiration per token type
  - PKCE (Proof Key for Code Exchange) support
  - Configurable HTTPS requirements
  - Proxy-aware redirect URI resolution
  - Rate limiting and CORS support

- **Management Features**:
  - Dynamic client registration via API (with audience support)
  - Web-based documentation and client management
  - Health check endpoints
  - Prometheus metrics (optional)

- **Token Introspection**:
  - `/introspect` endpoint returns all standard fields, including `aud` as a JSON array.

- **Token Statistics**:
  - `/token/stats` endpoint provides statistics about issued, active, revoked, and expired tokens.

## Setup Instructions

### Local Development

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd oauth2-server
   ```

2. **Install dependencies**:
   ```bash
   go mod tidy
   ```

3. **Run with Docker Compose** (includes Redis and PostgreSQL):
   ```bash
   docker-compose up
   ```

4. **Or run directly**:
   ```bash
   make run
   # or
   go run cmd/server/main.go
   ```

### Kubernetes Deployment

1. **Deploy with Helm**:
   ```bash
   # Create namespace
   kubectl create namespace oauth2-server

   # Install chart
   helm install oauth2-server ./helm/oauth2-server \
     -n oauth2-server \
     --set config.server.baseUrl="https://your-domain.com" \
     --set config.jwt.secret="your-jwt-secret"
   ```

2. **With custom values**:
   ```bash
   helm upgrade --install oauth2-server ./helm/oauth2-server \
     -n oauth2-server \
     -f custom-values.yaml
   ```

## Configuration

The server can be configured using environment variables:

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `PORT` | Server listening port | `8080` |
| `HOST` | Host binding address | `""` |
| `PUBLIC_BASE_URL` | Public base URL for the server | Auto-detected |
| `JWT_SIGNING_KEY` | JWT signing secret | Required |
| `TRUST_PROXY_HEADERS` | Trust proxy headers for URL resolution | `false` |
| `REQUIRE_HTTPS` | Require HTTPS for OAuth flows | `false` |
| `ENABLE_PKCE` | Enable PKCE for authorization code flow | `true` |
| `TOKEN_EXPIRY_SECONDS` | Access token expiry in seconds | `3600` |
| `REFRESH_TOKEN_EXPIRY_SECONDS` | Refresh token expiry in seconds | `86400` |

### Docker Compose Configuration

See `docker-compose.yml` for a complete development setup with Redis and PostgreSQL.

### Helm Configuration

See `helm/oauth2-server/values.yaml` for all available Helm chart configuration options.

## API Endpoints

### OAuth2/OIDC Endpoints

| Endpoint | Method | Description | RFC |
|----------|--------|-------------|-----|
| `/oauth2/auth` | GET | Authorization endpoint | RFC 6749 |
| `/oauth2/token` | POST | Token endpoint (all grant types, including device code and token exchange) | RFC 6749, 8628, 8693 |
| `/oauth2/device` | POST | Device authorization | RFC 8628 |
| `/device` | GET/POST | Device verification UI | RFC 8628 |
| `/oauth2/introspect` | POST | Token introspection (returns `aud` as array) | RFC 7662 |
| `/oauth2/userinfo` | GET | UserInfo endpoint | OIDC Core |
| `/token/stats` | GET | Token statistics endpoint | Custom |

### Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/clients` | GET | List OAuth2 clients |
| `/api/clients` | POST | Create new client (specify `audience`) |
| `/api/clients/{id}` | GET | Get specific client |
| `/api/clients/{id}` | PUT | Update client |
| `/api/clients/{id}` | DELETE | Delete client |
| `/register` | POST | Dynamic client registration (with audience) |

### Discovery & Health

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/oauth-authorization-server` | GET | OAuth2 server metadata |
| `/.well-known/openid_configuration` | GET | OIDC configuration |
| `/jwks` | GET | JSON Web Key Set |
| `/health` | GET | Health check |
| `/ready` | GET | Readiness probe |
| `/` | GET | Interactive documentation |

## Usage Guidelines

### Client Registration

Use the client management API or web interface at `/docs` to register OAuth2 clients:

```bash
curl -X POST http://localhost:8080/api/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "redirect_uris": ["https://myapp.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "audience": ["client_id_of_backend"],
    "scope": "openid profile email"
  }'
```

### Token Exchange for Refresh Token

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=<refresh_token>" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:refresh_token" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:refresh_token" \
  -d "audience=<target_audience>"
```

### Introspect a Token

```bash
curl -X POST http://localhost:8080/oauth2/introspect \
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

### Authorization Code Flow

1. Redirect user to `/oauth2/auth` with required parameters
2. Exchange authorization code at `/oauth2/token`
3. Use access token to access protected resources

### Testing

- Use the included Makefile commands: `make test`, `make lint`
- Access interactive documentation at `http://localhost:8080/docs`
- Use tools like Postman, Insomnia, or curl to test endpoints

## Development

```bash
# Run tests
make test

# Lint code
make lint

# Format code
make fmt

# Build binary
make build

# Build Docker image
make docker-build
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

[Add your license information here]

## Use Cases

### 1. CLI Application Authentication
Perfect for command-line tools that need user authentication:

```bash
# CLI tool initiates device flow
$ my-cli-tool login
# Output: Visit https://oauth.example.com/device and enter code: ABCD-EFGH
# User authorizes on their browser
# CLI tool receives tokens and can make authenticated API calls
$ my-cli-tool api-call --endpoint /protected-resource
```

**Flow Details:**
1. CLI tool requests device authorization
2. Server returns device code and user verification URL
3. User visits URL and enters/confirms code
4. CLI tool polls token endpoint until authorization completes
5. CLI tool receives access and refresh tokens

### 2. IoT Device Authentication
For smart devices with limited input capabilities:

```bash
# Smart TV or IoT device scenario
Device Display: "Visit oauth.example.com/device"
Device Display: "Enter code: WXYZ-1234"
# User authorizes on phone/computer
# Device receives tokens for API access
```

### 3. Service-to-Service Communication
Backend services exchange tokens for secure API access:

```bash
# Service A authenticates user (frontend flow)
# Service A needs to call Service B on behalf of user
# Service A exchanges user token for Service B specific token
curl -X POST /oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=<frontend_user_token>" \
  -d "audience=service-b"
```

### 4. Long-Running Processes
Applications that need extended access:

```bash
# Batch job or background service
# Gets initial tokens with refresh token
# Automatically refreshes before expiration
# Runs for days/weeks without user intervention
```

## Technical Implementation

### Architecture Highlights

- **🌐 OpenID Connect Compliant**: Full OIDC support with discovery endpoints
- **🔒 JWT Tokens**: RS256 signed tokens with proper validation and claims
- **🔄 Reverse Proxy Ready**: Production deployment with nginx/ingress support
- **⚡ High Performance**: Built with Go for concurrent request handling
- **🛡️ Security First**: PKCE, HTTPS enforcement, secure token storage

### Supported Grant Types

| Grant Type | RFC | Use Case | Client Type |
|------------|-----|----------|-------------|
| Authorization Code + PKCE | RFC 6749 + 7636 | Web/Mobile Apps | Public/Confidential |
| Client Credentials | RFC 6749 | Service-to-Service | Confidential |
| Device Authorization | RFC 8628 | CLI/IoT Devices | Public |
| Token Exchange | RFC 8693 | Service Delegation | Confidential |
| Refresh Token | RFC 6749 | Long-running Access | Both |

### Discovery Endpoints

The server provides standard OAuth2/OIDC discovery:

- `GET /.well-known/oauth-authorization-server` - OAuth2 metadata
- `GET /.well-known/openid_configuration` - OIDC configuration
- `GET /jwks` - JSON Web Key Set for token validation

## Standards Compliance & References

### Implemented RFCs

- 📚 [RFC 6749: OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- 📚 [RFC 8628: OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)
- 📚 [RFC 8693: OAuth 2.0 Token Exchange](https://tools.ietf.org/html/rfc8693)
- 📚 [RFC 7591: OAuth 2.0 Dynamic Client Registration](https://tools.ietf.org/html/rfc7591)
- 📚 [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- 📚 [RFC 7636: Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636)
- 📚 [RFC 7662: OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)

### OpenID Connect Specifications

- 📚 [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- 📚 [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

### Security Considerations

- 🔒 [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- 🔒 [OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)

---

**Built with ❤️ using [Fosite](https://github.com/ory/fosite) - The security first OAuth2 & OpenID Connect framework for Go.**