# OAuth2 Demo Server

A comprehensive OAuth2 authorization server built with Go, using a local fork of Fosite that includes RFC 8693 Token Exchange support.

## Features

- 🔐 **OAuth2 Authorization Server** with full spec compliance
- 🔄 **RFC 8693 Token Exchange** support
- 📱 **RFC 8628 Device Authorization Grant** (Device Flow)
- 🌐 **HTML Authentication Interface** with responsive design
- ⚙️ **YAML Configuration** for easy setup
- 🔧 **Multiple Grant Types**:
  - Authorization Code Flow
  - Client Credentials Flow
  - Refresh Token Flow
  - Device Authorization Flow
  - Token Exchange Flow

## Project Structure

```
oauth2-demo/
├── cmd/server/main.go          # Main application entry point
├── internal/
│   ├── config/config.go        # Configuration management
│   └── storage/storage.go      # Custom storage implementation
├── templates/                  # HTML templates
│   ├── login.html             # Login form
│   ├── device.html            # Device authorization display
│   └── device_verify.html     # Device verification form
├── fosite/                    # Local Fosite fork with RFC 8693 support
├── config.yaml               # Application configuration
├── test-endpoints.sh         # Test script for endpoints
└── README.md                 # This file
```

## Configuration

The server is configured via `config.yaml`. Key sections include:

### Server Configuration
```yaml
server:
  base_url: "http://localhost:8080"
  port: 8080
  host: "localhost"
```

### Security Settings
```yaml
security:
  jwt_signing_key: "your-secret-key-here"
  token_expiry_seconds: 3600
  refresh_token_expiry_seconds: 86400
  enable_pkce: true
```

### OAuth2 Clients
Configure multiple clients with different grant types:
```yaml
clients:
- id: "frontend-app"
  secret: "frontend-secret"
  grant_types: ["authorization_code", "refresh_token"]
  # ... more configuration
```

### Test Users
Pre-configured users for development:
```yaml
users:
- username: "john.doe"
  password: "password123"
  # ... more user data
```

## Running the Server

1. **Build and run**:
   ```bash
   go run cmd/server/main.go
   ```

2. **Access the server**:
   - Main page: http://localhost:8080
   - Login: http://localhost:8080/login
   - Device verification: http://localhost:8080/device/verify

## OAuth2 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/auth` | GET | Authorization endpoint |
| `/oauth2/token` | POST | Token endpoint |
| `/oauth2/introspect` | POST | Token introspection |
| `/device/code` | POST | Device authorization |
| `/device/verify` | GET/POST | Device verification |
| `/device/poll` | POST | Device polling |
| `/login` | GET/POST | User authentication |

## Testing

Use the provided test script:
```bash
./test-endpoints.sh
```

### Manual Testing Examples

#### 1. Authorization Code Flow
```bash
# Visit in browser:
http://localhost:8080/oauth2/auth?response_type=code&client_id=frontend-app&redirect_uri=/callback&scope=openid+profile&state=random-state
```

#### 2. Client Credentials Flow
```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "backend-client:backend-client-secret" \
  -d "grant_type=client_credentials&scope=api:read api:write"
```

#### 3. Device Authorization Flow
```bash
# Step 1: Get device code
curl -X POST http://localhost:8080/device/code \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=frontend-client&scope=openid profile"

# Step 2: Visit verification URL with user code
# Step 3: Poll for tokens
curl -X POST http://localhost:8080/device/poll \
  -H "Content-Type: application/json" \
  -d '{"device_code":"DEVICE_CODE_FROM_STEP_1"}'
```

#### 4. Token Exchange (RFC 8693)
```bash
# Exchange an access token for another token
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "backend-client:backend-client-secret" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=ACCESS_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
```

## Development

### Using Local Fosite Fork

This project uses a local fork of Fosite located in the `./fosite` directory. The fork includes:
- RFC 8693 Token Exchange implementation
- Enhanced device flow support
- Custom storage interfaces

The go.mod file includes:
```go
replace github.com/ory/fosite => ./fosite
```

### Adding New Features

1. **Custom Grant Types**: Extend the Fosite compose factories
2. **Storage Backends**: Implement the storage interfaces
3. **Authentication**: Modify the user authentication logic
4. **Templates**: Update HTML templates in the `templates/` directory

## Security Considerations

⚠️ **This is a demo server. For production use:**

- Use proper password hashing (bcrypt, scrypt, etc.)
- Implement secure session management
- Use HTTPS in production
- Validate all inputs
- Implement rate limiting
- Use proper secret management
- Enable proper logging and monitoring

## Dependencies

- **Fosite**: OAuth2 framework (local fork)
- **Logrus**: Structured logging
- **YAML**: Configuration parsing
- **Go standard library**: HTTP server, templates, etc.

## License

This project is for demonstration purposes. Check the Fosite license for the underlying OAuth2 implementation.
