# Configuration Guide

## Environment Variables

The server supports configuration via environment variables for security-sensitive settings:

### Upstream Provider Configuration (Proxy Mode)

When these environment variables are set, the server runs in proxy mode and ignores user details from `config.yaml`:

```bash
# Required for proxy mode
UPSTREAM_PROVIDER_URL=https://accounts.google.com
UPSTREAM_CLIENT_ID=your-client-id
UPSTREAM_CLIENT_SECRET=your-client-secret
UPSTREAM_CALLBACK_URL=${OAUTH2_SERVER_URL:-http://localhost:8080}/callback
```

**Security Note**: Upstream provider configuration has been moved from `config.yaml` to environment variables only to prevent storing sensitive credentials in configuration files.

### Other Environment Variables

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

## Configuration Files

See `values.yaml` and `docker-compose.yml` for additional configuration options.

**Trust Anchor Storage**: Trust anchor certificates are stored in `/tmp/trust-anchors/` directory with `.pem` file extensions. Ensure this directory is writable by the server process and consider mounting it as a persistent volume in production deployments.

## Proxy Mode

When upstream provider environment variables are configured, the server operates in proxy mode:

1. **Client Authentication**: Accepts requests from downstream clients
2. **Token Issuance**: Issues proxy-controlled access tokens instead of passing through upstream tokens
3. **UserInfo Proxying**: Maps proxy tokens back to upstream tokens for userinfo requests
4. **Security**: Upstream tokens are never exposed to downstream clients

**Token Flow in Proxy Mode:**
- Downstream client requests token → Server validates with upstream → Server issues proxy token
- Downstream client calls userinfo with proxy token → Server maps to upstream token → Server proxies userinfo call

This provides an additional security layer where upstream access tokens are never exposed to client applications.