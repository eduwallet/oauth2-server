# Deployment Guide

## Kubernetes Deployment

### Quick Start

```bash
kubectl create namespace oauth2-server
helm install oauth2-server ./helm/oauth2-server -n oauth2-server --set config.server.baseUrl="https://your-domain.com" --set config.jwt.secret="your-jwt-secret"
```

## Helm Chart Installation

This Helm chart deploys the OAuth2 Server application on a Kubernetes cluster.

### Prerequisites

- Kubernetes 1.19+
- Helm 3.8+

### Installation

#### Add the chart repository (if published)
```bash
helm repo add oauth2-server https://your-charts-repo.com
helm repo update
```

#### Install from local directory
```bash
# Install with default values
helm install oauth2-server ./helm/oauth2-server

# Install with custom values
helm install oauth2-server ./helm/oauth2-server -f values-dev.yaml

# Install in specific namespace
helm install oauth2-server ./helm/oauth2-server -n oauth2 --create-namespace
```

#### Upgrade
```bash
helm upgrade oauth2-server ./helm/oauth2-server -f values-prod.yaml
```

#### Uninstall
```bash
helm uninstall oauth2-server
```

## Configuration

### Key Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `harrykodden/oauth2-server` |
| `image.tag` | Image tag | `latest` |
| `service.port` | Service port | `8080` |
| `ingress.enabled` | Enable ingress | `false` |
| `config.server.baseUrl` | Public base URL (PUBLIC_BASE_URL) | `""` |
| `config.server.port` | Server port (PORT) | `"8080"` |
| `config.server.host` | Host binding (HOST) | `""` |
| `config.jwt.secret` | JWT signing key (JWT_SIGNING_KEY) | `""` |
| `config.proxy.trustHeaders` | Trust proxy headers (TRUST_PROXY_HEADERS) | `true` |
| `config.proxy.forceHTTPS` | Force HTTPS (FORCE_HTTPS) | `false` |
| `config.security.requireHTTPS` | Require HTTPS (REQUIRE_HTTPS) | `false` |
| `config.security.enablePKCE` | Enable PKCE (ENABLE_PKCE) | `true` |
| `config.security.tokenExpirySeconds` | Token expiry (TOKEN_EXPIRY_SECONDS) | `3600` |
| `config.security.refreshTokenExpirySeconds` | Refresh token expiry (REFRESH_TOKEN_EXPIRY_SECONDS) | `86400` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `autoscaling.enabled` | Enable HPA | `false` |

### Security Configuration

For production deployments, ensure:

1. **Set a strong JWT secret**: `--set config.jwt.secret="$(openssl rand -base64 32)"`
2. **Enable TLS on ingress**: Set up proper TLS certificates
3. **Configure HTTPS requirements**: `--set config.security.requireHTTPS=true`
4. **Enable PKCE**: `--set config.security.enablePKCE=true` (enabled by default)
5. **Configure trusted proxies**: `--set config.proxy.trustedProxies="10.0.0.0/8,172.16.0.0/12"`
6. **Use appropriate resource limits**: Configure CPU and memory limits
7. **Enable network policies**: Configure network isolation if needed
8. **Use non-root security context**: Enabled by default in this chart

## Environment Variable Mapping

This chart maps Helm values to the following environment variables that the OAuth2 server expects:

| Helm Value | Environment Variable | Description |
|------------|---------------------|-------------|
| `config.server.port` | `PORT` | Server listening port |
| `config.server.host` | `HOST` | Host binding address |
| `config.server.baseUrl` | `PUBLIC_BASE_URL` | Public base URL for the server |
| `config.proxy.trustHeaders` | `TRUST_PROXY_HEADERS` | Trust proxy headers |
| `config.proxy.forceHTTPS` | `FORCE_HTTPS` | Force HTTPS redirects |
| `config.proxy.trustedProxies` | `TRUSTED_PROXIES` | Comma-separated trusted proxy IPs |
| `config.jwt.secret` | `JWT_SIGNING_KEY` | JWT signing secret |
| `config.security.tokenExpirySeconds` | `TOKEN_EXPIRY_SECONDS` | Access token expiry in seconds |
| `config.security.refreshTokenExpirySeconds` | `REFRESH_TOKEN_EXPIRY_SECONDS` | Refresh token expiry in seconds |
| `config.security.requireHTTPS` | `REQUIRE_HTTPS` | Require HTTPS for OAuth flows |
| `config.security.enablePKCE` | `ENABLE_PKCE` | Enable PKCE for OAuth flows |

## Examples

### Development Deployment
```bash
helm install oauth2-server-dev ./helm/oauth2-server \
  --set ingress.enabled=true \
  --set config.jwt.secret="dev-secret" \
  --set config.server.baseUrl="http://localhost:8080" \
  --set config.security.requireHTTPS=false \
  --set image.tag="latest"
```

### Production Deployment
```bash
helm install oauth2-server-prod ./helm/oauth2-server \
  -f values-prod.yaml \
  --set config.jwt.secret="$(openssl rand -base64 32)" \
  --set config.server.baseUrl="https://oauth.yourdomain.com" \
  --set config.security.requireHTTPS=true \
  --set config.proxy.trustHeaders=true
```

### Sample deployment with public hostname
```bash
helm upgrade --install oauth2-server ./helm/oauth2-server \
  -n oauth2-server --create-namespace \
  --set config.server.baseUrl="https://oauth2-server.homelab.kodden.nl" \
  --set config.security.requireHTTPS=true \
  --set config.proxy.trustHeaders=true
```

### Quick local testing
```bash
helm upgrade --install oauth2-server ./helm/oauth2-server \
  -n demo --create-namespace \
  --set config.server.baseUrl="http://localhost:8080" \
  --set config.jwt.secret="local-dev-secret" \
  --set config.security.requireHTTPS=false
```