# OAuth 2.0 Attestation-Based Client Authentication

This server implements OAuth 2.0 Attestation-Based Client Authentication as specified in [draft-ietf-oauth-attestation-based-client-auth-07](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/). This provides enterprise-grade security for mobile applications, IoT devices, and other clients that can provide cryptographic proof of their integrity and authenticity.

## Overview

Attestation-based authentication allows clients to authenticate using hardware-backed cryptographic attestations instead of traditional client secrets. This is particularly valuable for:

- **Mobile Applications**: Apps running on devices with hardware security modules (HSM) or secure enclaves
- **IoT Devices**: Hardware devices with embedded secure elements or TPMs
- **High-Security Environments**: Applications requiring cryptographic proof of client integrity

## Supported Attestation Methods

### 1. JWT-Based Attestation (`attest_jwt_client_auth`)

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

### 2. TLS Certificate-Based Attestation (`attest_tls_client_auth`)

Clients authenticate using X.509 client certificates with attestation extensions:

```bash
# Example client certificate request with attestation
curl -X POST https://oauth2-server.example.com/oauth/token \
  --cert client-cert.pem \
  --key client-key.pem \
  -d "grant_type=client_credentials&client_id=attested-client"
```

## Privileged Client Audience Inclusion

Attestation-enabled clients automatically receive privileged clients in their audience during dynamic registration, enabling token introspection by privileged clients. This feature ensures that privileged clients (configured as `server-owned-client` by default) can introspect tokens issued to attestation-enabled clients.

### How It Works

1. **Client Registration**: When registering a client with `attestation_config`, the server automatically:
   - Adds `client_credentials` grant type if not present
   - Includes the privileged client ID in the client's audience array
   - Logs the privileged client inclusion for audit purposes

2. **Token Introspection**: Privileged clients can introspect tokens from attestation-enabled clients using the `/introspect` endpoint

3. **Configuration**: The privileged client ID is configurable via the `PRIVILEGED_CLIENT_ID` environment variable or `config.security.privilegedClientId` in configuration files

### Example Registration

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

### Privileged Client Token Introspection

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

## Configuration

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

## Proxy Mode Attestation Verification

When running in proxy mode, attestation verification occurs **before** proxying requests to upstream providers:

1. **Client Authentication**: Downstream client sends token request with attestation
2. **Attestation Verification**: Server verifies JWT assertion and certificate chain
3. **Proxy Only After Success**: Only successful attestation allows upstream communication
4. **Clean Proxying**: Attestation parameters are removed before upstream requests

**Security Flow:**
- **Downstream (HSM Demo)**: `client_id` + JWT client assertion attestation
- **Upstream (Google OAuth2)**: `client_id` + `client_secret` (standard OAuth2)

## Client Configuration

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

## Trust Levels

The system supports three trust levels based on attestation strength:

- **`high`**: Hardware-backed keys, secure enclaves, verified boot chains
- **`medium`**: Software-based attestation with device integrity checks
- **`low`**: Basic attestation without hardware backing

## Discovery Support

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

## Usage Examples

### JWT Attestation

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

### TLS Certificate Attestation

```bash
# Use client certificate for attestation
curl -X POST https://oauth2-server.example.com/oauth/token \
  --cert client-attestation.crt \
  --key client-attestation.key \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=iot-device-001"
```

## HSM Attestation Demo

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

## Security Considerations

1. **Certificate Validation**: All attestation certificates are validated against configured trust anchors
2. **Revocation Checking**: Certificate revocation status is verified when possible
3. **Timestamp Validation**: Attestation timestamps are checked for freshness
4. **Hardware Requirements**: High trust levels require hardware-backed key storage
5. **Audit Logging**: All attestation attempts are logged for security monitoring
6. **Proxy Mode Security**: Attestation verification occurs before upstream communication

## Debugging and Monitoring

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

## Monitoring and Metrics

Attestation events are tracked in Prometheus metrics:

```promql
# Attestation verification attempts
oauth2_attestation_verifications_total{client_id="hsm-demo", method="jwt", result="success"}

# Trust level distribution
oauth2_attestation_trust_level{level="high", client_id="hsm-demo"}

# Verification latency
oauth2_attestation_verification_duration_seconds{method="jwt"}
```