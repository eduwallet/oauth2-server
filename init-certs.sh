#!/bin/sh
set -e

# Parse command line arguments
OAUTH_URL="${OAUTH_URL:-http://oauth2-server:8080}"
for arg in "$@"; do
    case $arg in
        url=*)
            OAUTH_URL="${arg#url=}"
            ;;
        *)
            echo "Unknown parameter: $arg"
            echo "Usage: $0 [url=http://oauth-server-url]"
            exit 1
            ;;
    esac
done

echo "Using OAuth server URL: $OAUTH_URL"

CERT_DIR="/tmp/certs"
CERT_FILE="$CERT_DIR/hsm_ca.pem"

mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_FILE" ]; then
    echo "Generating HSM CA certificate..."
        # Generate CA key and certificate (EC-P256)
        openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/hsm_ca.key"
        openssl req -x509 -new -key "$CERT_DIR/hsm_ca.key" -sha256 -days 365 -out "$CERT_FILE" -subj "/CN=MockHSMCA/O=Demo/C=US"
    echo "Certificate generated at $CERT_FILE"
else
    echo "Certificate already exists at $CERT_FILE"
fi

# Also create a test trust anchor certificate
TEST_CERT_FILE="$CERT_DIR/test-trust-anchor.pem"
if [ ! -f "$TEST_CERT_FILE" ]; then
    echo "Generating test trust anchor certificate..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/test-trust-anchor.key"
    openssl req -x509 -new -key "$CERT_DIR/test-trust-anchor.key" -sha256 -days 365 -out "$TEST_CERT_FILE" -subj "/CN=TestTrustAnchor/O=Demo/C=US"
    echo "Test certificate generated at $TEST_CERT_FILE"
else
    echo "Test certificate already exists at $TEST_CERT_FILE"
fi


# Upload certificate to oauth2-server
echo "Uploading trust anchor certificate to oauth2-server..."
curl -X POST "$OAUTH_URL/trust-anchor/hsm_ca" \
    -H "X-API-Key: ${API_KEY}" \
  -F "certificate=@$CERT_FILE" \
  --max-time 30 \
  --retry 5 \
  --retry-delay 2

echo "Trust anchor certificate uploaded successfully"

# curl -X POST http://oauth2-server:8080/register \
#   -H "X-API-Key: ${API_KEY}" \
#   -H "Content-Type: application/json" \
#   -d '{
#     "client_id": "hsm-attestation-wallet-demo",
#     "redirect_uris": [
#       "http://localhost:8001/callback",
#       "http://localhost:8001/callback.html", 
#       "http://localhost:8001",
#       "http://127.0.0.1:8001/callback",
#       "http://127.0.0.1:8001/callback.html",
#       "http://127.0.0.1:8001",
#       "http://localhost:8001/oauth2/callback",
#       "https://demo-app.oauth2-server.orb.local/callback.html"
#     ],
#     "grant_types": [
#       "authorization_code",
#       "refresh_token",
#       "client_credentials"
#     ],
#     "response_types": ["code"],
#     "scope": "openid profile email wallet:read wallet:write api:read",
#     "audience": ["api-service"],
#     "token_endpoint_auth_method": "attest_jwt_client_auth",
#     "client_name": "HSM Attestation Wallet Demo",
#     "client_uri": "http://localhost:8001",
#     "attestation_config": {
#       "client_id": "hsm-attestation-wallet-demo",
#       "allowed_methods": ["attest_jwt_client_auth"],
#       "trust_anchors": ["hsm-ca"]
#     }
#   }'

# echo "Client 'hsm-attestation-wallet-demo' registered successfully"