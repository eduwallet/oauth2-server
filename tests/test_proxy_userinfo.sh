#!/bin/bash

# Test script for proxy mode userinfo endpoint
# Tests that proxy userinfo correctly forwards requests to upstream provider
# using the mapped upstream access token from token exchange

set -e

# Configuration
SERVER_URL="http://localhost:8080"
MOCK_PROVIDER_PORT=9999
MOCK_PROVIDER_URL="http://localhost:$MOCK_PROVIDER_PORT"
TEST_USERNAME="john.doe"
TEST_PASSWORD="password123"
TEST_SCOPE="openid profile email"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 Proxy UserInfo Test"
echo "======================"
echo "Testing proxy mode UserInfo endpoint with token exchange"
echo "Using mock upstream provider at: $MOCK_PROVIDER_URL"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function for colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "success" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "error" ]; then
        echo -e "${RED}❌ $message${NC}"
    elif [ "$status" = "info" ]; then
        echo -e "${YELLOW}ℹ️  $message${NC}"
    else
        echo "$message"
    fi
}

# Start mock upstream OAuth2 provider
start_mock_provider() {
    print_status "info" "Starting mock upstream OAuth2 provider on port $MOCK_PROVIDER_PORT..."

    # Create a simple mock server using Python
    cat > mock_provider.py << 'EOF'
#!/usr/bin/env python3
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class MockOAuthProvider(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)

        if parsed_path.path == "/.well-known/openid-configuration":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            config = {
                "issuer": "http://localhost:9999",
                "authorization_endpoint": "http://localhost:9999/auth",
                "token_endpoint": "http://localhost:9999/token",
                "userinfo_endpoint": "http://localhost:9999/userinfo",
                "introspection_endpoint": "http://localhost:9999/introspect",
                "jwks_uri": "http://localhost:9999/jwks",
                "scopes_supported": ["openid", "profile", "email"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"]
            }
            self.wfile.write(json.dumps(config).encode())
            return

        elif parsed_path.path == "/auth":
            # Mock authorization endpoint - redirect back with code
            redirect_uri = query_params.get('redirect_uri', [''])[0]
            state = query_params.get('state', [''])[0]
            code = f"mock_auth_code_{int(time.time())}"

            if redirect_uri:
                location = f"{redirect_uri}?code={code}&state={state}&scope=openid+profile+email+offline_access"
                self.send_response(302)
                self.send_header('Location', location)
                self.end_headers()
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing redirect_uri")
            return

        elif parsed_path.path == "/userinfo":
            # Check for valid authorization header
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Bearer realm="demo", error="invalid_token", error_description="Token verification failed"')
                self.end_headers()
                self.wfile.write(b'{"error": "invalid_token"}')
                return

            # Extract token
            token = auth_header[7:]  # Remove 'Bearer ' prefix

            # Check if it's a valid mock token
            if token.startswith('mock_exchanged_token_'):
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()

                # Mock userinfo response
                userinfo_response = {
                    "sub": "john.doe",
                    "name": "John Doe",
                    "email": "john.doe@example.com",
                    "username": "john.doe"
                }
                self.wfile.write(json.dumps(userinfo_response).encode())
            else:
                # Invalid token
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Bearer realm="demo", error="invalid_token", error_description="Token verification failed"')
                self.end_headers()
                self.wfile.write(b'{"error": "invalid_token"}')
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        if self.path == "/token":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            # Mock token response
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length).decode('utf-8')
                params = urllib.parse.parse_qs(post_data)

                grant_type = params.get('grant_type', [''])[0]

                if grant_type == 'urn:ietf:params:oauth:grant-type:token-exchange':
                    # Mock token exchange response
                    token_response = {
                        "access_token": f"mock_exchanged_token_{int(time.time())}",
                        "token_type": "bearer",
                        "expires_in": 3600,
                        "scope": "openid profile email",
                        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
                    }
                else:
                    # Regular token response
                    token_response = {
                        "access_token": f"mock_access_token_{int(time.time())}",
                        "token_type": "bearer",
                        "expires_in": 3600,
                        "scope": "openid profile email offline_access",
                        "refresh_token": f"mock_refresh_token_{int(time.time())}",
                        "id_token": f"mock_id_token_{int(time.time())}"
                    }
            else:
                # Default token response
                token_response = {
                    "access_token": f"mock_access_token_{int(time.time())}",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "scope": "openid profile email"
                }

            self.wfile.write(json.dumps(token_response).encode())
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def log_message(self, format, *args):
        # Suppress default logging
        pass

if __name__ == "__main__":
    server = HTTPServer(('localhost', 9999), MockOAuthProvider)
    print("Mock OAuth2 provider running on http://localhost:9999")
    print("Ready to serve requests...")
    server.serve_forever()
EOF

    chmod +x mock_provider.py
    python3 mock_provider.py &
    MOCK_PID=$!
    echo $MOCK_PID > mock_provider.pid

    # Wait for mock server to start
    sleep 3

    # Test that mock provider is responding
    MOCK_RESPONSE=$(curl -s "$MOCK_PROVIDER_URL/.well-known/openid-configuration")
    if [ $? -eq 0 ] && [ -n "$MOCK_RESPONSE" ]; then
        print_status "success" "Mock upstream provider started successfully"
        echo "Mock provider response preview: ${MOCK_RESPONSE:0:100}..."
    else
        print_status "error" "Failed to start mock upstream provider"
        echo "Curl exit code: $?"
        echo "Response: $MOCK_RESPONSE"
        exit 1
    fi
}

# Stop mock provider
stop_mock_provider() {
    if [ -f mock_provider.pid ]; then
        kill $(cat mock_provider.pid) 2>/dev/null || true
        rm -f mock_provider.pid mock_provider.py
        print_status "info" "Mock upstream provider stopped"
    fi
}

# Cleanup function
cleanup() {
    stop_mock_provider
    if [ -f server.pid ]; then
        kill $(cat server.pid) 2>/dev/null || true
        rm -f server.pid
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Start mock upstream provider
start_mock_provider

echo ""
echo "🧪 Step 1: Starting OAuth2 server in proxy mode..."

# Check if port 8080 is already in use and kill any existing server
if lsof -i :8080 > /dev/null 2>&1; then
    echo "Port 8080 is already in use. Killing existing server..."
    kill $(lsof -t -i :8080) 2>/dev/null || true
    sleep 2
fi

# Start the OAuth2 server in proxy mode with the mock provider
echo "DEBUG: Starting server with UPSTREAM_PROVIDER_URL=$MOCK_PROVIDER_URL"
env UPSTREAM_PROVIDER_URL="$MOCK_PROVIDER_URL" UPSTREAM_CLIENT_ID="mock-client-id" UPSTREAM_CLIENT_SECRET="mock-client-secret" UPSTREAM_CALLBACK_URL="$SERVER_URL/callback" API_KEY="$API_KEY" JWT_SIGNING_KEY="abcdefghijklmnopqrstuvwxyz123456" CONFIG_FILE="../config.yaml" ../bin/oauth2-server > server.log 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > server.pid

# Wait for server to start
sleep 8

# Test server health
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    print_status "error" "OAuth2 server failed to start"
    echo "Server logs:"
    cat server.log
    exit 1
fi

print_status "success" "OAuth2 server started in proxy mode"
echo ""

echo "🧪 Step 2: Registering clients for token exchange..."

# Register frontend client (confidential client)
FRONTEND_RESPONSE=$(curl -s -X POST "$SERVER_URL/register" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "client_id": "frontend-client",
    "client_name": "Frontend Client",
    "client_secret": "frontend-secret",
    "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange", "client_credentials"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile email",
    "redirect_uris": ["http://localhost:8080/callback"]
  }')

echo "Frontend client registration response: $FRONTEND_RESPONSE"

# Register backend client (confidential client)
BACKEND_RESPONSE=$(curl -s -X POST "$SERVER_URL/register" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "client_id": "backend-client",
    "client_name": "Backend Client",
    "client_secret": "backend-secret",
    "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange", "client_credentials"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile email api:read",
    "redirect_uris": ["http://localhost:8080/backend-callback"]
  }')

echo "Backend client registration response: $BACKEND_RESPONSE"

print_status "success" "Clients registered for token exchange testing"
echo ""

echo "🧪 Step 3: Obtaining initial access token via authorization code flow..."

# Generate PKCE parameters
CODE_VERIFIER=$(openssl rand -hex 32 | head -c 43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16)

# Build authorization URL
AUTH_URL="$SERVER_URL/authorize?response_type=code&client_id=frontend-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email%20offline_access&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

echo "🔗 Authorization URL: $AUTH_URL"

# Make authorization request (should redirect to mock provider)
AUTH_RESPONSE=$(curl -s -i --max-time 10 "$AUTH_URL")

# Check if we got redirected to the mock provider
if echo "$AUTH_RESPONSE" | grep -q "Location: $MOCK_PROVIDER_URL"; then
    print_status "success" "Authorization request redirected to upstream provider"
else
    print_status "error" "Authorization request did not redirect to upstream provider"
    echo "Response: $AUTH_RESPONSE"
    exit 1
fi

# Extract the upstream authorization URL from the redirect
UPSTREAM_AUTH_URL=$(echo "$AUTH_RESPONSE" | grep "Location:" | sed 's/.*Location: //' | tr -d '\r')

if [ -z "$UPSTREAM_AUTH_URL" ]; then
    print_status "error" "Could not extract upstream authorization URL"
    exit 1
fi

# Simulate the upstream authorization response
CALLBACK_RESPONSE=$(curl -s -i --max-redirs 0 "$UPSTREAM_AUTH_URL")

# Extract authorization code from the redirect location
AUTH_CODE=$(echo "$CALLBACK_RESPONSE" | grep "Location:" | grep -o 'code=[^&]*' | cut -d'=' -f2)

if [ -z "$AUTH_CODE" ]; then
    print_status "error" "Could not extract authorization code from callback"
    exit 1
fi

print_status "success" "Authorization code obtained: $AUTH_CODE"

# Exchange authorization code for tokens
TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "frontend-client:frontend-secret" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=http://localhost:8080/callback&code_verifier=$CODE_VERIFIER")

echo "Full initial token response: $TOKEN_RESPONSE"

# Extract access token
INITIAL_ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ -z "$INITIAL_ACCESS_TOKEN" ] || [ "$INITIAL_ACCESS_TOKEN" = "null" ]; then
    print_status "error" "Failed to obtain initial access token"
    exit 1
fi

print_status "success" "Initial tokens obtained: access=${INITIAL_ACCESS_TOKEN:0:30}..."
echo ""

echo "🧪 Step 4: Performing token exchange to create proxy token..."

# Perform token exchange using the frontend client
EXCHANGE_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "frontend-client:frontend-secret" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$INITIAL_ACCESS_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token&audience=api-service&scope=api:read")

echo "Token exchange response: $EXCHANGE_RESPONSE"

# Extract exchanged token
EXCHANGED_TOKEN=$(echo "$EXCHANGE_RESPONSE" | jq -r '.access_token')

if [ -z "$EXCHANGED_TOKEN" ] || [ "$EXCHANGED_TOKEN" = "null" ]; then
    print_status "error" "Token exchange failed"
    echo "Response: $EXCHANGE_RESPONSE"
    exit 1
fi

# Check if response indicates proxy processing
PROXY_PROCESSED=$(echo "$EXCHANGE_RESPONSE" | jq -r '.proxy_processed // false')
PROXY_SERVER=$(echo "$EXCHANGE_RESPONSE" | jq -r '.proxy_server // empty')

if [ "$PROXY_PROCESSED" = "true" ] && [ "$PROXY_SERVER" = "oauth2-server" ]; then
    print_status "success" "Token exchange processed by proxy server"
else
    print_status "error" "Token exchange response does not indicate proxy processing"
    echo "Expected proxy_processed=true and proxy_server=oauth2-server"
    exit 1
fi

print_status "success" "Proxy token obtained: ${EXCHANGED_TOKEN:0:50}..."
echo ""

echo "🧪 Step 5: Testing proxy userinfo endpoint..."

# Test userinfo with the exchanged proxy token
USERINFO_RESPONSE=$(curl -s -X GET "$SERVER_URL/userinfo" \
  -H "Authorization: Bearer $EXCHANGED_TOKEN")

echo "Proxy userinfo response: $USERINFO_RESPONSE"

# Check if userinfo worked and shows proxy processing
USERNAME=$(echo "$USERINFO_RESPONSE" | jq -r '.username')
EMAIL=$(echo "$USERINFO_RESPONSE" | jq -r '.email')
PROXY_PROCESSED_USERINFO=$(echo "$USERINFO_RESPONSE" | jq -r '.proxy_processed // false')
PROXY_SERVER_USERINFO=$(echo "$USERINFO_RESPONSE" | jq -r '.proxy_server // empty')

if [ "$USERNAME" = "john.doe" ] && [ "$EMAIL" = "john.doe@example.com" ] && [ "$PROXY_PROCESSED_USERINFO" = "true" ] && [ "$PROXY_SERVER_USERINFO" = "oauth2-server" ]; then
    print_status "success" "Proxy userinfo endpoint working correctly"
    print_status "success" "Upstream userinfo correctly retrieved through proxy token mapping"
    print_status "success" "Proxy claims correctly added to response"
else
    print_status "error" "Proxy userinfo failed or missing expected data"
    echo "Expected: username=john.doe, email=john.doe@example.com, proxy_processed=true, proxy_server=oauth2-server"
    echo "Got: username=$USERNAME, email=$EMAIL, proxy_processed=$PROXY_PROCESSED_USERINFO, proxy_server=$PROXY_SERVER_USERINFO"
    exit 1
fi

echo ""

echo "🧪 Step 6: Testing userinfo with invalid proxy token..."

# Test with a fake token that doesn't exist
INVALID_USERINFO_RESPONSE=$(curl -s -X GET "$SERVER_URL/userinfo" \
  -H "Authorization: Bearer fake-invalid-token")

echo "Invalid token userinfo response: $INVALID_USERINFO_RESPONSE"

# Should get an unauthorized error
if echo "$INVALID_USERINFO_RESPONSE" | grep -q "invalid proxy token"; then
    print_status "success" "Invalid proxy token correctly rejected"
else
    print_status "error" "Invalid proxy token was not rejected"
    echo "Expected error response, got: $INVALID_USERINFO_RESPONSE"
    exit 1
fi

echo ""

echo "🧪 Step 7: Testing userinfo with missing authorization header..."

# Test without authorization header
NO_AUTH_USERINFO_RESPONSE=$(curl -s -X GET "$SERVER_URL/userinfo")

echo "No auth header userinfo response: $NO_AUTH_USERINFO_RESPONSE"

# Should get an unauthorized error
if echo "$NO_AUTH_USERINFO_RESPONSE" | grep -q "authorization required"; then
    print_status "success" "Missing authorization header correctly rejected"
else
    print_status "error" "Missing authorization header was not rejected"
    echo "Expected error response, got: $NO_AUTH_USERINFO_RESPONSE"
    exit 1
fi

echo ""

echo "📊 Proxy UserInfo Test Results Summary"
echo "======================================"
echo "Step 1 (OAuth2 server in proxy mode): ✅ PASS"
echo "Step 2 (Client registration): ✅ PASS"
echo "Step 3 (Initial token acquisition): ✅ PASS"
echo "Step 4 (Token exchange proxy): ✅ PASS"
echo "Step 5 (Proxy userinfo success): ✅ PASS"
echo "Step 6 (Invalid token rejection): ✅ PASS"
echo "Step 7 (Missing auth rejection): ✅ PASS"
echo ""
print_status "success" "All proxy userinfo tests PASSED!"
echo ""
echo "🎉 Proxy userinfo endpoint working correctly!"
echo "   ✅ Proxy tokens correctly mapped to upstream tokens"
echo "   ✅ Userinfo requests forwarded to upstream provider"
echo "   ✅ Upstream responses correctly returned with proxy claims"
echo "   ✅ Invalid tokens properly rejected"
echo "   ✅ Missing authorization headers properly rejected"