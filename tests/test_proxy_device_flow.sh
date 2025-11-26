#!/bin/bash

# Test script for proxy mode device authorization grant flow
# Tests device authorization through a mocked upstream provider

set -e

# Configuration
SERVER_URL="http://localhost:8080"
MOCK_PROVIDER_PORT=9999
MOCK_PROVIDER_URL="http://localhost:$MOCK_PROVIDER_PORT"
TEST_USERNAME="john.doe"
TEST_PASSWORD="password123"
TEST_SCOPE="openid profile api:read"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 Proxy Mode Device Flow Test"
echo "=============================="
echo "Testing proxy mode device authorization grant flow (RFC 8628)"
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

# Start mock upstream OAuth2 provider with device authorization support
start_mock_provider() {
    # Check if mock provider is already running
    if [ -f mock_provider.pid ] && kill -0 $(cat mock_provider.pid) 2>/dev/null; then
        print_status "info" "Mock upstream provider already running (PID: $(cat mock_provider.pid))"
        return 0
    fi

    print_status "info" "Starting mock upstream OAuth2 provider on port $MOCK_PROVIDER_PORT..."

    cat > mock_provider.py << 'EOF'
#!/usr/bin/env python3
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class MockOAuthProvider(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.device_codes = {}  # Store device codes and their state
        super().__init__(*args, **kwargs)

    def do_GET(self):
        print(f"DEBUG: Received GET request for path: {self.path}")
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)

        if parsed_path.path == "/.well-known/openid-configuration":
            print("DEBUG: Serving OIDC discovery document")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            config = {
                "issuer": "http://localhost:9999",
                "authorization_endpoint": "http://localhost:9999/auth",
                "device_authorization_endpoint": "http://localhost:9999/device/authorize",
                "token_endpoint": "http://localhost:9999/token",
                "introspection_endpoint": "http://localhost:9999/introspect",
                "userinfo_endpoint": "http://localhost:9999/userinfo",
                "jwks_uri": "http://localhost:9999/jwks",
                "scopes_supported": ["openid", "profile", "email", "api:read"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"]
            }
            self.wfile.write(json.dumps(config).encode())
            return

        elif parsed_path.path == "/device":
            print("DEBUG: Serving device verification page")
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """
            <html>
            <body>
                <h1>Device Authorization</h1>
                <p>Enter your user code to authorize the device:</p>
                <form method="POST" action="/device/verify">
                    <input type="text" name="user_code" placeholder="Enter user code">
                    <button type="submit">Authorize</button>
                </form>
            </body>
            </html>
            """
            self.wfile.write(html.encode())
            return

        elif parsed_path.path == "/userinfo":
            print("DEBUG: Handling userinfo request")
            # Check for authorization header
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Bearer')
                self.end_headers()
                self.wfile.write(b'{"error": "invalid_token"}')
                return
            
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Mock userinfo response - in a real implementation this would validate the token
            userinfo = {
                "sub": "john.doe",
                "name": "John Doe",
                "email": "john.doe@example.com",
                "username": "john.doe",
                "preferred_username": "john.doe"
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(userinfo).encode())
            print(f"DEBUG: Served userinfo for token: {token[:20]}...")
            return

        print(f"DEBUG: Path not found: {parsed_path.path}")
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        if self.path == "/device/authorize":
            print("DEBUG: Handling device authorization request")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            # Generate device and user codes
            device_code = f"mock_device_code_{uuid.uuid4().hex}"
            user_code = f"{uuid.uuid4().hex[:8].upper()}"

            # Store device code state
            self.server.device_codes[device_code] = {
                "user_code": user_code,
                "authorized": False,
                "client_id": "test-device-client",
                "scope": "openid profile api:read"
            }

            device_response = {
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": "http://localhost:9999/device",
                "verification_uri_complete": f"http://localhost:9999/device?user_code={user_code}",
                "expires_in": 600,
                "interval": 5
            }
            self.wfile.write(json.dumps(device_response).encode())
            print(f"DEBUG: Created device code: {device_code}, user code: {user_code}")
            return

        elif self.path == "/device/verify":
            print("DEBUG: Handling device verification")
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)

            user_code = params.get('user_code', [''])[0]

            # Find device code by user code
            device_code = None
            for code, data in self.server.device_codes.items():
                if data['user_code'] == user_code:
                    device_code = code
                    break

            if device_code:
                # Mark as authorized
                self.server.device_codes[device_code]['authorized'] = True
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<h1>Device Authorized Successfully!</h1>")
                print(f"DEBUG: Authorized device code: {device_code}")
            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<h1>Invalid User Code</h1>")
            return

        elif self.path == "/token":
            print("DEBUG: Handling token request")
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)

            grant_type = params.get('grant_type', [''])[0]

            if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
                device_code = params.get('device_code', [''])[0]

                if device_code in self.server.device_codes:
                    device_data = self.server.device_codes[device_code]
                    if device_data['authorized']:
                        # Issue token
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        token_response = {
                            "access_token": f"mock_access_token_{uuid.uuid4().hex}",
                            "token_type": "bearer",
                            "expires_in": 3600,
                            "scope": device_data['scope'],
                            "id_token": f"mock_id_token_{uuid.uuid4().hex}"
                        }
                        self.wfile.write(json.dumps(token_response).encode())
                        print(f"DEBUG: Issued token for device code: {device_code}")
                    else:
                        # Still pending
                        self.send_response(400)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        error_response = {"error": "authorization_pending"}
                        self.wfile.write(json.dumps(error_response).encode())
                else:
                    # Invalid device code
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    error_response = {"error": "invalid_grant"}
                    self.wfile.write(json.dumps(error_response).encode())
            else:
                # Handle authorization code flow
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                token_response = {
                    "access_token": f"mock_access_token_{uuid.uuid4().hex}",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "scope": "openid profile email",
                    "id_token": f"mock_id_token_{uuid.uuid4().hex}"
                }
                self.wfile.write(json.dumps(token_response).encode())
            return

        elif self.path == "/introspect":
            print("DEBUG: Handling introspection request")
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)

            token = params.get('token', [''])[0]

            if token.startswith('mock_access_token_'):
                # Mock active token response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                introspect_response = {
                    "active": True,
                    "client_id": "mock-client-id",
                    "sub": "john.doe",
                    "scope": "openid profile api:read",
                    "token_type": "bearer",
                    "exp": int(time.time()) + 3600,
                    "iat": int(time.time()),
                    "iss": "http://localhost:9999"
                }
                self.wfile.write(json.dumps(introspect_response).encode())
                print(f"DEBUG: Introspected active token: {token[:20]}...")
            else:
                # Mock inactive token response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                introspect_response = {
                    "active": False
                }
                self.wfile.write(json.dumps(introspect_response).encode())
                print(f"DEBUG: Introspected inactive token: {token[:20]}...")
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def log_message(self, format, *args):
        # Suppress default logging
        pass

if __name__ == "__main__":
    # Custom server class to store device codes
    class MockServer(HTTPServer):
        def __init__(self, *args, **kwargs):
            self.device_codes = {}
            super().__init__(*args, **kwargs)

    server = MockServer(('localhost', 9999), MockOAuthProvider)
    print("Mock OAuth2 provider with device authorization running on http://localhost:9999")
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
    sleep 1
    echo "Testing mock provider endpoint..."
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
UPSTREAM_PROVIDER_URL="$MOCK_PROVIDER_URL" UPSTREAM_CLIENT_ID="mock-client-id" UPSTREAM_CLIENT_SECRET="mock-client-secret" UPSTREAM_CALLBACK_URL="$SERVER_URL/callback" ./bin/oauth2-server > server.log 2>&1 &
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

echo "🧪 Step 2: Registering test client for device authorization..."

# Register a client for device authorization testing
REGISTER_RESPONSE=$(curl -s -X POST "$SERVER_URL/register" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Device Test Client",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile api:read",
    "redirect_uris": ["http://localhost:8080/test-callback"],
    "client_secret": "device-client-secret",
    "public": false
  }')

echo "Client Registration Response: $REGISTER_RESPONSE"

# Extract client ID from registration response
TEST_CLIENT_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.client_id // empty' 2>/dev/null || echo "")

if [ -z "$TEST_CLIENT_ID" ]; then
    print_status "error" "Failed to register test client"
    echo "Response: $REGISTER_RESPONSE"
    exit 1
fi

print_status "success" "Test client registered successfully"
echo "   Client ID: $TEST_CLIENT_ID"
echo ""

echo "🧪 Step 3: Testing proxy device authorization flow..."

# Check if server is still running
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    print_status "error" "OAuth2 server is not responding"
    exit 1
fi

print_status "info" "Server is still running, proceeding with device authorization request"

# Request device authorization (should be forwarded to upstream provider)
echo "📱 Requesting device authorization through proxy..."
DEVICE_RESPONSE=$(curl -s -X POST "$SERVER_URL/device/authorize" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$TEST_CLIENT_ID&scope=api:read")

echo "Device Authorization Response: $DEVICE_RESPONSE"

# Extract device code and user code
DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code // empty' 2>/dev/null || echo "")
USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code // empty' 2>/dev/null || echo "")

if [ -z "$DEVICE_CODE" ] || [ -z "$USER_CODE" ]; then
    print_status "error" "Failed to get proxy device/user codes"
    echo "Response: $DEVICE_RESPONSE"
    exit 1
fi

print_status "success" "Proxy device authorization successful"
echo "   Proxy Device Code: ${DEVICE_CODE:0:30}..."
echo "   Proxy User Code: $USER_CODE"
echo ""

echo "🧪 Step 4: Simulating user verification at upstream provider..."

# Simulate user verification at the upstream provider
# In a real scenario, the user would visit the verification URI and enter the user code
VERIFY_RESPONSE=$(curl -s -X POST "$MOCK_PROVIDER_URL/device/verify" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_code=$USER_CODE")

if echo "$VERIFY_RESPONSE" | grep -q "Authorized Successfully"; then
    print_status "success" "User verification completed at upstream provider"
else
    print_status "error" "User verification failed at upstream provider"
    echo "Response: $VERIFY_RESPONSE"
    exit 1
fi

echo ""

echo "🧪 Step 5: Polling for device token through proxy..."

# Poll for token using the proxy device code
# The proxy should forward this to the upstream provider
MAX_ATTEMPTS=10
ATTEMPT=1
TOKEN_RECEIVED=false

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    echo "🔄 Token polling attempt $ATTEMPT/$MAX_ATTEMPTS..."

    TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -u "$TEST_CLIENT_ID:device-client-secret" \
      -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=$TEST_CLIENT_ID")

    echo "Token Response: $TOKEN_RESPONSE"

    # Check if we got a token
    if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
        print_status "success" "Device token received through proxy!"
        TOKEN_RECEIVED=true
        break
    elif echo "$TOKEN_RESPONSE" | grep -q "authorization_pending"; then
        echo "⏳ Authorization still pending, waiting 3 seconds..."
        sleep 3
    elif echo "$TOKEN_RESPONSE" | grep -q "slow_down"; then
        echo "🐌 Server requested slow down, waiting 5 seconds..."
        sleep 5
    else
        print_status "error" "Unexpected token response"
        echo "Response: $TOKEN_RESPONSE"
        break
    fi

    ATTEMPT=$((ATTEMPT + 1))
done

if [ "$TOKEN_RECEIVED" = false ]; then
    print_status "error" "Failed to receive device token through proxy"
    exit 1
fi

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null || echo "")

if [ -z "$ACCESS_TOKEN" ]; then
    print_status "error" "Could not extract access token from response"
    exit 1
fi

print_status "success" "Access token obtained: ${ACCESS_TOKEN:0:30}..."
echo ""

echo "🧪 Step 6: Testing userinfo endpoint through proxy..."

# Test userinfo endpoint with the proxy access token
# This should forward to the upstream provider and return userinfo
USERINFO_RESPONSE=$(curl -s -X GET "$SERVER_URL/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "UserInfo Response: $USERINFO_RESPONSE"

# Check if we got userinfo response
if echo "$USERINFO_RESPONSE" | grep -q "sub"; then
    print_status "success" "Userinfo retrieved through proxy!"
    
    # Extract and display some userinfo fields
    SUB=$(echo "$USERINFO_RESPONSE" | jq -r '.sub // empty' 2>/dev/null || echo "")
    NAME=$(echo "$USERINFO_RESPONSE" | jq -r '.name // empty' 2>/dev/null || echo "")
    EMAIL=$(echo "$USERINFO_RESPONSE" | jq -r '.email // empty' 2>/dev/null || echo "")
    PROXY_PROCESSED=$(echo "$USERINFO_RESPONSE" | jq -r '.proxy_processed // empty' 2>/dev/null || echo "")
    
    if [ -n "$SUB" ]; then
        echo "   Subject: $SUB"
    fi
    if [ -n "$NAME" ]; then
        echo "   Name: $NAME"
    fi
    if [ -n "$EMAIL" ]; then
        echo "   Email: $EMAIL"
    fi
    if [ "$PROXY_PROCESSED" = "true" ]; then
        echo "   ✅ Proxy processed: $PROXY_PROCESSED"
    fi
else
    print_status "error" "Failed to retrieve userinfo through proxy"
    echo "Response: $USERINFO_RESPONSE"
    exit 1
fi

echo ""

echo "🧪 Step 7: Testing token introspection..."

# Test introspection with privileged client
PRIVILEGED_TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "server-owned-client:server-admin-secret" \
  -d "grant_type=client_credentials&scope=admin")

PRIVILEGED_TOKEN=$(echo "$PRIVILEGED_TOKEN_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null || echo "")

if [ -z "$PRIVILEGED_TOKEN" ]; then
    print_status "error" "Failed to obtain privileged client token"
    exit 1
fi

print_status "success" "Privileged client token obtained"

# Test introspection - note: proxy device tokens may not be introspectable locally
# since they come from upstream provider
INTROSPECTION_RESPONSE=$(curl -s -X POST "$SERVER_URL/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "server-owned-client:server-admin-secret" \
  -d "token=$ACCESS_TOKEN")

echo "Introspection Response: $INTROSPECTION_RESPONSE"

# Check if token introspection worked through proxy
if echo "$INTROSPECTION_RESPONSE" | grep -q '"active":true'; then
    print_status "success" "Token introspection successful through proxy!"
    
    # Verify upstream introspection data
    if echo "$INTROSPECTION_RESPONSE" | grep -q '"issued_by_proxy":true'; then
        print_status "success" "Upstream introspection response properly enhanced with proxy information"
    else
        print_status "error" "Upstream introspection response missing proxy enhancement"
        exit 1
    fi
    
    if echo "$INTROSPECTION_RESPONSE" | grep -q '"proxy_server":"oauth2-server"'; then
        print_status "success" "Proxy server identification included in response"
    else
        print_status "error" "Proxy server identification missing from response"
        exit 1
    fi
else
    print_status "error" "Token introspection failed through proxy"
    echo "Response: $INTROSPECTION_RESPONSE"
    exit 1
fi

echo ""

echo "📊 Proxy Mode Device Flow Test Results Summary"
echo "=============================================="
echo "Step 1 (OAuth2 server in proxy mode): ✅ PASS"
echo "Step 2 (Client registration): ✅ PASS"
echo "Step 3 (Proxy device authorization): ✅ PASS"
echo "Step 4 (Upstream user verification): ✅ PASS"
echo "Step 5 (Proxy token polling): ✅ PASS"
echo "Step 6 (Proxy userinfo): ✅ PASS"
echo "Step 7 (Token introspection): ✅ PASS"
echo "      Note: Proxy device tokens are introspectable via upstream provider"
echo ""
print_status "success" "All core proxy mode device flow tests PASSED!"
echo ""
echo "🎉 Proxy mode device authorization grant flow working correctly!"
echo "   ✅ Client registration for device authorization"
echo "   ✅ Device authorization requests forwarded to upstream provider"
echo "   ✅ Proxy codes mapped to upstream codes for correlation"
echo "   ✅ User verification handled at upstream provider"
echo "   ✅ Token polling forwarded through proxy with code mapping"
echo "   ✅ Tokens issued by upstream provider accessible through proxy"
echo "   ✅ Userinfo requests forwarded through proxy with upstream token mapping"
echo "   ✅ Token introspection forwarded through proxy with upstream provider data"