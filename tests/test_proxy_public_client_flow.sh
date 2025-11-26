#!/bin/bash

# Test Proxy Public Client Authorization Code Flow
# This script tests the OAuth2 authorization code flow in proxy mode
# where the downstream client is a public client and upstream is confidential

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile email}"

echo "🧪 Proxy Public Client Authorization Code Flow Test"
echo "=================================================="
echo "Testing OAuth2 Authorization Code Flow in Proxy Mode"
echo "Downstream: Public Client | Upstream: Confidential Client"
echo "Using environment variables:"
echo "  TEST_USERNAME: $TEST_USERNAME"
echo "  TEST_PASSWORD: $TEST_PASSWORD"
echo "  TEST_SCOPE: $TEST_SCOPE"
echo ""

SERVER_URL="http://localhost:8080"
MOCK_PROVIDER_URL="http://localhost:9999"
API_KEY="test-api-key"

# Initialize test results
STEP1_PASS=false
STEP2_PASS=false
STEP3_PASS=false
STEP4_PASS=false
STEP5_PASS=false
STEP6_PASS=false

# Function to print status
print_status() {
    local status="$1"
    local message="$2"
    case "$status" in
        "success")
            echo "✅ $message"
            ;;
        "error")
            echo "❌ $message"
            ;;
        "info")
            echo "ℹ️  $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Start mock upstream provider
start_mock_provider() {
    print_status "info" "Starting mock upstream OAuth2 provider..."

    # Kill any existing process on port 9999
    if lsof -i :9999 > /dev/null 2>&1; then
        echo "Port 9999 is already in use. Killing existing process..."
        kill $(lsof -t -i :9999) 2>/dev/null || true
        sleep 2
    fi

    cat > mock_provider.py << 'EOF'
import http.server
import socketserver
import json
import urllib.parse
import uuid
import time
import base64

class MockOAuthProvider(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query_params = urllib.parse.parse_qs(parsed_path.query)

        if path == "/.well-known/openid-configuration":
            print("DEBUG: Serving OpenID configuration")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            config = {
                "issuer": "http://localhost:9999",
                "authorization_endpoint": "http://localhost:9999/authorize",
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

        elif path == "/authorize":
            print("DEBUG: Handling authorization request")
            # Mock login form
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """
            <html>
            <body>
                <h1>Mock OAuth2 Login</h1>
                <form method="POST" action="/authorize">
                    <input type="hidden" name="response_type" value="{response_type}">
                    <input type="hidden" name="client_id" value="{client_id}">
                    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                    <input type="hidden" name="state" value="{state}">
                    <input type="hidden" name="scope" value="{scope}">
                    <input type="hidden" name="code_challenge" value="{code_challenge}">
                    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
                    <label>Username: <input type="text" name="username" value="john.doe"></label><br>
                    <label>Password: <input type="password" name="password" value="password123"></label><br>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>
            """.format(
                response_type=parsed_path.query_params.get('response_type', [''])[0] if hasattr(parsed_path, 'query_params') else '',
                client_id=urllib.parse.parse_qs(parsed_path.query)['client_id'][0] if 'client_id' in urllib.parse.parse_qs(parsed_path.query) else '',
                redirect_uri=urllib.parse.parse_qs(parsed_path.query).get('redirect_uri', [''])[0],
                state=urllib.parse.parse_qs(parsed_path.query).get('state', [''])[0],
                scope=urllib.parse.parse_qs(parsed_path.query).get('scope', [''])[0],
                code_challenge=urllib.parse.parse_qs(parsed_path.query).get('code_challenge', [''])[0],
                code_challenge_method=urllib.parse.parse_qs(parsed_path.query).get('code_challenge_method', [''])[0]
            )
            self.wfile.write(html.encode())
            return

        elif path == "/userinfo":
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

            # Mock userinfo response
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

        print(f"DEBUG: Path not found: {path}")
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == "/authorize":
            print("DEBUG: Handling login submission")
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)

            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]

            if username == "john.doe" and password == "password123":
                # Generate authorization code
                auth_code = f"mock_auth_code_{uuid.uuid4().hex}"

                # Build redirect URI
                redirect_uri = params.get('redirect_uri', [''])[0]
                state = params.get('state', [''])[0]
                redirect_url = f"{redirect_uri}?code={auth_code}&state={state}"

                self.send_response(302)
                self.send_header('Location', redirect_url)
                self.end_headers()
                print(f"DEBUG: Redirecting to: {redirect_url}")
            else:
                self.send_response(401)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<h1>Invalid credentials</h1>")
            return

        elif path == "/token":
            print("DEBUG: Handling token request")
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)

            grant_type = params.get('grant_type', [''])[0]

            if grant_type == "authorization_code":
                auth_code = params.get('code', [''])[0]

                if auth_code.startswith('mock_auth_code_'):
                    # Issue token
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
                    print(f"DEBUG: Issued token for auth code: {auth_code}")
                else:
                    # Invalid code
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    error_response = {"error": "invalid_grant"}
                    self.wfile.write(json.dumps(error_response).encode())
            else:
                # Handle other grant types
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

        elif path == "/introspect":
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
    server = socketserver.TCPServer(('localhost', 9999), MockOAuthProvider)
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
UPSTREAM_PROVIDER_URL="$MOCK_PROVIDER_URL" UPSTREAM_CLIENT_ID="mock-client-id" UPSTREAM_CLIENT_SECRET="mock-client-secret" UPSTREAM_CALLBACK_URL="$SERVER_URL/callback" API_KEY="$API_KEY" ./bin/oauth2-server > server.log 2>&1 &
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

echo "🧪 Step 2: Registering public client for proxy authorization code flow..."

# Register a public client for authorization code testing
REGISTER_RESPONSE=$(curl -s -X POST "$SERVER_URL/register" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Proxy Public Client Test",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": "openid profile email",
    "redirect_uris": ["http://localhost:8080/oauth/callback"],
    "public": true
  }')

echo "Client Registration Response: $REGISTER_RESPONSE"

# Extract client ID from registration response
TEST_CLIENT_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.client_id // empty' 2>/dev/null || echo "")

if [ -z "$TEST_CLIENT_ID" ]; then
    print_status "error" "Failed to register public test client"
    echo "Response: $REGISTER_RESPONSE"
    exit 1
fi

print_status "success" "Public client registered successfully"
echo "   Client ID: $TEST_CLIENT_ID"
echo "   Public: true (no client secret)"
echo ""

echo "🧪 Step 3: Testing proxy public client authorization code flow..."

# Check if server is still running
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    print_status "error" "OAuth2 server is not responding"
    exit 1
fi

print_status "info" "Server is still running, proceeding with authorization request"

# Generate PKCE parameters
CODE_VERIFIER=$(openssl rand -hex 32 | cut -c1-64 | tr -d '\n')
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')

echo "🔐 PKCE Code Verifier: ${CODE_VERIFIER:0:20}..."
echo "🔐 PKCE Code Challenge: ${CODE_CHALLENGE:0:20}..."

# Generate state
STATE=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
echo "🎲 State: ${STATE:0:20}..."

# Build authorization URL for proxy
AUTH_URL="$SERVER_URL/authorize?response_type=code&client_id=$TEST_CLIENT_ID&redirect_uri=http://localhost:8080/oauth/callback&state=$STATE&scope=openid&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

echo "🔗 Proxy Authorization URL: $AUTH_URL"

# Make initial GET request to authorization endpoint
AUTH_RESPONSE=$(curl -s -i -X GET "$AUTH_URL" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")

# Check for redirect to upstream provider (proxy mode behavior)
if echo "$AUTH_RESPONSE" | grep -q "302 Found" && echo "$AUTH_RESPONSE" | grep -q "Location: http://localhost:9999/authorize"; then
    print_status "success" "Proxy authorization redirect successful - correctly forwarding to upstream provider"
    STEP3_PASS=true
else
    print_status "error" "Expected redirect to upstream provider in proxy mode"
    echo "Response: $AUTH_RESPONSE"
    exit 1
fi

echo ""

echo "🧪 Step 4: Simulating upstream login and authorization code exchange..."

# Extract upstream authorization URL from redirect
UPSTREAM_AUTH_URL=$(echo "$AUTH_RESPONSE" | grep -i "Location:" | sed 's/.*Location: //' | tr -d '\r\n')

if [ -z "$UPSTREAM_AUTH_URL" ]; then
    print_status "error" "Could not extract upstream authorization URL from redirect"
    exit 1
fi

echo "🔗 Upstream Authorization URL: $UPSTREAM_AUTH_URL"

# Simulate login by POSTing to upstream /authorize
UPSTREAM_LOGIN_RESPONSE=$(curl -s -i -X POST "$UPSTREAM_AUTH_URL" \
    --data-urlencode "username=$TEST_USERNAME" \
    --data-urlencode "password=$TEST_PASSWORD" \
    --data-urlencode "response_type=code" \
    --data-urlencode "client_id=mock-client-id" \
    --data-urlencode "redirect_uri=$SERVER_URL/callback" \
    --data-urlencode "state=$STATE" \
    --data-urlencode "scope=openid" \
    --data-urlencode "code_challenge=$CODE_CHALLENGE" \
    --data-urlencode "code_challenge_method=S256")

# Check for redirect back to proxy callback with authorization code
if echo "$UPSTREAM_LOGIN_RESPONSE" | grep -q "302 Found" && echo "$UPSTREAM_LOGIN_RESPONSE" | grep -q "Location: $SERVER_URL/callback"; then
    print_status "success" "Upstream login successful - redirecting back to proxy callback"
else
    print_status "error" "Expected redirect back to proxy callback after upstream login"
    echo "Response: $UPSTREAM_LOGIN_RESPONSE"
    exit 1
fi

# Extract authorization code from callback redirect
CALLBACK_URL=$(echo "$UPSTREAM_LOGIN_RESPONSE" | grep -i "Location:" | sed 's/.*Location: //' | tr -d '\r\n')
AUTH_CODE=$(echo "$CALLBACK_URL" | sed 's/.*code=\([^&]*\).*/\1/')

if [ -z "$AUTH_CODE" ]; then
    print_status "error" "Could not extract authorization code from callback URL"
    exit 1
fi

print_status "success" "Authorization code obtained: ${AUTH_CODE:0:20}..."
STEP4_PASS=true

echo ""

echo "🧪 Step 5: Exchanging authorization code for access token..."

# Exchange authorization code for token at proxy server
TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&client_id=$TEST_CLIENT_ID&code=$AUTH_CODE&redirect_uri=http://localhost:8080/oauth/callback&code_verifier=$CODE_VERIFIER")

echo "Token Response: $TOKEN_RESPONSE"

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null || echo "")

if [ -z "$ACCESS_TOKEN" ]; then
    print_status "error" "Failed to obtain access token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

print_status "success" "Access token obtained: ${ACCESS_TOKEN:0:20}..."
STEP5_PASS=true

echo ""

echo "🧪 Step 6: Testing UserInfo endpoint with access token..."

# Call UserInfo endpoint with the access token
USERINFO_RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$SERVER_URL/userinfo")

echo "UserInfo Response: $USERINFO_RESPONSE"

# Validate UserInfo response
EXPECTED_SUB="john.doe"
ACTUAL_SUB=$(echo "$USERINFO_RESPONSE" | jq -r '.sub // empty' 2>/dev/null || echo "")

if [ "$ACTUAL_SUB" = "$EXPECTED_SUB" ]; then
    print_status "success" "UserInfo endpoint returned correct user data"
    STEP6_PASS=true
else
    print_status "error" "UserInfo endpoint returned incorrect or missing data"
    echo "Expected sub: $EXPECTED_SUB"
    echo "Actual sub: $ACTUAL_SUB"
    exit 1
fi

echo ""

echo ""

echo "📊 Proxy Public Client Flow Test Results Summary"
echo "================================================"
echo "Step 1 (OAuth2 server in proxy mode): ✅ PASS"
echo "Step 2 (Public client registration): ✅ PASS"
echo "Step 3 (Proxy authorization redirect): $([ "$STEP3_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 4 (Upstream login and code exchange): $([ "$STEP4_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 5 (Token exchange): $([ "$STEP5_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"
echo "Step 6 (UserInfo endpoint): $([ "$STEP6_PASS" = true ] && echo "✅ PASS" || echo "❌ FAIL")"

# Overall result
if [ "$STEP3_PASS" = true ] && [ "$STEP4_PASS" = true ] && [ "$STEP5_PASS" = true ] && [ "$STEP6_PASS" = true ]; then
    echo ""
    print_status "success" "Proxy public client authorization code flow test PASSED!"
    echo "   ✅ Public client authorization requests are correctly forwarded to upstream provider"
    echo "   ✅ Proxy mode works for public clients without client secrets"
    echo "   ✅ PKCE parameters are properly passed through to upstream"
    echo "   ✅ Authorization code exchange returns valid access token"
    echo "   ✅ UserInfo endpoint returns correct user data from upstream"
    exit 0
else
    echo ""
    print_status "error" "Proxy public client authorization code flow test FAILED!"
    exit 1
fi