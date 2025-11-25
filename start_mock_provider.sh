#!/bin/bash
# Mock upstream OAuth2 provider startup script
MOCK_PROVIDER_PORT=9999

cat > mock_provider.py << 'MOCK_EOF'
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
MOCK_EOF

chmod +x mock_provider.py
python3 mock_provider.py &
MOCK_PID=$!
echo $MOCK_PID > mock_provider.pid

# Wait for mock server to start
sleep 3

# Test that mock provider is responding
sleep 1
echo "Testing mock provider endpoint..."
MOCK_RESPONSE=$(curl -s "http://localhost:9999/.well-known/openid-configuration")
if [ $? -eq 0 ] && [ -n "$MOCK_RESPONSE" ]; then
    echo "Mock upstream provider started successfully"
    echo "Mock provider response preview: ${MOCK_RESPONSE:0:100}..."
else
    echo "Failed to start mock upstream provider"
    echo "Curl exit code: $?"
    echo "Response: $MOCK_RESPONSE"
    exit 1
fi