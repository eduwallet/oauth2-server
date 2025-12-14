#!/bin/bash

set -euo pipefail

# Test CIMD (Client ID Metadata Document) auto-registration flow
# Starts a small mock metadata server and triggers an /authorize request
# with client_id set to the metadata URL and verifies the server auto-registers

SERVER_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"

echo "🧪 CIMD Registration Integration Test"
echo "===================================="

# Create a temporary directory for the mock server
TMPDIR=$(mktemp -d)
PY="$TMPDIR/mock_cimd_server.py"
OUT="$TMPDIR/server.out"

cat > "$PY" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/client.json':
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Cache-Control','max-age=60')
            self.end_headers()
            host = self.headers.get('Host')
            scheme = 'http'
            base = f"{scheme}://{host}"
            payload = {
                "client_id": f"{base}/client.json",
                "redirect_uris": [f"{base}/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "openid profile"
            }
            self.wfile.write(json.dumps(payload).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 0), Handler)
    print(server.server_address[1], flush=True)
    server.serve_forever()
PY

echo "🚀 Starting mock CIMD metadata server..."
python3 "$PY" > "$OUT" 2>&1 &
MOCK_PID=$!

# Wait for mock server to print port
for i in {1..20}; do
    if [[ -s "$OUT" ]]; then
        break
    fi
    sleep 0.1
done

if [[ ! -s "$OUT" ]]; then
    echo "❌ Mock CIMD server failed to start"
    cat "$OUT" || true
    kill $MOCK_PID 2>/dev/null || true
    exit 1
fi

PORT=$(head -n1 "$OUT" | tr -d '[:space:]')
METADATA_BASE="http://127.0.0.1:$PORT"
METADATA_URL="$METADATA_BASE/client.json"

echo "✅ Mock metadata server running at $METADATA_BASE (PID: $MOCK_PID)"

# Start OAuth2 server if not running, with CIMD enabled and HTTP permitted
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    echo "🚀 Starting OAuth2 server with CIMD enabled (local mode)..."
    UPSTREAM_PROVIDER_URL="" CIMD_ENABLED=true CIMD_HTTP_PERMITTED=true API_KEY="$API_KEY" LOG_LEVEL=debug ./bin/oauth2-server > server-cimd.log 2>&1 &
    SERVER_PID=$!
    echo "✅ OAuth2 server started (PID: $SERVER_PID)"

    # Wait for server health
    for i in {1..10}; do
        if curl -s "$SERVER_URL/health" > /dev/null; then
            break
        fi
        sleep 1
    done
fi

echo "ℹ️  Verifying server is accessible at $SERVER_URL..."
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    echo "❌ Server is not accessible at $SERVER_URL"
    kill $MOCK_PID 2>/dev/null || true
    exit 1
fi

echo "🔍 Triggering authorization request with client_id=$METADATA_URL"
AUTH_URL="$SERVER_URL/authorize?response_type=code&client_id=$METADATA_URL&redirect_uri=${METADATA_BASE}/callback&scope=openid&state=teststate"

RESP=$(curl -s -i -X GET "$AUTH_URL" -H "Accept: text/html")

if echo "$RESP" | grep -qi "login\|Login\|Username\|Password"; then
    echo "✅ Authorization endpoint served login form for CIMD client - auto-registration likely succeeded"
else
    echo "❌ Authorization endpoint did not return a login form"
    echo "Response preview:" 
    echo "$RESP" | head -n 40
    kill $MOCK_PID 2>/dev/null || true
    if [[ -n "${SERVER_PID:-}" ]]; then kill $SERVER_PID 2>/dev/null || true; fi
    exit 1
fi

echo "✅ CIMD registration flow appears to work (authorization login form returned)."

# Cleanup
echo "🛑 Cleaning up..."
kill $MOCK_PID 2>/dev/null || true
rm -rf "$TMPDIR"
if [[ -n "${SERVER_PID:-}" ]]; then
    kill $SERVER_PID 2>/dev/null || true
    rm -f server-cimd.log
fi

echo "🎉 CIMD registration integration test completed successfully"
exit 0
