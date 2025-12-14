#!/bin/bash

set -euo pipefail

# Test CIMD using the example metadata server in examples/cimd
SERVER_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 CIMD Example Integration Test"
echo "================================"

EXAMPLE_DIR="$(pwd)/examples/cimd"

# Choose a free port dynamically to avoid collisions
PORT=$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("",0))
print(s.getsockname()[1])
s.close()
PY
)

echo "🚀 Starting example metadata server (serve.sh) on port $PORT..."
chmod +x "$EXAMPLE_DIR/serve.sh"
nohup "$EXAMPLE_DIR/serve.sh" "$PORT" > /tmp/cimd_example_server.log 2>&1 &
SERVER_PID=$!

# Wait for the server to be ready
for i in {1..20}; do
    if curl -s "http://127.0.0.1:$PORT/client.json" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if ! curl -s "http://127.0.0.1:$PORT/client.json" >/dev/null 2>&1; then
    echo "❌ Example metadata server failed to start or serve files"
    cat /tmp/cimd_example_server.log || true
    exit 1
fi

METADATA_BASE="http://127.0.0.1:$PORT"
METADATA_URL="$METADATA_BASE/client.json"

echo "✅ Example metadata server running at $METADATA_BASE (PID: $SERVER_PID)"

# Start OAuth2 server if not already running
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    echo "🚀 Starting OAuth2 server with CIMD enabled (local mode)..."
    UPSTREAM_PROVIDER_URL="" CIMD_ENABLED=true CIMD_HTTP_PERMITTED=true ENABLE_TRUST_ANCHOR_API=true API_KEY="$API_KEY" LOG_LEVEL=debug ./bin/oauth2-server > server-cimd.log 2>&1 &
    OAUTH_PID=$!
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
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "🔍 Triggering authorization request with client_id=$METADATA_URL"
AUTH_URL="$SERVER_URL/authorize?response_type=code&client_id=$METADATA_URL&redirect_uri=${METADATA_BASE}/callback&scope=openid&state=teststate"

RESP=$(curl -s -i -X GET "$AUTH_URL" -H "Accept: text/html")

if echo "$RESP" | grep -qi "login\|Login\|Username\|Password"; then
    echo "✅ Authorization endpoint served login form for CIMD client - example auto-registration succeeded"
else
    echo "❌ Authorization endpoint did not return a login form"
    echo "Response preview:"
    echo "$RESP" | head -n 40
    kill $SERVER_PID 2>/dev/null || true
    if [[ -n "${OAUTH_PID:-}" ]]; then kill $OAUTH_PID 2>/dev/null || true; fi
    exit 1
fi

echo "✅ CIMD example registration flow appears to work (authorization login form returned)."

# Cleanup
echo "🛑 Cleaning up..."
kill $SERVER_PID 2>/dev/null || true
if [[ -n "${OAUTH_PID:-}" ]]; then
    kill $OAUTH_PID 2>/dev/null || true
    rm -f server-cimd.log
fi

echo "🎉 CIMD example integration test completed successfully"
exit 0
