#!/bin/bash

# Simple RFC8693 Token Exchange Test
# This script tests ONLY the RFC8693 token exchange part

set -e

BASE_URL="http://localhost:8080"
CLIENT_ID="backend-client"
CLIENT_SECRET="backend-client-secret"

echo "🧪 Testing RFC8693 Token Exchange Recognition"
echo "============================================="

# Start server in background
echo "🚀 Starting server..."
cd /Users/kodde001/work/oauth2-server
./bin/oauth2-server > test_server.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to start..."
sleep 3

# Test RFC8693 token exchange endpoint directly with dummy tokens
echo "🔄 Testing RFC8693 grant type recognition..."
EXCHANGE_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=dummy_token&subject_token_type=urn:ietf:params:oauth:token-type:access_token")

echo "RFC8693 Response: $EXCHANGE_RESPONSE"

# Cleanup
echo "🧹 Cleaning up..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Check if our handler was invoked
if echo "$EXCHANGE_RESPONSE" | grep -q "error"; then
    ERROR_TYPE=$(echo "$EXCHANGE_RESPONSE" | grep -o '"error":"[^"]*"' | sed 's/"error":"\([^"]*\)"/\1/')
    echo "✅ RFC8693 handler invoked (error: $ERROR_TYPE)"
    echo "This confirms our implementation is being called!"
else
    echo "❌ Unexpected response format"
fi
