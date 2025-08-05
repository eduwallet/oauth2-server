#!/bin/bash

echo "🧪 Testing OAuth2 Discovery Endpoints"
echo "===================================="

# Start server in background
./oauth2-server &
SERVER_PID=$!

# Wait for server to start
sleep 2

echo ""
echo "📋 Testing discovery endpoints:"
echo ""

# Test OAuth2 Authorization Server Discovery
echo "1️⃣  OAuth2 Authorization Server Discovery:"
echo "   GET /.well-known/oauth-authorization-server"
curl -s http://localhost:8080/.well-known/oauth-authorization-server | jq -r '.issuer, .authorization_endpoint, .token_endpoint' 2>/dev/null || curl -s http://localhost:8080/.well-known/oauth-authorization-server | head -3
echo ""

# Test OpenID Connect Discovery  
echo "2️⃣  OpenID Connect Discovery:"
echo "   GET /.well-known/openid-configuration"
curl -s http://localhost:8080/.well-known/openid-configuration | jq -r '.issuer, .authorization_endpoint, .token_endpoint' 2>/dev/null || curl -s http://localhost:8080/.well-known/openid-configuration | head -3
echo ""

# Test JWKS endpoint
echo "3️⃣  JSON Web Key Set:"
echo "   GET /.well-known/jwks.json"
curl -s http://localhost:8080/.well-known/jwks.json | jq -r '.keys | length' 2>/dev/null || curl -s http://localhost:8080/.well-known/jwks.json | head -3
echo ""

# Test main page
echo "4️⃣  Main page (should show discovery endpoints):"
echo "   GET /"
curl -s http://localhost:8080/ | grep -E "(well-known|Discovery)" | head -3
echo ""

# Cleanup
kill $SERVER_PID 2>/dev/null
echo "✅ Discovery endpoints test complete!"
