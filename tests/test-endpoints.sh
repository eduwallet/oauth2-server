#!/bin/bash

# OAuth2 Demo Test Script
echo "🔐 OAuth2 Server Test Script"
echo "=============================="

BASE_URL="http://localhost:8080"

echo ""
echo "🚀 Testing OAuth2 Endpoints..."

echo ""
echo "1. Testing Authorization Code Flow..."
echo "   Visit: $BASE_URL/oauth2/auth?response_type=code&client_id=frontend-app&redirect_uri=/callback&scope=openid+profile&state=random-state"

echo ""
echo "2. Testing Device Authorization Flow..."
echo "   POST to: $BASE_URL/device/code"
curl -s -X POST "$BASE_URL/device/code" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=frontend-client&scope=openid profile" | jq . 2>/dev/null || echo "   (Install jq for formatted output)"

echo ""
echo "3. Testing Client Credentials Flow..."
echo "   POST to: $BASE_URL/oauth2/token"
curl -s -X POST "$BASE_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "backend-client:backend-client-secret" \
  -d "grant_type=client_credentials&scope=api:read api:write" | jq . 2>/dev/null || echo "   (Install jq for formatted output)"

echo ""
echo "4. Testing Token Exchange Flow..."
echo "   First get an access token, then exchange it:"
echo "   POST to: $BASE_URL/oauth2/token"

echo ""
echo "📱 Web Interface:"
echo "   Main page: $BASE_URL"
echo "   Login: $BASE_URL/login"
echo "   Device verification: $BASE_URL/device/verify"

echo ""
echo "👥 Test Users (from config.yaml):"
echo "   - john.doe / password123"
echo "   - jane.smith / secret456"
echo "   - testuser / testpass"

echo ""
echo "🔧 OAuth2 Clients (from config.yaml):"
echo "   - frontend-app (Authorization Code)"
echo "   - backend-client (Client Credentials + Token Exchange)"
echo "   - frontend-client (Device Flow)"
echo "   - mobile-app (Authorization Code + Device Flow, Public)"
echo "   - smart-tv-app (Device Flow)"
