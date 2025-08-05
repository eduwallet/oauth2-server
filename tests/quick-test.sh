#!/bin/bash

# Quick test for the specific client registration issue
echo "Testing client registration with client_credentials + token_exchange (no redirect URIs)..."

# Start server in background
./oauth2-server &
SERVER_PID=$!
sleep 2

# Test the specific registration request that was failing
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Backend Service Client",
    "grant_types": [
      "client_credentials",
      "refresh_token", 
      "urn:ietf:params:oauth:grant-type:token-exchange"
    ],
    "response_types": ["code"],
    "scope": "profile email",
    "token_endpoint_auth_method": "client_secret_basic"
  }' \
  http://localhost:8080/oauth2/register

echo ""
echo "HTTP Status:"
curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Backend Service Client",
    "grant_types": [
      "client_credentials",
      "refresh_token", 
      "urn:ietf:params:oauth:grant-type:token-exchange"
    ],
    "response_types": ["code"],
    "scope": "profile email",
    "token_endpoint_auth_method": "client_secret_basic"
  }' \
  http://localhost:8080/oauth2/register

echo ""

# Clean up
kill $SERVER_PID 2>/dev/null || true
