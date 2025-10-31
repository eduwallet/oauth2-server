#!/bin/bash

echo "=== Testing Scope Handling in Authorization Code Flow ==="

# Generate PKCE parameters
CODE_VERIFIER=$(python3 -c "
import base64
import hashlib
import secrets
verifier = secrets.token_urlsafe(64)[:64]
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
print(verifier)
")
CODE_CHALLENGE=$(python3 -c "
import base64
import hashlib
verifier='$CODE_VERIFIER'
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
print(challenge)
")

echo "Generated PKCE - Verifier: ${CODE_VERIFIER:0:20}..., Challenge: $CODE_CHALLENGE"

# Test 1: No scope parameter provided (should default to openid)
echo ""
echo "Test 1: No scope parameter (should default to openid)"
AUTH_CODE_1=$(curl -s -L "http://localhost:8080/auth?response_type=code&client_id=web-app-client&redirect_uri=http://localhost:8080/callback&state=test1&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john.doe&password=password123" | grep -o 'code=[^&]*' | cut -d'=' -f2)

if [ -z "$AUTH_CODE_1" ]; then
    echo "❌ Failed to get authorization code for test 1"
    exit 1
fi

echo "✅ Got authorization code: ${AUTH_CODE_1:0:30}..."

# Exchange for token
TOKEN_RESPONSE_1=$(curl -s -X POST "http://localhost:8080/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'web-app-client:web-app-secret' | base64)" \
  -d "grant_type=authorization_code&code=$AUTH_CODE_1&redirect_uri=http://localhost:8080/callback&code_verifier=$CODE_VERIFIER")

ACCESS_TOKEN_1=$(echo "$TOKEN_RESPONSE_1" | jq -r '.access_token' 2>/dev/null)
if [ "$ACCESS_TOKEN_1" = "null" ] || [ -z "$ACCESS_TOKEN_1" ]; then
    echo "❌ Failed to get access token for test 1"
    echo "Response: $TOKEN_RESPONSE_1"
    exit 1
fi

echo "✅ Got access token: ${ACCESS_TOKEN_1:0:30}..."

# Test UserInfo
USERINFO_RESPONSE_1=$(curl -s -X GET "http://localhost:8080/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN_1" \
  -w "HTTP_STATUS:%{http_code}")

HTTP_STATUS_1=$(echo "$USERINFO_RESPONSE_1" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
RESPONSE_BODY_1=$(echo "$USERINFO_RESPONSE_1" | sed 's/HTTP_STATUS:[0-9]*$//')

echo "UserInfo Status: $HTTP_STATUS_1"
if [ "$HTTP_STATUS_1" = "200" ]; then
    echo "✅ UserInfo works with default openid scope"
    echo "Response: $RESPONSE_BODY_1"
else
    echo "❌ UserInfo failed: $RESPONSE_BODY_1"
fi

# Test 2: Explicit scope parameter provided
echo ""
echo "Test 2: Explicit scope parameter (openid profile email)"
AUTH_CODE_2=$(curl -s -L "http://localhost:8080/auth?response_type=code&client_id=web-app-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email&state=test2&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john.doe&password=password123" | grep -o 'code=[^&]*' | cut -d'=' -f2)

if [ -z "$AUTH_CODE_2" ]; then
    echo "❌ Failed to get authorization code for test 2"
    exit 1
fi

echo "✅ Got authorization code: ${AUTH_CODE_2:0:30}..."

# Exchange for token
TOKEN_RESPONSE_2=$(curl -s -X POST "http://localhost:8080/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'web-app-client:web-app-secret' | base64)" \
  -d "grant_type=authorization_code&code=$AUTH_CODE_2&redirect_uri=http://localhost:8080/callback&code_verifier=$CODE_VERIFIER")

ACCESS_TOKEN_2=$(echo "$TOKEN_RESPONSE_2" | jq -r '.access_token' 2>/dev/null)
if [ "$ACCESS_TOKEN_2" = "null" ] || [ -z "$ACCESS_TOKEN_2" ]; then
    echo "❌ Failed to get access token for test 2"
    echo "Response: $TOKEN_RESPONSE_2"
    exit 1
fi

echo "✅ Got access token: ${ACCESS_TOKEN_2:0:30}..."

# Test UserInfo
USERINFO_RESPONSE_2=$(curl -s -X GET "http://localhost:8080/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN_2" \
  -w "HTTP_STATUS:%{http_code}")

HTTP_STATUS_2=$(echo "$USERINFO_RESPONSE_2" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
RESPONSE_BODY_2=$(echo "$USERINFO_RESPONSE_2" | sed 's/HTTP_STATUS:[0-9]*$//')

echo "UserInfo Status: $HTTP_STATUS_2"
if [ "$HTTP_STATUS_2" = "200" ]; then
    echo "✅ UserInfo works with explicit scopes"
    echo "Response: $RESPONSE_BODY_2"
else
    echo "❌ UserInfo failed: $RESPONSE_BODY_2"
fi

# Test 3: Token introspection to verify scopes
echo ""
echo "Test 3: Token introspection to verify scopes"

# Introspect token from test 1 (default scope)
INTROSPECT_1=$(curl -s -X POST "http://localhost:8080/oauth/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'web-app-client:web-app-secret' | base64)" \
  -d "token=$ACCESS_TOKEN_1")

SCOPE_1=$(echo "$INTROSPECT_1" | jq -r '.scope' 2>/dev/null)
echo "Token 1 scope: $SCOPE_1"
if [ "$SCOPE_1" = "openid" ]; then
    echo "✅ Token 1 has correct default scope"
else
    echo "❌ Token 1 scope incorrect: $SCOPE_1"
fi

# Introspect token from test 2 (explicit scopes)
INTROSPECT_2=$(curl -s -X POST "http://localhost:8080/oauth/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'web-app-client:web-app-secret' | base64)" \
  -d "token=$ACCESS_TOKEN_2")

SCOPE_2=$(echo "$INTROSPECT_2" | jq -r '.scope' 2>/dev/null)
echo "Token 2 scope: $SCOPE_2"
if [[ "$SCOPE_2" == *"openid"* ]] && [[ "$SCOPE_2" == *"profile"* ]] && [[ "$SCOPE_2" == *"email"* ]]; then
    echo "✅ Token 2 has correct explicit scopes"
else
    echo "❌ Token 2 scope incorrect: $SCOPE_2"
fi

echo ""
echo "=== Test Summary ==="
echo "✅ Test 1 (default scope): $([ "$HTTP_STATUS_1" = "200" ] && echo "PASS" || echo "FAIL")"
echo "✅ Test 2 (explicit scopes): $([ "$HTTP_STATUS_2" = "200" ] && echo "PASS" || echo "FAIL")"
echo "✅ Scope verification: $([ "$SCOPE_1" = "openid" ] && [[ "$SCOPE_2" == *"openid"* ]] && [[ "$SCOPE_2" == *"profile"* ]] && [[ "$SCOPE_2" == *"email"* ]] && echo "PASS" || echo "FAIL")"

echo ""
echo "=== Tests completed ==="
