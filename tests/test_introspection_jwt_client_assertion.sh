#!/bin/bash

# Test script for JWT Client Assertion authentication in token introspection
# This test validates RFC 7662 introspection with JWT client assertion (RFC 7523/8725)

set -e

# Configuration
OAUTH2_SERVER_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"
CLIENT_ID="test-introspect-attestation-client"
SCOPE="openid profile"
AUDIENCE="${OAUTH2_SERVER_URL}/token"
API_KEY="${API_KEY:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

echo "🧪 Introspection with JWT Client Assertion Test"
echo "==============================================="
echo "Testing RFC 7662 introspection with JWT client assertion authentication"
echo ""

# Function to generate a mock JWT attestation token
generate_mock_jwt() {
    local client_id="$1"
    local audience="$2"

    # Create JWT header
    local header='{"alg":"ES256","typ":"JWT"}'
    local header_b64=$(echo -n "$header" | base64 | tr -d '=' | tr '/+' '_-')

    # Create JWT payload with attestation claims
    local now=$(date +%s)
    local exp=$((now + 3600))
    local payload='{
        "iss":"test-attestor",
        "sub":"'"$client_id"'",
        "aud":"'"$audience"'",
        "exp":'"$exp"',
        "iat":'"$now"',
        "jti":"test-nonce-123",
        "att_type":"hsm",
        "att_level":"high",
        "att_hardware_backed":true,
        "att_device_integrity":"verified",
        "cnf":{"jwk":{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtmUAmh9K8X1GYTAJwTDFbU4Y6iWJ","e":"AQAB"}}
    }'
    local payload_b64=$(echo -n "$payload" | base64 | tr -d '=' | tr '/+' '_-')

    # Create signature (simplified for testing - in real implementation this would be properly signed)
    local signature="simplified_signature_for_testing_purposes_only"

    echo "${header_b64}.${payload_b64}.${signature}"
}

# Function to make curl requests with error handling
make_request() {
    local method="$1"
    local url="$2"
    local data="$3"
    local extra_headers="$4"

    local curl_cmd="curl -s -X $method"

    # Add API key header if this is a registration request
    if [[ "$url" == *"/register"* ]]; then
        curl_cmd="$curl_cmd -H 'X-API-Key: $API_KEY' -H 'Content-Type: application/json'"
    else
        curl_cmd="$curl_cmd -H 'Content-Type: application/x-www-form-urlencoded'"
    fi

    # Add any extra headers
    if [ -n "$extra_headers" ]; then
        curl_cmd="$curl_cmd -H '$extra_headers'"
    fi

    if [ -n "$data" ]; then
        curl_cmd="$curl_cmd -d '$data'"
    fi

    curl_cmd="$curl_cmd '$url'"

    echo "🔍 Making request: $curl_cmd" >&2
    eval "$curl_cmd"
}

echo "🧪 Step 1: Registering attestation-enabled client"

# Register client with attestation configuration
REGISTER_DATA='{
    "client_id": "'"$CLIENT_ID"'",
    "public": true,
    "token_endpoint_auth_method": "attest_jwt_client_auth",
    "grant_types": ["client_credentials"],
    "scope": "'"$SCOPE"'",
    "attestation_config": {
        "client_id": "'"$CLIENT_ID"'",
        "allowed_methods": ["attest_jwt_client_auth"],
        "trust_anchors": ["hsm_ca"],
        "required_level": "high"
    }
}'

echo "Registration request data: $REGISTER_DATA"

REGISTER_RESPONSE=$(make_request "POST" "$OAUTH2_SERVER_URL/register" "$REGISTER_DATA")

if [ $? -ne 0 ]; then
    echo "❌ Client registration failed"
    exit 1
fi

echo "Registration response: $REGISTER_RESPONSE"

# Extract client_id from response to confirm registration
REGISTERED_CLIENT_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.client_id // empty')
if [ -z "$REGISTERED_CLIENT_ID" ] || [ "$REGISTERED_CLIENT_ID" = "null" ]; then
    echo "❌ Failed to extract client_id from registration response"
    exit 1
fi

echo "✅ Attestation client registered successfully"
echo ""

echo "🧪 Step 2: Creating mock JWT attestation token"

JWT_ASSERTION=$(generate_mock_jwt "$CLIENT_ID" "$AUDIENCE")

if [ -z "$JWT_ASSERTION" ]; then
    echo "❌ Failed to generate JWT assertion"
    exit 1
fi

echo "✅ Mock JWT attestation token created"
echo "JWT: ${JWT_ASSERTION:0:50}..."
echo ""

echo "🧪 Step 3: Getting access token with JWT client assertion"

# Request access token using JWT client assertion
TOKEN_DATA="grant_type=client_credentials&client_id=$CLIENT_ID&scope=$SCOPE&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=$JWT_ASSERTION"

echo "Token request data: $TOKEN_DATA"

TOKEN_RESPONSE=$(make_request "POST" "$OAUTH2_SERVER_URL/token" "$TOKEN_DATA")

if [ $? -ne 0 ]; then
    echo "❌ Token request failed"
    exit 1
fi

echo "Token response: $TOKEN_RESPONSE"

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo "❌ Failed to extract access_token from token response"
    exit 1
fi

echo "✅ Access token obtained successfully"
echo "Access Token: ${ACCESS_TOKEN:0:50}..."
echo ""

echo "🧪 Step 4: Testing introspection with JWT client assertion"

# Perform introspection using JWT client assertion
INTROSPECT_DATA="token=$ACCESS_TOKEN&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=$JWT_ASSERTION"

echo "Introspection request data: $INTROSPECT_DATA"

INTROSPECT_RESPONSE=$(make_request "POST" "$OAUTH2_SERVER_URL/introspect" "$INTROSPECT_DATA")

if [ $? -ne 0 ]; then
    echo "❌ Introspection request failed"
    exit 1
fi

echo "Introspection response: $INTROSPECT_RESPONSE"

# Validate introspection response
ACTIVE=$(echo "$INTROSPECT_RESPONSE" | jq -r '.active // empty')
if [ "$ACTIVE" != "true" ]; then
    echo "❌ Token introspection failed - token not active"
    exit 1
fi

CLIENT_ID_FROM_INTROSPECT=$(echo "$INTROSPECT_RESPONSE" | jq -r '.client_id // empty')
if [ "$CLIENT_ID_FROM_INTROSPECT" != "$CLIENT_ID" ]; then
    echo "❌ Token introspection failed - wrong client_id"
    exit 1
fi

SCOPE_FROM_INTROSPECT=$(echo "$INTROSPECT_RESPONSE" | jq -r '.scope // empty')
if [ "$SCOPE_FROM_INTROSPECT" != "$SCOPE" ]; then
    echo "❌ Token introspection failed - wrong scope"
    exit 1
fi

echo "✅ Introspection with JWT client assertion successful!"
echo "✅ Attestation client authenticated using JWT assertion"
echo "✅ Token introspection completed successfully"
echo "Client ID: $CLIENT_ID_FROM_INTROSPECT"
echo "Scope: $SCOPE_FROM_INTROSPECT"
echo ""

echo "📊 Introspection JWT Client Assertion Test Results Summary"
echo "==========================================================="
echo "Step 1 (Client registration): ✅ PASS"
echo "Step 2 (JWT creation): ✅ PASS"
echo "Step 3 (Token acquisition): ✅ PASS"
echo "Step 4 (JWT introspection): ✅ PASS"
echo ""
echo "✅ Introspection with JWT client assertion tests PASSED!"
echo ""
echo "🎉 JWT client assertion authentication works for token introspection!"
echo "   ✅ Attestation client can authenticate to introspection endpoint"
echo "   ✅ JWT client assertions processed correctly"
echo "   ✅ Token introspection with attestation-based auth functional"