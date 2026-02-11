#!/bin/bash

# Test: Force Consent Interception in Proxy Mode
# This test validates that clients with ForceConsent=true show a local consent
# screen after upstream authentication but before completing authorization

set -e

echo "🧪 Force Consent Interception Test (Proxy Mode)"
echo "=============================================="

# Configuration
OAUTH2_SERVER_URL="${OAUTH2_SERVER_URL:-http://localhost:8080}"
MOCK_PROVIDER_URL="http://localhost:9999"
TEST_REDIRECT_URI="$OAUTH2_SERVER_URL/callback"
TEST_CLIENT_ID="force-consent-client-$(date +%s)"
TEST_CLIENT_SECRET="test-secret-$(date +%s)"
TEST_REDIRECT_URI="$OAUTH2_SERVER_URL/callback"
TEST_USERNAME="john.doe"
TEST_PASSWORD="password123"
TEST_SCOPE="openid profile email"
API_KEY="super-secure-random-api-key-change-in-production-32-chars-minimum"

echo ""
echo "📋 Test Configuration:"
echo "  OAuth2 Server: $OAUTH2_SERVER_URL"
echo "  Mock Provider: $MOCK_PROVIDER_URL"
echo "  Client ID: $TEST_CLIENT_ID"
echo "  Redirect URI: $TEST_REDIRECT_URI"
echo "  Test User: $TEST_USERNAME"
echo "  Scope: $TEST_SCOPE"
echo "  Force Consent: true"

echo ""
echo "🔍 Step 1: Verifying services are running..."

# Check mock provider
if curl -s -f "$MOCK_PROVIDER_URL/health" > /dev/null 2>&1; then
    echo "✅ Mock provider is running"
else
    echo "❌ Mock provider not responding at $MOCK_PROVIDER_URL"
    exit 1
fi

# Check OAuth2 server
if curl -s -f "$OAUTH2_SERVER_URL/health" > /dev/null 2>&1; then
    echo "✅ OAuth2 server is running"
else
    echo "❌ OAuth2 server not responding at $OAUTH2_SERVER_URL"
    exit 1
fi

echo ""
echo "🧪 Step 2: Registering client with ForceConsent=true..."

# Register a client with force_consent enabled
REGISTER_RESPONSE=$(curl -s -X POST "$OAUTH2_SERVER_URL/register" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"Force Consent Test Client\",
    \"grant_types\": [\"authorization_code\"],
    \"response_types\": [\"code\"],
    \"token_endpoint_auth_method\": \"none\",
    \"scope\": \"$TEST_SCOPE\",
    \"redirect_uris\": [\"$TEST_REDIRECT_URI\"],
    \"force_consent\": true,
    \"public\": true
  }")

echo "Client Registration Response: $REGISTER_RESPONSE"

# Extract client ID from registration response
CLIENT_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.client_id // empty' 2>/dev/null || echo "")

if [ -z "$CLIENT_ID" ]; then
    echo "❌ Failed to register test client"
    echo "Response: $REGISTER_RESPONSE"
    exit 1
fi

echo "✅ Client registered successfully"
echo "   Client ID: $CLIENT_ID"
echo "   Force Consent: true"

echo ""
echo "🧪 Step 3: Initiating authorization request..."

# Generate state (no PKCE for shorter URL)
STATE="test-state-$(date +%s)"

# Start authorization flow
AUTH_URL="$OAUTH2_SERVER_URL/authorize"

echo "📤 Authorization URL: $AUTH_URL with parameters"
echo "  response_type: code"
echo "  client_id: $CLIENT_ID"
echo "  redirect_uri: $TEST_REDIRECT_URI"
echo "  scope: $TEST_SCOPE"
echo "  state: $STATE"

# Make authorization request (this should redirect to upstream provider)
echo "Making request to: $AUTH_URL"

# First, check that we get a redirect
AUTH_CHECK=$(curl -s -w "HTTP_CODE:%{http_code}\n" \
  --connect-timeout 5 --max-time 10 \
  -G "$AUTH_URL" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$TEST_REDIRECT_URI" \
  --data-urlencode "scope=$TEST_SCOPE" \
  --data-urlencode "state=$STATE")

HTTP_CODE=$(echo "$AUTH_CHECK" | grep "HTTP_CODE:" | sed 's/HTTP_CODE://')

if [ "$HTTP_CODE" != "302" ]; then
    echo "❌ Expected redirect (302) but got: $HTTP_CODE"
    echo "Response: $AUTH_CHECK"
    exit 1
fi

echo "✅ Authorization endpoint returned redirect (302) as expected"

# Now follow redirects to get the final response (consent screen)
echo "Following redirects with curl..."
AUTH_RESPONSE=$(timeout 30 curl -s -L --connect-timeout 5 --max-time 15 \
  -G "$AUTH_URL" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$TEST_REDIRECT_URI" \
  --data-urlencode "scope=$TEST_SCOPE" \
  --data-urlencode "state=$STATE" \
  || echo "TIMEOUT")

if [ "$AUTH_RESPONSE" = "TIMEOUT" ]; then
    echo "❌ Curl command timed out"
    exit 1
fi

echo "✅ Curl command completed"

echo "Authorization response:"
echo "$AUTH_RESPONSE" | head -20
echo "---"

# Check for successful redirect and consent screen display
if echo "$AUTH_RESPONSE" | grep -q "Authorization Request"; then
    echo "✅ Authorization request successfully redirected and consent screen displayed"
else
    echo "❌ Authorization did not result in consent screen"
    echo "Response:"
    echo "$AUTH_RESPONSE" | head -20
    exit 1
fi

echo ""
echo "🧪 Step 4: Testing force consent interception..."

# The authorization response should directly contain the consent screen
# Check the response - it should contain the consent form HTML
if echo "$AUTH_RESPONSE" | grep -q "Authorization Request"; then
    echo "✅ Consent screen displayed after upstream authentication"
else
    echo "❌ Consent screen not displayed"
    echo "Response headers:"
    echo "$AUTH_RESPONSE" | head -20
    exit 1
fi

# Extract the HTML content to verify consent form details
AUTH_HTML=$(echo "$AUTH_RESPONSE" | sed -n '/<!DOCTYPE html>/,$p')

if echo "$AUTH_HTML" | grep -q "$CLIENT_ID"; then
    echo "✅ Consent form contains correct client ID"
else
    echo "❌ Consent form missing client ID"
    exit 1
fi

# Extract authorization code from the consent form HTML
AUTH_CODE=$(echo "$AUTH_HTML" | grep -o 'name="code" value="[^"]*"' | cut -d'"' -f4)

if [ -z "$AUTH_CODE" ]; then
    echo "❌ Could not extract authorization code from consent form"
    exit 1
fi

echo "✅ Consent form contains authorization code: ${AUTH_CODE:0:20}..."

echo ""
echo "🧪 Step 5: Simulating user consent approval..."

# Extract proxy_state from the consent form
PROXY_STATE=$(echo "$AUTH_HTML" | grep -o 'name="proxy_state" value="[^"]*"' | cut -d'"' -f4)

if [ -z "$PROXY_STATE" ]; then
    echo "❌ Could not extract proxy_state from consent form"
    exit 1
fi

echo "📋 Extracted proxy state: $PROXY_STATE"

# Submit consent approval
CONSENT_URL="$OAUTH2_SERVER_URL/auth/consent"
CONSENT_DATA="action=allow&client_id=$CLIENT_ID&code=$AUTH_CODE&proxy_state=$PROXY_STATE&state=$STATE"

echo "📤 Submitting consent approval to: $CONSENT_URL"

CONSENT_RESPONSE=$(curl -s -i -X POST "$CONSENT_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$CONSENT_DATA")

# Check for redirect to client redirect URI
CONSENT_REDIRECT=$(echo "$CONSENT_RESPONSE" | grep -i "location:" | head -1 | sed 's/.*location: *//' | tr -d '\r')

if [ -z "$CONSENT_REDIRECT" ]; then
    echo "❌ No redirect received after consent approval"
    echo "Response: $CONSENT_RESPONSE"
    exit 1
fi

echo "✅ Consent approval redirected to: $CONSENT_REDIRECT"

# Verify redirect contains authorization code and correct state
if echo "$CONSENT_REDIRECT" | grep -q "code=" && echo "$CONSENT_REDIRECT" | grep -q "state=$STATE"; then
    echo "✅ Redirect contains authorization code and correct state"
else
    echo "❌ Redirect missing code or incorrect state"
    echo "Expected state: $STATE"
    echo "Redirect: $CONSENT_REDIRECT"
    exit 1
fi

echo ""
echo "🧪 Step 6: Testing consent denial..."

# Start a new authorization flow for denial test
NEW_STATE="deny-state-$(date +%s)"

echo "📤 Starting new authorization flow for denial test"
NEW_AUTH_RESPONSE=$(timeout 30 curl -s -L --connect-timeout 5 --max-time 15 \
  -G "$AUTH_URL" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$TEST_REDIRECT_URI" \
  --data-urlencode "scope=$TEST_SCOPE" \
  --data-urlencode "state=$NEW_STATE" \
  || echo "TIMEOUT")

if [ "$NEW_AUTH_RESPONSE" = "TIMEOUT" ]; then
    echo "❌ Curl command timed out for denial test"
    exit 1
fi

echo "✅ New authorization flow completed"

# Check that consent screen is shown
if echo "$NEW_AUTH_RESPONSE" | grep -q "Authorization Request"; then
    echo "✅ Consent screen displayed for denial test"
else
    echo "❌ Consent screen not displayed for denial test"
    echo "Response:"
    echo "$NEW_AUTH_RESPONSE" | head -20
    exit 1
fi

# Extract HTML and proxy state for denial
NEW_AUTH_HTML=$(echo "$NEW_AUTH_RESPONSE" | sed -n '/<!DOCTYPE html>/,$p')
NEW_PROXY_STATE=$(echo "$NEW_AUTH_HTML" | grep -o 'name="proxy_state" value="[^"]*"' | cut -d'"' -f4)
NEW_AUTH_CODE=$(echo "$NEW_AUTH_HTML" | grep -o 'name="code" value="[^"]*"' | cut -d'"' -f4)

# Submit consent denial
DENY_DATA="action=deny&client_id=$CLIENT_ID&code=$NEW_AUTH_CODE&proxy_state=$NEW_PROXY_STATE&state=$NEW_STATE"

echo "📤 Submitting consent denial"

DENY_RESPONSE=$(curl -s -i -X POST "$CONSENT_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$DENY_DATA")

# Check denial response
DENY_REDIRECT_URL=$(echo "$DENY_RESPONSE" | grep -i "location:" | head -1 | sed 's/.*location: *//' | tr -d '\r')
if [[ "$DENY_REDIRECT_URL" == *"$TEST_REDIRECT_URI"* ]] && [[ "$DENY_REDIRECT_URL" == *"error=access_denied"* ]]; then
    echo "✅ Consent denial successful - redirected to client with access_denied error"
else
    echo "❌ Consent denial failed - unexpected redirect: $DENY_REDIRECT_URL"
    echo "Full denial response:"
    echo "$DENY_RESPONSE"
    exit 1
fi

echo ""
echo "🎉 All tests passed!"
echo "✅ Force consent interception working correctly"
echo "✅ Consent screen displayed after upstream authentication"
echo "✅ Consent approval completes authorization flow"
echo "✅ Consent denial properly rejects access"

exit 0