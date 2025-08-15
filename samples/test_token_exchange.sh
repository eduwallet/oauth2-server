#!/bin/bash
# filepath: /Users/harry/projects/oauth2-server/samples/token_exchange_demo.sh

set -e

SERVER="http://localhost:8080"
FRONTEND_ID="frontend-app"
FRONTEND_SECRET="frontend-secret"
BACKEND_ID="backend-client"
BACKEND_SECRET="backend-client-secret"
USER="john.doe"
PASS="password123"
AUDIENCE="backend-client"

echo "Step 1: Authenticate USER via Authorization Code Flow"
echo "Visit: $SERVER/auth?client_id=$FRONTEND_ID&response_type=code&scope=openid%20profile%20email%20offline_access%20api:read&redirect_uri=/callback"
echo "Login as $USER / $PASS, consent, and copy the code from /callback?code=..."
read -p "Paste authorization code: " AUTH_CODE

echo "Step 2: frontend-app obtains access token + refresh token"
TOKENS=$(curl -s -X POST "$SERVER/token" \
  -u "$FRONTEND_ID:$FRONTEND_SECRET" \
  -d grant_type=authorization_code \
  -d code="$AUTH_CODE" \
  -d redirect_uri="/callback")
echo "$TOKENS" | jq .
REFRESH_TOKEN=$(echo "$TOKENS" | jq -r .refresh_token)

echo "Step 3: frontend-app refreshes tokens"
TOKENS2=$(curl -s -X POST "$SERVER/token" \
  -u "$FRONTEND_ID:$FRONTEND_SECRET" \
  -d grant_type=refresh_token \
  -d refresh_token="$REFRESH_TOKEN")
echo "$TOKENS2" | jq .
REFRESH_TOKEN2=$(echo "$TOKENS2" | jq -r .refresh_token)

echo "Step 4: frontend-app initiates token exchange (requesting refresh_token for backend-client)"
EXCHANGE=$(curl -s -X POST "$SERVER/token" \
  -u "$FRONTEND_ID:$FRONTEND_SECRET" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$REFRESH_TOKEN2" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:refresh_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:refresh_token \
  -d audience="$AUDIENCE")
echo "$EXCHANGE" | jq .
EXCH_REFRESH=$(echo "$EXCHANGE" | jq -r .refresh_token)

echo "Step 5: Handover exchanged refresh token to backend-client"
echo "Backend-client received refresh token: $EXCH_REFRESH"

echo "Step 6: backend-client uses received token to refresh"
BACKEND_TOKENS=$(curl -s -X POST "$SERVER/token" \
  -u "$BACKEND_ID:$BACKEND_SECRET" \
  -d grant_type=refresh_token \
  -d refresh_token="$EXCH_REFRESH")
echo "$BACKEND_TOKENS" | jq .
BACKEND_ACCESS=$(echo "$BACKEND_TOKENS" | jq -r .access_token)
BACKEND_REFRESH=$(echo "$BACKEND_TOKENS" | jq -r .refresh_token)

echo "Step 7: backend-client validates tokens via introspect"
INTROSPECT=$(curl -s -X POST "$SERVER/introspect" \
  -u "$BACKEND_ID:$BACKEND_SECRET" \
  -d token="$BACKEND_ACCESS")
echo "$INTROSPECT" | jq .

echo "Step 8: backend-client requests userinfo"
USERINFO=$(curl -s -X GET "$SERVER/userinfo" \
  -H "Authorization: Bearer $BACKEND_ACCESS")
echo "$USERINFO" | jq .

echo "✅ All steps completed successfully."