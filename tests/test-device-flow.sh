#!/bin/bash

# Device Code Flow Test Script
# ============================

echo "🔄 Testing Device Code Flow"
echo "============================"
echo ""

BASE_URL="http://localhost:8080"
DEVICE_ENDPOINT="$BASE_URL/device/code"
TOKEN_ENDPOINT="$BASE_URL/oauth2/token"

# Start server in background if not running
if ! curl -s "$BASE_URL/" >/dev/null 2>&1; then
    echo "Starting server..."
    ./oauth2-server &
    SERVER_PID=$!
    sleep 3
else
    echo "✅ Server is already running"
fi

echo ""

# Step 1: Request device code
echo "🧪 Step 1: Request Device Code"
echo "------------------------------"

CLIENT_ID="test-client"  # From your config.yaml

DEVICE_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&scope=profile email" \
  "$DEVICE_ENDPOINT")

echo "Device Response:"
echo "$DEVICE_RESPONSE" | jq . 2>/dev/null || echo "$DEVICE_RESPONSE"
echo ""

# Extract values
DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code' 2>/dev/null)
USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code' 2>/dev/null)
VERIFICATION_URI=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri' 2>/dev/null)
VERIFICATION_URI_COMPLETE=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri_complete' 2>/dev/null)

if [ "$DEVICE_CODE" = "null" ] || [ "$DEVICE_CODE" = "" ]; then
    echo "❌ Failed to get device code"
    exit 1
fi

echo "📋 Device Flow Information:"
echo "   Device Code: $DEVICE_CODE"
echo "   User Code: $USER_CODE"
echo "   Verification URI: $VERIFICATION_URI"
echo "   Complete URI: $VERIFICATION_URI_COMPLETE"
echo ""

# Step 2: Test polling before authorization (should be pending)
echo "🧪 Step 2: Test Token Request (Before Authorization)"
echo "---------------------------------------------------"

TOKEN_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=$CLIENT_ID" \
  "$TOKEN_ENDPOINT")

echo "Token Response (should be pending):"
echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"
echo ""

# Instructions for manual testing
echo "🎯 Manual Testing Instructions:"
echo "==============================="
echo ""
echo "1. Open this URL in your browser:"
echo "   $VERIFICATION_URI_COMPLETE"
echo ""
echo "2. You should see the user code: $USER_CODE pre-filled"
echo "3. Enter the user code if not pre-filled and submit"
echo "4. Login with credentials from your config.yaml (e.g., admin/admin)"
echo "5. You should see an authorization consent screen"
echo "6. Click 'Authorize Device' to complete the flow"
echo ""
echo "🔄 After authorization, run this command to get the token:"
echo "curl -X POST \\"
echo "  -H \"Content-Type: application/x-www-form-urlencoded\" \\"
echo "  -d \"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DEVICE_CODE&client_id=$CLIENT_ID\" \\"
echo "  \"$TOKEN_ENDPOINT\""
echo ""
echo "📖 Expected Flow:"
echo "   1. ✅ Device code request successful"
echo "   2. ⏳ Token request returns 'authorization_pending'"
echo "   3. 🔐 User visits URL and authenticates"
echo "   4. ✅ User authorizes device"
echo "   5. 🎫 Token request returns access token"

# Clean up
if [ ! -z "$SERVER_PID" ]; then
    echo ""
    echo "Press Enter to stop the server..."
    read
    kill $SERVER_PID 2>/dev/null || true
fi
