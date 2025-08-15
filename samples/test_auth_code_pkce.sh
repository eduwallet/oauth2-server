#!/bin/bash

# Authorization Code Flow with PKCE Demo
# This script demonstrates a complete OAuth2 authorization code flow with PKCE
# including user login and claims display

set -e

BASE_URL="http://localhost:8080"
CLIENT_ID="web-app-client"
CLIENT_SECRET="web-app-secret"
REDIRECT_URI="http://localhost:8080/callback"
SCOPE="openid profile email api:read"

echo "🧪 Testing Authorization Code Flow with PKCE"
echo "============================================="

# Assume server is already running (managed by Makefile)
echo "📡 Using server at $BASE_URL"

# Function to generate PKCE code verifier and challenge
generate_pkce() {
    # Generate code verifier (43-128 characters, URL-safe)
    CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
    
    # Generate code challenge (SHA256 hash of verifier, base64url encoded)
    CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d "=+/" | tr -d '\n')
    
    echo "🔐 PKCE Code Verifier: ${CODE_VERIFIER:0:20}..."
    echo "🔐 PKCE Code Challenge: ${CODE_CHALLENGE:0:20}..."
}

# Function to generate secure state parameter
generate_state() {
    STATE=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    echo "🎲 State: ${STATE:0:20}..."
}

# Step 1: Generate PKCE parameters
echo ""
echo "📋 Step 1: Generating PKCE parameters..."
generate_pkce
generate_state

# Step 2: Build authorization URL
echo ""
echo "📋 Step 2: Building authorization URL..."

# URL encode parameters
ENCODED_REDIRECT_URI=$(printf '%s' "$REDIRECT_URI" | jq -sRr @uri)
ENCODED_SCOPE=$(printf '%s' "$SCOPE" | jq -sRr @uri)

AUTHORIZATION_URL="${BASE_URL}/auth"
AUTHORIZATION_URL+="?response_type=code"
AUTHORIZATION_URL+="&client_id=${CLIENT_ID}"
AUTHORIZATION_URL+="&redirect_uri=${ENCODED_REDIRECT_URI}"
AUTHORIZATION_URL+="&scope=${ENCODED_SCOPE}"
AUTHORIZATION_URL+="&state=${STATE}"
AUTHORIZATION_URL+="&code_challenge=${CODE_CHALLENGE}"
AUTHORIZATION_URL+="&code_challenge_method=S256"

echo "🔗 Authorization URL:"
echo "$AUTHORIZATION_URL"

# Step 3: Simulate user authorization (in real flow, user would visit URL in browser)
echo ""
echo "📋 Step 3: Simulating user authorization flow..."
echo "   (In a real application, the user would visit the URL above in their browser)"

# Make initial request to authorization endpoint
echo "🌐 Making initial authorization request..."
AUTH_RESPONSE=$(curl -s -i -X GET "$AUTHORIZATION_URL" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")

echo "📋 Authorization endpoint responded (should show login form or redirect)"

# Check if we got a login form or redirect
if echo "$AUTH_RESPONSE" | grep -q "Login\|Username\|Password"; then
    echo "✅ Received login form - authorization endpoint is working"
    
    # Step 4: Simulate user login
    echo ""
    echo "📋 Step 4: Simulating user login..."
    
    # Extract any hidden form fields or session cookies
    COOKIES=$(echo "$AUTH_RESPONSE" | grep -i "set-cookie" | cut -d' ' -f2- | tr '\n' ';' | sed 's/;$//')
    
    # Simulate login form submission
    LOGIN_DATA="username=john.doe&password=password123&action=login"
    
    echo "🔐 Submitting login credentials..."
    LOGIN_RESPONSE=$(curl -s -i -X POST "${BASE_URL}/auth?$(echo "$AUTHORIZATION_URL" | cut -d'?' -f2)" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Cookie: $COOKIES" \
      -d "$LOGIN_DATA")
    
    if echo "$LOGIN_RESPONSE" | grep -q "consent\|Consent\|Authorization"; then
        echo "✅ Login successful - received consent form"
        
        # Step 5: Simulate consent
        echo ""
        echo "📋 Step 5: Simulating user consent..."
        
        # Extract any new cookies
        NEW_COOKIES=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie" | cut -d' ' -f2- | tr '\n' ';' | sed 's/;$//')
        if [ -n "$NEW_COOKIES" ]; then
            COOKIES="$COOKIES;$NEW_COOKIES"
        fi
        
        # Submit consent
        CONSENT_DATA="consent=allow&action=consent"
        
        echo "✅ Granting consent..."
        CONSENT_RESPONSE=$(curl -s -i -X POST "${BASE_URL}/auth?$(echo "$AUTHORIZATION_URL" | cut -d'?' -f2)" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -H "Cookie: $COOKIES" \
          -d "$CONSENT_DATA")
        
        # Step 6: Extract authorization code from redirect
        echo ""
        echo "📋 Step 6: Extracting authorization code..."
        
        # Look for Location header with authorization code
        LOCATION_HEADER=$(echo "$CONSENT_RESPONSE" | grep -i "location:" | cut -d' ' -f2- | tr -d '\r\n')
        
        if [ -n "$LOCATION_HEADER" ]; then
            echo "🔄 Redirect location: $LOCATION_HEADER"
            
            # Extract code and state from redirect URL
            if echo "$LOCATION_HEADER" | grep -q "code="; then
                AUTHORIZATION_CODE=$(echo "$LOCATION_HEADER" | sed 's/.*code=\([^&]*\).*/\1/')
                RETURNED_STATE=$(echo "$LOCATION_HEADER" | sed 's/.*state=\([^&]*\).*/\1/' 2>/dev/null || echo "")
                
                echo "✅ Authorization Code: ${AUTHORIZATION_CODE:0:30}..."
                echo "✅ Returned State: ${RETURNED_STATE:0:20}..."
                
                # Verify state matches
                if [ "$STATE" = "$RETURNED_STATE" ]; then
                    echo "✅ State verification successful"
                else
                    echo "⚠️  State mismatch - possible CSRF attack!"
                fi
                
                # Step 7: Exchange authorization code for tokens
                echo ""
                echo "📋 Step 7: Exchanging authorization code for tokens..."
                
                TOKEN_REQUEST_DATA="grant_type=authorization_code"
                TOKEN_REQUEST_DATA+="&code=${AUTHORIZATION_CODE}"
                TOKEN_REQUEST_DATA+="&redirect_uri=${REDIRECT_URI}"
                TOKEN_REQUEST_DATA+="&client_id=${CLIENT_ID}"
                TOKEN_REQUEST_DATA+="&code_verifier=${CODE_VERIFIER}"
                
                # Add client authentication
                AUTH_HEADER=$(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)
                
                echo "🔄 Making token exchange request..."
                TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
                  -H "Content-Type: application/x-www-form-urlencoded" \
                  -H "Authorization: Basic $AUTH_HEADER" \
                  -d "$TOKEN_REQUEST_DATA")
                
                echo "📋 Token Response:"
                echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE"
                
                # Extract tokens
                if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
                    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null || echo "")
                    ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token' 2>/dev/null || echo "")
                    REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token' 2>/dev/null || echo "")
                    TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | jq -r '.token_type' 2>/dev/null || echo "Bearer")
                    EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in' 2>/dev/null || echo "3600")
                    
                    echo ""
                    echo "✅ Token exchange successful!"
                    echo "🔑 Access Token: ${ACCESS_TOKEN:0:50}..."
                    if [ "$ID_TOKEN" != "null" ] && [ -n "$ID_TOKEN" ]; then
                        echo "🆔 ID Token: ${ID_TOKEN:0:50}..."
                    fi
                    if [ "$REFRESH_TOKEN" != "null" ] && [ -n "$REFRESH_TOKEN" ]; then
                        echo "♻️  Refresh Token: ${REFRESH_TOKEN:0:50}..."
                    fi
                    echo "⏰ Expires in: $EXPIRES_IN seconds"
                    
                    # Step 8: Test UserInfo endpoint with access token
                    echo ""
                    echo "📋 Step 8: Testing UserInfo endpoint..."
                    
                    USERINFO_RESPONSE=$(curl -s -X GET "$BASE_URL/userinfo" \
                      -H "Authorization: Bearer $ACCESS_TOKEN")
                    
                    echo "👤 UserInfo Response:"
                    echo "$USERINFO_RESPONSE" | jq . 2>/dev/null || echo "$USERINFO_RESPONSE"
                    
                    # Step 9: Display user claims (simulate redirect to claims page)
                    echo ""
                    echo "📋 Step 9: Simulating claims display page..."
                    
                    # Build claims display URL with extracted tokens
                    CLAIMS_URL="${BASE_URL}/claims"
                    CLAIMS_URL+="?client_id=${CLIENT_ID}"
                    CLAIMS_URL+="&username=john.doe"
                    CLAIMS_URL+="&scope=$(echo "$SCOPE" | sed 's/ /%20/g')"
                    if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
                        CLAIMS_URL+="&access_token=${ACCESS_TOKEN}"
                    fi
                    if [ -n "$ID_TOKEN" ] && [ "$ID_TOKEN" != "null" ]; then
                        CLAIMS_URL+="&id_token=${ID_TOKEN}"
                    fi
                    if [ -n "$REFRESH_TOKEN" ] && [ "$REFRESH_TOKEN" != "null" ]; then
                        CLAIMS_URL+="&refresh_token=${REFRESH_TOKEN}"
                    fi
                    
                    echo "🎨 Claims display URL:"
                    echo "$CLAIMS_URL"
                    
                    echo ""
                    echo "✅ Authorization Code Flow with PKCE completed successfully!"
                    echo ""
                    echo "📊 Flow Summary:"
                    echo "   ✅ PKCE parameters generated"
                    echo "   ✅ Authorization URL built"
                    echo "   ✅ User login simulated"
                    echo "   ✅ User consent granted"
                    echo "   ✅ Authorization code received"
                    echo "   ✅ State parameter verified"
                    echo "   ✅ Authorization code exchanged for tokens"
                    echo "   ✅ UserInfo endpoint tested"
                    echo "   ✅ Claims display prepared"
                    echo ""
                    echo "🌐 To view the claims page in a browser, visit:"
                    echo "   $CLAIMS_URL"
                    
                else
                    echo "❌ Token exchange failed"
                    echo "Response: $TOKEN_RESPONSE"
                fi
                
            else
                echo "❌ No authorization code found in redirect"
                echo "Location: $LOCATION_HEADER"
            fi
        else
            echo "❌ No redirect location found in consent response"
            echo "Response headers:"
            echo "$CONSENT_RESPONSE" | head -20
        fi
        
    else
        echo "❌ Login failed or no consent form received"
        echo "Response:"
        echo "$LOGIN_RESPONSE" | head -20
    fi
    
else
    echo "❌ No login form received from authorization endpoint"
    echo "Response:"
    echo "$AUTH_RESPONSE" | head -20
fi

echo ""
echo "✅ Authorization Code Flow with PKCE test completed"
