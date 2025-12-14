#!/bin/bash

# Test configuration - use environment variables with defaults
TEST_USERNAME="${TEST_USERNAME:-john.doe}"
TEST_PASSWORD="${TEST_PASSWORD:-password123}"
TEST_SCOPE="${TEST_SCOPE:-openid profile email}"

echo "🧪 Testing Device Code Validation"
echo "================================="

# Test invalid user code verification
echo ""
echo "📝 Testing invalid user code validation..."
echo "Attempting to verify with invalid user code 'INVALID123'"

curl -s -X POST ${OAUTH2_SERVER_URL:-http://localhost:8080}/device/verify \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_code=INVALID123&username=admin&password=password" \
  | grep -q "Invalid User Code" && echo "✅ Invalid user code properly detected" || echo "❌ Invalid user code validation failed"

echo ""
echo "🎯 Testing expired/non-existent user code consent..."
echo "Attempting consent with invalid user code 'EXPIRED456'"

curl -s -X POST ${OAUTH2_SERVER_URL:-http://localhost:8080}/device/consent \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_code=EXPIRED456&username=admin&action=approve" \
  | grep -q "Invalid User Code" && echo "✅ Invalid user code in consent properly detected" || echo "❌ Invalid user code in consent validation failed"

echo ""
echo "✅ Validation tests completed!"
