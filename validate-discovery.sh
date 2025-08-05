#!/bin/bash

# Simple Discovery Endpoints Validation
# =====================================

echo "🔍 Discovery Endpoints Validation"
echo "================================="
echo ""

# Function to test an endpoint
test_endpoint() {
    local name="$1"
    local url="$2"
    local expected_field="$3"
    
    echo -n "Testing $name... "
    
    response=$(curl -s -w "%{http_code}" "$url" -o /tmp/discovery_test.json)
    http_code="${response: -3}"
    
    if [ "$http_code" = "200" ]; then
        if command -v jq >/dev/null 2>&1; then
            if jq -e ".$expected_field" /tmp/discovery_test.json >/dev/null 2>&1; then
                echo "✅ OK"
                return 0
            else
                echo "❌ FAIL (missing $expected_field)"
                return 1
            fi
        else
            echo "✅ OK (HTTP 200)"
            return 0
        fi
    else
        echo "❌ FAIL (HTTP $http_code)"
        return 1
    fi
}

# Test if server is running
if ! curl -s http://localhost:8080/ >/dev/null 2>&1; then
    echo "❌ Server not running on localhost:8080"
    echo "   Start with: make run"
    exit 1
fi

echo "✅ Server is running"
echo ""

# Test discovery endpoints
total_tests=0
passed_tests=0

# OAuth2 Discovery
((total_tests++))
if test_endpoint "OAuth2 Discovery" "http://localhost:8080/.well-known/oauth-authorization-server" "issuer"; then
    ((passed_tests++))
fi

# OpenID Discovery  
((total_tests++))
if test_endpoint "OpenID Discovery" "http://localhost:8080/.well-known/openid-configuration" "issuer"; then
    ((passed_tests++))
fi

# JWKS
((total_tests++))
if test_endpoint "JWKS" "http://localhost:8080/.well-known/jwks.json" "keys"; then
    ((passed_tests++))
fi

echo ""
echo "Results: $passed_tests/$total_tests tests passed"

if [ "$passed_tests" = "$total_tests" ]; then
    echo "🎉 All discovery endpoints are working!"
    exit 0
else
    echo "⚠️  Some endpoints failed"
    exit 1
fi
