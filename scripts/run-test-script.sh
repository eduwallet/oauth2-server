#!/bin/bash

SCRIPT="$1"
TEST_DATABASE_TYPE="${2:-memory}"
OAUTH2_SERVER_URL="${3:-http://localhost:8080}"
TEST_USERNAME="${4:-john.doe}"
TEST_PASSWORD="${5:-password123}"
TEST_SCOPE="${6:-openid profile email offline_access}"
API_KEY="${7:-super-secure-random-api-key-change-in-production-32-chars-minimum}"

if echo "$SCRIPT" | grep -q "proxy"; then
    echo "🔄 Detected proxy test script - running script directly (it handles mock provider and server)"
    bash "tests/$SCRIPT"
    exit $?
else
    echo "🚀 Starting OAuth2 server in background..."
    DATABASE_TYPE="$TEST_DATABASE_TYPE" UPSTREAM_PROVIDER_URL="" ENABLE_TRUST_ANCHOR_API=true API_KEY="$API_KEY" ./bin/oauth2-server > server-test.log 2>&1 &
    echo $! > server.pid

    echo "⏳ Waiting for server to start..."
    sleep 5

    echo "🔍 Testing server health..."
    for i in 1 2 3 4 5; do
        if curl -f -s --max-time 5 "$OAUTH2_SERVER_URL/health" > /dev/null 2>&1; then
            echo "✅ Server is healthy"
            break
        else
            echo "⏳ Waiting for server to respond (attempt $i/5)..."
            sleep 2
            if [ $i -eq 5 ]; then
                echo "❌ Server failed to start after 5 attempts"
                cat server-test.log
                if [ -f server.pid ]; then kill $(cat server.pid) 2>/dev/null || true; rm -f server.pid; fi
                exit 1
            fi
        fi
    done

    echo "🔧 Setting up test certificates..."
    if [ -f "init-certs.sh" ]; then
        API_KEY="$API_KEY" OAUTH_URL="$OAUTH2_SERVER_URL" bash init-certs.sh
    else
        echo "⚠️  init-certs.sh not found, skipping certificate setup"
    fi

    echo "✅ Server is healthy, running $SCRIPT..."
    if TEST_USERNAME="$TEST_USERNAME" TEST_PASSWORD="$TEST_PASSWORD" TEST_SCOPE="$TEST_SCOPE" bash "tests/$SCRIPT"; then
        echo "✅ $SCRIPT passed"
        result=0
    else
        echo "❌ $SCRIPT failed"
        result=1
    fi

    if [ -f server.pid ]; then
        echo "🛑 Stopping server..."
        kill $(cat server.pid) 2>/dev/null || true
        rm -f server.pid
    fi

    echo "Server logs:"
    cat server-test.log 2>/dev/null || true
    rm -f server-test.log
    exit $result
fi