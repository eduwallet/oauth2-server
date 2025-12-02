#!/bin/bash

SCRIPT="$1"
TEST_DATABASE_TYPE="${2:-memory}"
OAUTH2_SERVER_URL="${3:-http://localhost:8080}"
TEST_USERNAME="${4:-john.doe}"
TEST_PASSWORD="${5:-password123}"
TEST_SCOPE="${6:-openid profile email offline_access}"
API_KEY="${7:-super-secure-random-api-key-change-in-production-32-chars-minimum}"
QUIET="${8:-}"

# Helper function for logging
log() {
    if [ -z "$QUIET" ]; then
        echo "$@"
    fi
}

if echo "$SCRIPT" | grep -q "proxy"; then
    log "🔄 Detected proxy test script - starting mock provider and proxy server"
    
    # Start mock provider
    log "🚀 Starting mock upstream provider..."
    if lsof -i :9999 >/dev/null 2>&1; then
        log "⚠️  Port 9999 is already in use. Killing existing process..."
        lsof -ti :9999 | xargs kill -9 2>/dev/null || true
        sleep 2
    fi
    
    if [ ! -f "mock_provider.py" ]; then
        echo "❌ mock_provider.py not found"
        exit 1
    fi
    
    cp mock_provider.py mock_provider_test.py
    chmod +x mock_provider_test.py
    python3 mock_provider_test.py > mock_provider.log 2>&1 & echo $! > mock_provider.pid
    
    log "⏳ Waiting for mock provider to start..."
    sleep 3
    
    log "🔍 Testing mock provider health..."
    for i in 1 2 3 4 5; do
        if curl -f -s --max-time 5 http://localhost:9999/.well-known/openid-configuration > /dev/null 2>&1; then
            log "✅ Mock provider is healthy"
            break
        else
            log "⏳ Waiting for mock provider to respond (attempt $i/5)..."
            sleep 2
            if [ $i -eq 5 ]; then
                echo "❌ Mock provider failed to start after 5 attempts"
                cat mock_provider.log
                if [ -f mock_provider.pid ]; then kill $(cat mock_provider.pid) 2>/dev/null || true; rm -f mock_provider.pid mock_provider_test.py; fi
                exit 1
            fi
        fi
    done
    
    # Start OAuth2 server in proxy mode
    log "🚀 Starting OAuth2 server in proxy mode..."
    DATABASE_TYPE="$TEST_DATABASE_TYPE" \
        UPSTREAM_PROVIDER_URL="http://localhost:9999" \
        UPSTREAM_CLIENT_ID="upstream_client" \
        UPSTREAM_CLIENT_SECRET="upstream_secret" \
        ENABLE_TRUST_ANCHOR_API=true \
        API_KEY="$API_KEY" \
        ./bin/oauth2-server > server-test.log 2>&1 &
    echo $! > server.pid
    
    log "⏳ Waiting for server to start..."
    sleep 5
    
    log "🔍 Testing server health..."
    for i in 1 2 3 4 5; do
        if curl -f -s --max-time 5 "$OAUTH2_SERVER_URL/health" > /dev/null 2>&1; then
            log "✅ Server is healthy"
            break
        else
            log "⏳ Waiting for server to respond (attempt $i/5)..."
            sleep 2
            if [ $i -eq 5 ]; then
                echo "❌ Server failed to start after 5 attempts"
                cat server-test.log
                if [ -f server.pid ]; then kill $(cat server.pid) 2>/dev/null || true; rm -f server.pid; fi
                if [ -f mock_provider.pid ]; then kill $(cat mock_provider.pid) 2>/dev/null || true; rm -f mock_provider.pid mock_provider_test.py; fi
                exit 1
            fi
        fi
    done
    
    # Run the test
    log "✅ Proxy environment ready, running $SCRIPT..."
    if [ -n "$QUIET" ]; then
        TEST_USERNAME="$TEST_USERNAME" TEST_PASSWORD="$TEST_PASSWORD" TEST_SCOPE="$TEST_SCOPE" bash "tests/$SCRIPT" > /dev/null 2>&1
        result=$?
    else
        TEST_USERNAME="$TEST_USERNAME" TEST_PASSWORD="$TEST_PASSWORD" TEST_SCOPE="$TEST_SCOPE" bash "tests/$SCRIPT"
        result=$?
    fi
    
    # Cleanup
    if [ -f server.pid ]; then
        log "🛑 Stopping server..."
        kill $(cat server.pid) 2>/dev/null || true
        rm -f server.pid
    fi
    
    if [ -f mock_provider.pid ]; then
        log "🛑 Stopping mock provider..."
        kill $(cat mock_provider.pid) 2>/dev/null || true
        rm -f mock_provider.pid mock_provider_test.py mock_provider.log
    fi
    
    if [ -z "$QUIET" ]; then
        if [ $result -eq 0 ]; then
            echo "✅ $SCRIPT passed"
        else
            echo "❌ $SCRIPT failed"
        fi
        echo "Server logs:"
        cat server-test.log 2>/dev/null || true
    fi
    
    rm -f server-test.log
    exit $result
else
    log "🚀 Starting OAuth2 server in background..."
    DATABASE_TYPE="$TEST_DATABASE_TYPE" UPSTREAM_PROVIDER_URL="" ENABLE_TRUST_ANCHOR_API=true API_KEY="$API_KEY" ./bin/oauth2-server > server-test.log 2>&1 &
    echo $! > server.pid

    log "⏳ Waiting for server to start..."
    sleep 5

    log "🔍 Testing server health..."
    for i in 1 2 3 4 5; do
        if curl -f -s --max-time 5 "$OAUTH2_SERVER_URL/health" > /dev/null 2>&1; then
            log "✅ Server is healthy"
            break
        else
            log "⏳ Waiting for server to respond (attempt $i/5)..."
            sleep 2
            if [ $i -eq 5 ]; then
                echo "❌ Server failed to start after 5 attempts"
                cat server-test.log
                if [ -f server.pid ]; then kill $(cat server.pid) 2>/dev/null || true; rm -f server.pid; fi
                exit 1
            fi
        fi
    done

    log "🔧 Setting up test certificates..."
    if [ -f "init-certs.sh" ]; then
        if [ -n "$QUIET" ]; then
            API_KEY="$API_KEY" OAUTH_URL="$OAUTH2_SERVER_URL" bash init-certs.sh > /dev/null 2>&1
        else
            API_KEY="$API_KEY" OAUTH_URL="$OAUTH2_SERVER_URL" bash init-certs.sh
        fi
    else
        log "⚠️  init-certs.sh not found, skipping certificate setup"
    fi

    log "✅ Server is healthy, running $SCRIPT..."
    if [ -n "$QUIET" ]; then
        TEST_USERNAME="$TEST_USERNAME" TEST_PASSWORD="$TEST_PASSWORD" TEST_SCOPE="$TEST_SCOPE" bash "tests/$SCRIPT" > /dev/null 2>&1
        result=$?
    else
        TEST_USERNAME="$TEST_USERNAME" TEST_PASSWORD="$TEST_PASSWORD" TEST_SCOPE="$TEST_SCOPE" bash "tests/$SCRIPT"
        result=$?
    fi

    if [ -f server.pid ]; then
        log "🛑 Stopping server..."
        kill $(cat server.pid) 2>/dev/null || true
        rm -f server.pid
    fi

    if [ -z "$QUIET" ]; then
        if [ $result -eq 0 ]; then
            echo "✅ $SCRIPT passed"
        else
            echo "❌ $SCRIPT failed"
        fi
        echo "Server logs:"
        cat server-test.log 2>/dev/null || true
    fi
    
    rm -f server-test.log
    exit $result
fi