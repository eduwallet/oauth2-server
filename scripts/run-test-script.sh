#!/bin/bash

# Avoid "Terminated: 15" noise when cleaning up background jobs on macOS/bash.
set +m

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

# Normalize script name so both "test_foo.sh" and "tests/test_foo.sh" work.
SCRIPT="$(basename "$SCRIPT")"

# Extract listen port from OAUTH2_SERVER_URL (default 8080)
SERVER_PORT="$(printf '%s' "$OAUTH2_SERVER_URL" | sed -n 's|.*:\([0-9][0-9]*\).*|\1|p')"
SERVER_PORT="${SERVER_PORT:-8080}"

kill_port() {
    local port="$1"
    if lsof -i ":$port" >/dev/null 2>&1; then
        log "⚠️  Port $port is already in use. Killing existing process..."
        lsof -ti ":$port" | xargs kill -9 2>/dev/null || true
        sleep 1
    fi
}

stop_bg() {
    local pidfile="$1"
    if [ -f "$pidfile" ]; then
        local pid
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$pidfile"
    fi
}

if echo "$SCRIPT" | grep -q "storage_consistency"; then
    log "🧪 Detected storage consistency test script - running comprehensive tests directly"
    if bash "tests/$SCRIPT"; then
        log "✅ $SCRIPT passed"
        exit 0
    else
        log "❌ $SCRIPT failed"
        exit 1
    fi
elif echo "$SCRIPT" | grep -q "proxy"; then
    log "🔄 Detected proxy test script - starting mock provider and proxy server"
    
    # Start mock provider
    log "🚀 Starting mock upstream provider..."
    kill_port 9999
    kill_port "$SERVER_PORT"
    
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
                stop_bg mock_provider.pid
                rm -f mock_provider_test.py
                exit 1
            fi
        fi
    done
    
    # Some proxy tests manage their own OAuth2 server lifecycle.
    # In those cases we only prepare the mock provider here.
    PROXY_TEST_MANAGES_SERVER=""
    if [ "$SCRIPT" = "test_proxy_public_client_flow.sh" ]; then
        PROXY_TEST_MANAGES_SERVER="yes"
        log "ℹ️  $SCRIPT manages its own OAuth2 server lifecycle; skipping wrapper server startup"
    fi

    # Start OAuth2 server in proxy mode (unless test script manages it itself)
    log "🚀 Starting OAuth2 server in proxy mode..."
    
    # Some proxy tests need additional proxy-mode env configuration.
    # Keep this logic scoped to test scripts to avoid changing default proxy behavior.
    EXTRA_UPSTREAM_PROMPT_POLICY_ENV=""
    if echo "$SCRIPT" | grep -q "upstream_prompt_policies"; then
        EXTRA_UPSTREAM_PROMPT_POLICY_ENV="yes"
        log "🔧 Enabling upstream prompt policies for this test..."
    fi

    DPOP_PROXY_ENV=""
    case "$SCRIPT" in
        test_proxy_dpop_authorization_code.sh|test_proxy_dpop_refresh.sh|test_proxy_dpop_par.sh)
            DPOP_PROXY_ENV="yes"
            log "🔧 Enabling DPOP_ENABLED + DPOP_REQUIRED for $SCRIPT..."
            ;;
    esac

    # Proxy AS must advertise its own /callback to the upstream IdP.
    UPSTREAM_CALLBACK_URL="${UPSTREAM_CALLBACK_URL:-${OAUTH2_SERVER_URL}/callback}"

    if [ -z "$PROXY_TEST_MANAGES_SERVER" ]; then
        if [ -n "$EXTRA_UPSTREAM_PROMPT_POLICY_ENV" ]; then
            DATABASE_TYPE="$TEST_DATABASE_TYPE" \
                UPSTREAM_PROVIDER_URL="http://localhost:9999" \
                UPSTREAM_CLIENT_ID="upstream_client" \
                UPSTREAM_CLIENT_SECRET="upstream_secret" \
                UPSTREAM_CALLBACK_URL="$UPSTREAM_CALLBACK_URL" \
                ENABLE_TRUST_ANCHOR_API=true \
                API_KEY="$API_KEY" \
                UPSTREAM_PROMPT_POLICIES="EDUID_SCOPE,EDUID_AUTHZ_DETAILS" \
                UPSTREAM_PROMPT_POLICY_EDUID_SCOPE_ACTION="set" \
                UPSTREAM_PROMPT_POLICY_EDUID_SCOPE_PROMPT="login" \
                UPSTREAM_PROMPT_POLICY_EDUID_SCOPE_MATCH_SCOPE="eduID" \
                UPSTREAM_PROMPT_POLICY_EDUID_AUTHZ_DETAILS_ACTION="set" \
                UPSTREAM_PROMPT_POLICY_EDUID_AUTHZ_DETAILS_PROMPT="login" \
                UPSTREAM_PROMPT_POLICY_EDUID_AUTHZ_DETAILS_MATCH_AUTHZ_DETAILS_TYPE="openid_credential" \
                UPSTREAM_PROMPT_POLICY_EDUID_AUTHZ_DETAILS_MATCH_CREDENTIAL_CONFIGURATION_ID="eduID" \
                ./bin/oauth2-server > server-test.log 2>&1 &
        elif [ -n "$DPOP_PROXY_ENV" ]; then
            DATABASE_TYPE="$TEST_DATABASE_TYPE" \
                UPSTREAM_PROVIDER_URL="http://localhost:9999" \
                UPSTREAM_CLIENT_ID="upstream_client" \
                UPSTREAM_CLIENT_SECRET="upstream_secret" \
                UPSTREAM_CALLBACK_URL="$UPSTREAM_CALLBACK_URL" \
                ENABLE_TRUST_ANCHOR_API=true \
                API_KEY="$API_KEY" \
                DPOP_ENABLED=true \
                DPOP_REQUIRED=true \
                ./bin/oauth2-server > server-test.log 2>&1 &
        else
            DATABASE_TYPE="$TEST_DATABASE_TYPE" \
                UPSTREAM_PROVIDER_URL="http://localhost:9999" \
                UPSTREAM_CLIENT_ID="upstream_client" \
                UPSTREAM_CLIENT_SECRET="upstream_secret" \
                UPSTREAM_CALLBACK_URL="$UPSTREAM_CALLBACK_URL" \
                ENABLE_TRUST_ANCHOR_API=true \
                API_KEY="$API_KEY" \
                ./bin/oauth2-server > server-test.log 2>&1 &
        fi
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
                    stop_bg server.pid
                    stop_bg mock_provider.pid
                    rm -f mock_provider_test.py
                    exit 1
                fi
            fi
        done
    fi
    
    # Run the test
    log "✅ Proxy environment ready, running $SCRIPT..."
    if [ -n "$QUIET" ]; then
        TEST_USERNAME="$TEST_USERNAME" TEST_PASSWORD="$TEST_PASSWORD" TEST_SCOPE="$TEST_SCOPE" API_KEY="$API_KEY" bash "tests/$SCRIPT" > /dev/null 2>&1
        result=$?
    else
        TEST_USERNAME="$TEST_USERNAME" TEST_PASSWORD="$TEST_PASSWORD" TEST_SCOPE="$TEST_SCOPE" API_KEY="$API_KEY" bash "tests/$SCRIPT"
        result=$?
    fi
    
    # Cleanup
    if [ -z "$PROXY_TEST_MANAGES_SERVER" ]; then
        log "🛑 Stopping server..."
        stop_bg server.pid
    fi
    log "🛑 Stopping mock provider..."
    stop_bg mock_provider.pid
    rm -f mock_provider_test.py mock_provider.log
    
    if [ -z "$QUIET" ]; then
        if [ $result -eq 0 ]; then
            echo "✅ $SCRIPT passed"
        else
            echo "❌ $SCRIPT failed"
            echo "Server logs:"
            cat server-test.log 2>/dev/null || true
        fi
    fi
    
    rm -f server-test.log
    exit $result
else
    log "🚀 Starting OAuth2 server in background..."
    kill_port "$SERVER_PORT"
    # If running the CIMD integration tests, enable CIMD and permit HTTP for local mock metadata
    if [ "$SCRIPT" = "test_cimd_registration.sh" ] || [ "$SCRIPT" = "test_cimd_example.sh" ]; then
        log "🔧 Enabling CIMD for test script"
        DATABASE_TYPE="$TEST_DATABASE_TYPE" UPSTREAM_PROVIDER_URL="" CIMD_ENABLED=true CIMD_HTTP_PERMITTED=true ENABLE_TRUST_ANCHOR_API=true ENABLE_REGISTRATION_API=true API_KEY="$API_KEY" ./bin/oauth2-server > server-test.log 2>&1 &
    elif [ "$SCRIPT" = "test_dpop.sh" ]; then
        log "🔧 Enabling DPoP (RFC 9449) for test script"
        DATABASE_TYPE="$TEST_DATABASE_TYPE" UPSTREAM_PROVIDER_URL="" DPOP_ENABLED=true DPOP_NONCE_REQUIRED=true ENABLE_TRUST_ANCHOR_API=true API_KEY="$API_KEY" ./bin/oauth2-server > server-test.log 2>&1 &
    else
        DATABASE_TYPE="$TEST_DATABASE_TYPE" UPSTREAM_PROVIDER_URL="" ENABLE_TRUST_ANCHOR_API=true API_KEY="$API_KEY" ./bin/oauth2-server > server-test.log 2>&1 &
    fi
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
                stop_bg server.pid
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

    log "🛑 Stopping server..."
    stop_bg server.pid

    if [ -z "$QUIET" ]; then
        if [ $result -eq 0 ]; then
            echo "✅ $SCRIPT passed"
        else
            echo "❌ $SCRIPT failed"
            echo "Server logs:"
            cat server-test.log 2>/dev/null || true
        fi
    fi
    
    rm -f server-test.log
    exit $result
fi