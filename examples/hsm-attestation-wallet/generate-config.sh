#!/bin/sh
# Generate config.js with HSM_DEMO_SERVER_URL and PEM certificate from environment and file
CONFIG_PATH="/app/config.js"
: "${HSM_DEMO_SERVER_URL:=http://localhost:8080}"
: "${API_KEY:=super-secure-random-api-key-change-in-production-32-chars-minimum}"
PEM_CERT_PATH="/tmp/certs/hsm_ca.pem"

if [ -f "$PEM_CERT_PATH" ]; then
	PEM_CERT=$(awk 'NF {sub(/\r/,""); printf "%s\\n", $0;}' "$PEM_CERT_PATH")
	echo "window.HSM_DEMO_CONFIG = { serverUrl: '${HSM_DEMO_SERVER_URL}', apiKey: '${API_KEY}', certificate: \"${PEM_CERT//"/\\"}\" };" > "$CONFIG_PATH"
else
	echo "window.HSM_DEMO_CONFIG = { serverUrl: '${HSM_DEMO_SERVER_URL}', apiKey: '${API_KEY}' };" > "$CONFIG_PATH"
fi
