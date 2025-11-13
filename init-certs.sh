#!/bin/sh
set -e
CERT_DIR="/tmp/certs"
CERT_FILE="$CERT_DIR/hsm_ca.pem"

mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_FILE" ]; then
    echo "Generating HSM CA certificate..."
        # Generate CA key and certificate (EC-P256)
        openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/hsm_ca.key"
        openssl req -x509 -new -key "$CERT_DIR/hsm_ca.key" -sha256 -days 365 -out "$CERT_FILE" -subj "/CN=MockHSMCA/O=Demo/C=US"
    echo "Certificate generated at $CERT_FILE"
else
    echo "Certificate already exists at $CERT_FILE"
fi

# RSA version (deprecated)
#!/bin/sh
# set -e
# CERT_DIR="/tmp/certs"
# CERT_FILE="$CERT_DIR/hsm_ca.pem"

# mkdir -p "$CERT_DIR"
# if [ ! -f "$CERT_FILE" ]; then
#     echo "Generating HSM CA certificate..."
#     openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/hsm_ca.key" -out "$CERT_FILE" -days 365 -nodes -subj "/CN=MockHSMCA/O=Demo/C=US"
#     echo "Certificate generated at $CERT_FILE"
# else
#     echo "Certificate already exists at $CERT_FILE"
# fi
