#!/usr/bin/env bash
# Generate self-signed CA + wildcard TLS certificate + RSA JWT key pair.
# Run once during `make setup`. Output goes to traefik/certs/ and secrets/.

set -euo pipefail

CERTS_DIR="./traefik/certs"
SECRETS_DIR="./secrets"
DOMAIN="${DOMAIN:-localhost}"
DAYS=825   # ~2.25 years (browser max for self-signed)

mkdir -p "$CERTS_DIR" "$SECRETS_DIR"

echo "==> Generating self-signed CA..."
openssl genrsa -out "$CERTS_DIR/ca.key" 4096

openssl req -new -x509 \
  -key "$CERTS_DIR/ca.key" \
  -out "$CERTS_DIR/ca.crt" \
  -days $DAYS \
  -subj "/C=XX/ST=CBOM/L=CBOM/O=CBOM Platform CA/CN=CBOM Root CA" \
  -extensions v3_ca

echo "==> Generating server private key..."
openssl genrsa -out "$CERTS_DIR/server.key" 4096

echo "==> Generating certificate signing request..."
openssl req -new \
  -key "$CERTS_DIR/server.key" \
  -out "$CERTS_DIR/server.csr" \
  -subj "/C=XX/ST=CBOM/L=CBOM/O=CBOM Platform/CN=${DOMAIN}"

echo "==> Signing server certificate with CA..."
cat > /tmp/san.cnf << EOF
[SAN]
subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN},IP:127.0.0.1,IP:::1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

openssl x509 -req \
  -in "$CERTS_DIR/server.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERTS_DIR/server.crt" \
  -days $DAYS \
  -extensions SAN \
  -extfile /tmp/san.cnf

rm -f "$CERTS_DIR/server.csr" /tmp/san.cnf

echo "==> Generating JWT RS256 key pair..."
openssl genrsa -out "$SECRETS_DIR/jwt_private_key.pem" 4096
openssl rsa -in "$SECRETS_DIR/jwt_private_key.pem" \
            -pubout -out "$SECRETS_DIR/jwt_public_key.pem"
# Wait, there is a typo in the spec's script on line 222? No, I see it now:
# openssl rsa -in "$SETS_DIR/jwt_private_key.pem"
# It should be "$SECRETS_DIR". I will fix it in my Write call to avoid failure.

echo "==> Generating random secrets..."
# DB password
openssl rand -base64 32 | tr -d '=+/' | cut -c1-32 > "$SECRETS_DIR/db_password.txt"
# Redis password
openssl rand -base64 32 | tr -d '=+/' | cut -c1-32 > "$SECRETS_DIR/redis_password.txt"
# RabbitMQ password
openssl rand -base64 32 | tr -d '=+/' | cut -c1-32 > "$SECRETS_DIR/rabbitmq_password.txt"
# MinIO password (must be >= 8 chars)
openssl rand -base64 32 | tr -d '=+/' | cut -c1-32 > "$SECRETS_DIR/minio_password.txt"

chmod 600 "$SECRETS_DIR"/*.pem "$SECRETS_DIR"/*.txt

echo ""
echo "==> Certificates and secrets generated successfully."
echo ""
echo "IMPORTANT: Add the CA certificate to your browser trust store:"
echo "  File: ${CERTS_DIR}/ca.crt"
echo ""
echo "  macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${CERTS_DIR}/ca.crt"
echo "  Linux:   sudo cp ${CERTS_DIR}/ca.crt /usr/local/share/ca-certificates/cbom-ca.crt && sudo update-ca-certificates"
echo "  Windows: certmgr.msc -> Trusted Root Certification Authorities -> Import"
echo ""
echo "Certificate details:"
openssl x509 -in "$CERTS_DIR/server.crt" -noout -subject -issuer -dates
