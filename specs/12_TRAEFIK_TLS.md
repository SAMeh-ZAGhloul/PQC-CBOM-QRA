# 12 -- Traefik TLS Configuration

> Read `00_MASTER_SPEC.md`, `02_DOCKER_COMPOSE.md` first.

---

## Overview

Traefik v3 is the single external entry point. It:
- Terminates TLS 1.3 with a self-signed wildcard certificate
- Redirects all HTTP (port 80) to HTTPS (port 443)
- Routes requests by path prefix to backend services
- Enforces cipher suite restrictions
- Provides a read-only dashboard at port 8080 (internal only)

---

## traefik/traefik.yml (Static Config)

```yaml
# traefik/traefik.yml
# Static configuration -- requires Traefik restart to take effect

global:
  checkNewVersion: false
  sendAnonymousUsage: false

log:
  level: INFO
  format: json

accessLog:
  format: json
  fields:
    defaultMode: keep
    headers:
      defaultMode: drop
      names:
        Authorization: redact

api:
  dashboard: true
  insecure: false   # Dashboard only via internal network

ping:
  entryPoint: ping

entryPoints:
  # HTTP -- redirect all to HTTPS
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true

  # HTTPS -- TLS 1.3 only
  websecure:
    address: ":443"
    http:
      tls:
        options: tlsOptions
    transport:
      respondingTimeouts:
        readTimeout: 60s
        writeTimeout: 60s
        idleTimeout: 180s

  # Internal ping only (not routed externally)
  ping:
    address: ":8081"

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: cbom-frontend
    watch: true
  file:
    filename: /etc/traefik/dynamic.yml
    watch: true

# Self-signed certificate
tls:
  certificates:
    - certFile: /certs/server.crt
      keyFile: /certs/server.key
```

---

## traefik/dynamic.yml (Dynamic Config)

```yaml
# traefik/dynamic.yml
# Dynamic configuration -- reloaded without Traefik restart

# TLS options: enforce TLS 1.3 minimum, restrict cipher suites
tls:
  options:
    tlsOptions:
      minVersion: VersionTLS13
      cipherSuites:
        - TLS_AES_256_GCM_SHA384
        - TLS_CHACHA20_POLY1305_SHA256
        - TLS_AES_128_GCM_SHA256
      sniStrict: false       # Allow IP-based access for MVP (self-signed)
      curvePreferences:
        - X25519
        - CurveP384
        - CurveP256

# Security headers middleware
http:
  middlewares:
    security-headers:
      headers:
        frameDeny: true
        contentTypeNosniff: true
        browserXssFilter: true
        referrerPolicy: "strict-origin-when-cross-origin"
        permissionsPolicy: "camera=(), microphone=(), geolocation=()"
        customResponseHeaders:
          Strict-Transport-Security: "max-age=63072000; includeSubDomains"
          X-Content-Type-Options: "nosniff"
          X-Frame-Options: "DENY"
          Content-Security-Policy: >
            default-src 'self';
            script-src 'self' 'unsafe-inline';
            style-src 'self' 'unsafe-inline';
            img-src 'self' data:;
            connect-src 'self' wss:;
            font-src 'self'

    # Rate limiter for API endpoints
    api-ratelimit:
      rateLimit:
        average: 100
        burst: 50
        period: 1s

    # Strip /minio prefix when routing to MinIO console
    minio-stripprefix:
      stripPrefix:
        prefixes:
          - "/minio"

  routers:
    # Dashboard -- internal access only (no external route)
    dashboard:
      rule: "Host(`traefik.internal`)"
      service: "api@internal"
      entryPoints:
        - websecure
      tls:
        options: tlsOptions
      middlewares:
        - security-headers
```

---

## scripts/gen-certs.sh

```bash
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
```

---

## TLS Verification

After running `make setup` and `make up`, verify TLS:

```bash
# Check TLS version and cipher suite
openssl s_client -connect localhost:443 \
  -CAfile ./traefik/certs/ca.crt \
  -tls1_3 \
  -brief 2>&1 | grep -E "Protocol|Cipher"

# Expected output:
#   Protocol: TLSv1.3
#   Cipher: TLS_AES_256_GCM_SHA384

# Confirm TLS 1.2 is rejected
openssl s_client -connect localhost:443 \
  -CAfile ./traefik/certs/ca.crt \
  -tls1_2 2>&1 | grep -E "alert|error"
# Expected: handshake failure (TLS 1.2 rejected)

# Check HSTS header
curl -k -I https://localhost/ 2>&1 | grep -i "strict-transport"
# Expected: Strict-Transport-Security: max-age=63072000; includeSubDomains
```

---

## Routing Rules Summary

| Path Prefix | Routes To | Priority | Notes |
|------------|-----------|----------|-------|
| `/api/*` | api:8000 | 10 | All REST API calls |
| `/auth/*` | api:8000 | 10 | Login, logout, refresh |
| `/health` | api:8000 | 10 | Health check |
| `/metrics` | api:8000 | 10 | Prometheus metrics |
| `/minio/*` | minio:9001 | 5 | MinIO console (strip prefix) |
| `/*` | frontend:3000 | 1 | React SPA (catch-all) |

Priority order: higher number = matched first. API routes at priority 10
are matched before the catch-all frontend route at priority 1.

---

## Production Upgrade Path

To replace the self-signed cert with a real certificate:

```yaml
# Option A: Custom CA / enterprise PKI
# Replace traefik/certs/server.crt and server.key with your cert files.
# No traefik.yml changes needed.

# Option B: Let's Encrypt ACME (requires public DNS)
# traefik.yml additions:
certificatesResolvers:
  letsencrypt:
    acme:
      email: security@yourcompany.com
      storage: /letsencrypt/acme.json
      tlsChallenge: {}

# Then add to each router label in docker-compose.yml:
#   - "traefik.http.routers.api.tls.certresolver=letsencrypt"
```
