#!/usr/bin/env bash
# Initialize MinIO buckets, versioning, and lifecycle rules.

set -euo pipefail

CONTAINER="cbom-minio"
ALIAS="cbom-local"
ENDPOINT="http://localhost:9000"
USER="cbomadmin"
PASS_FILE="./secrets/minio_password.txt"

if [[ ! -f "$PASS_FILE" ]]; then
    echo "ERROR: MinIO password file not found: $PASS_FILE"
    echo "Run: make setup (or scripts/gen-certs.sh) first"
    exit 1
fi

PASS=$(cat "$PASS_FILE")
MAX_WAIT=60
WAIT=0

echo "==> Waiting for MinIO to be ready..."
until curl -sf "http://localhost:9000/minio/health/live" > /dev/null 2>&1; do
    if [[ $WAIT -ge $MAX_WAIT ]]; then
        echo "ERROR: MinIO did not become ready within ${MAX_WAIT}s"
        exit 1
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done

echo "==> Setting up mc alias..."
docker exec "$CONTAINER" mc alias set "$ALIAS" "$ENDPOINT" "$USER" "$PASS" --api "s3v4" > /dev/null

echo "==> Creating buckets..."
for bucket in cbom-exports zeek-logs scan-artifacts compliance-packages backups; do
    docker exec "$CONTAINER" mc mb --ignore-existing "$ALIAS/$bucket"
    echo "    Created: $bucket"
done

echo "==> Enabling versioning on compliance buckets..."
docker exec "$CONTAINER" mc version enable "$ALIAS/cbom-exports"
docker exec "$CONTAINER" mc version enable "$ALIAS/compliance-packages"

echo "==> Setting lifecycle rules..."

# zeek-logs: auto-delete after 90 days
docker exec "$CONTAINER" mc ilm add \
    --expiry-days 90 \
    "$ALIAS/zeek-logs" > /dev/null

# scan-artifacts: auto-delete after 30 days
docker exec "$CONTAINER" mc ilm add \
    --expiry-days 30 \
    "$ALIAS/scan-artifacts" > /dev/null

# backups: auto-delete after 90 days
docker exec "$CONTAINER" mc ilm add \
    --expiry-days 90 \
    "$ALIAS/backups" > /dev/null

echo "==> Configuring anonymous access (deny all -- buckets are private)..."
for bucket in cbom-exports zeek-logs scan-artifacts compliance-packages backups; do
    docker exec "$CONTAINER" mc anonymous set none "$ALIAS/$bucket" > /dev/null
done

echo ""
echo "==> MinIO initialization complete."
echo "    Buckets:"
docker exec "$CONTAINER" mc ls "$ALIAS"
echo ""
echo "    Console: https://localhost/minio"
echo "    User: $USER"
