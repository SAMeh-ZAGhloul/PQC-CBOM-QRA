#!/usr/bin/env bash
# PostgreSQL backup to MinIO.
# Runs in backup-cron container via cron at 02:00 UTC daily.
# Also callable manually: make backup

set -euo pipefail

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="/tmp/cbom-${TIMESTAMP}.sql.gz"
DB_HOST="${POSTGRES_HOST:-postgres}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_NAME="${POSTGRES_DB:-cbom}"
DB_USER="${POSTGRES_USER:-cbom}"
DB_PASS=$(cat /run/secrets/db_password 2>/dev/null || cat ./secrets/db_password.txt)
MINIO_ENDPOINT="${MINIO_ENDPOINT:-minio:9000}"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ==> Starting backup..."

# Dump and compress
PGPASSWORD="$DB_PASS" pg_dump \
    -h "$DB_HOST" -p "$DB_PORT" \
    -U "$DB_USER" -d "$DB_NAME" \
    --format=plain \
    --no-owner --no-acl \
    --exclude-table=audit_log \
    | gzip -9 > "$BACKUP_FILE"

SIZE=$(du -sh "$BACKUP_FILE" | cut -f1)
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ==> Backup size: ${SIZE}"

# Full backup including audit log (separate, larger)
AUDIT_FILE="/tmp/cbom-audit-${TIMESTAMP}.sql.gz"
PGPASSWORD="$DB_PASS" pg_dump \
    -h "$DB_HOST" -p "$DB_PORT" \
    -U "$DB_USER" -d "$DB_NAME" \
    --format=plain \
    --no-owner --no-acl \
    --table=audit_log \
    | gzip -9 > "$AUDIT_FILE"

# Upload both to MinIO
for file in "$BACKUP_FILE" "$AUDIT_FILE"; do
    filename=$(basename "$file")
    aws s3 cp "$file" \
        "s3://backups/postgres/${filename}" \
        --endpoint-url "http://${MINIO_ENDPOINT}" \
        --no-verify-ssl \
        --sse AES256
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ==> Uploaded: ${filename}"
    rm -f "$file"
done

# Purge old backups beyond retention period
RETENTION="${BACKUP_RETENTION_DAYS:-90}"
CUTOFF=$(date -d "-${RETENTION} days" +%Y%m%d 2>/dev/null || \
         date -v "-${RETENTION}d" +%Y%m%d 2>/dev/null || \
         echo "19700101")

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ==> Purging backups older than ${RETENTION} days..."
aws s3 ls "s3://backups/postgres/" \
    --endpoint-url "http://${MINIO_ENDPOINT}" \
    --no-verify-ssl \
    | awk '{print $4}' \
    | while read -r key; do
        file_date=$(echo "$key" | grep -oE '[0-9]{8}' | head -1 || true)
        if [[ -n "$file_date" && "$file_date" < "$CUTOFF" ]]; then
            aws s3 rm "s3://backups/postgres/$key" \
                --endpoint-url "http://${MINIO_ENDPOINT}" \
                --no-verify-ssl > /dev/null
            echo "  Deleted: $key"
        fi
    done

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ==> Backup complete."
