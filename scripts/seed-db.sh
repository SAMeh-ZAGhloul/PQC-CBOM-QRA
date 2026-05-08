#!/usr/bin/env bash
# Create the admin user and verify default groups.
# Called during: make setup

set -euo pipefail

DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_NAME="${POSTGRES_DB:-cbom}"
DB_USER="${POSTGRES_USER:-cbom}"
DB_PASS=$(cat ./secrets/db_password.txt)
MAX_WAIT=60
WAIT=0

echo "==> Waiting for PostgreSQL..."
until PGPASSWORD="$DB_PASS" psql \
    -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -c '\q' > /dev/null 2>&1; do
    if [[ $WAIT -ge $MAX_WAIT ]]; then
        echo "ERROR: PostgreSQL not ready after ${MAX_WAIT}s"
        exit 1
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done

echo "==> Verifying default groups..."
GROUP_COUNT=$(PGPASSWORD="$DB_PASS" psql \
    -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -tAc "SELECT COUNT(*) FROM groups;")

if [[ "$GROUP_COUNT" -lt 5 ]]; then
    echo "ERROR: Expected 5 default groups, found $GROUP_COUNT"
    echo "Check that db/init.sql ran successfully"
    exit 1
fi
echo "==> Found $GROUP_COUNT groups. OK."

echo ""
echo "==> Creating admin user..."
echo -n "Admin email (default: admin@cbom.local): "
read -r ADMIN_EMAIL
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@cbom.local}"

while true; do
    echo -n "Admin password (min 12 chars): "
    read -rs ADMIN_PASS
    echo ""
    if [[ ${#ADMIN_PASS} -ge 12 ]]; then
        break
    fi
    echo "ERROR: Password must be at least 12 characters."
done

echo "==> Hashing password..."
HASH=$(docker exec cbom-api python3 -c "
from passlib.context import CryptContext
ctx = CryptContext(schemes=['bcrypt'], deprecated='auto', bcrypt__rounds=12)
print(ctx.hash('${ADMIN_PASS}'))
" 2>/dev/null)

if [[ -z "$HASH" ]]; then
    echo "ERROR: Failed to hash password. Is the API container running?"
    echo "Try: docker compose up -d api && sleep 10 && make setup"
    exit 1
fi

ADMIN_GROUP_ID=$(PGPASSWORD="$DB_PASS" psql \
    -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -tAc "SELECT id FROM groups WHERE name = 'administrators' LIMIT 1;")

PGPASSWORD="$DB_PASS" psql \
    -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << SQL
INSERT INTO users (email, password_hash, display_name, is_active, is_admin)
VALUES ('${ADMIN_EMAIL}', '${HASH}', 'Platform Administrator', true, true)
ON CONFLICT (email) DO UPDATE
    SET password_hash = EXCLUDED.password_hash,
        is_admin = true,
        is_active = true;

INSERT INTO user_groups (user_id, group_id)
SELECT id, '${ADMIN_GROUP_ID}'
FROM users WHERE email = '${ADMIN_EMAIL}'
ON CONFLICT DO NOTHING;

INSERT INTO audit_log (actor_email, action, resource_type, new_value)
VALUES ('system', 'CREATE_USER', 'user',
        '{"email": "${ADMIN_EMAIL}", "source": "seed-db.sh"}');
SQL

echo ""
echo "==> Admin user created successfully!"
echo "    Email:    ${ADMIN_EMAIL}"
echo "    Role:     admin (via 'administrators' group)"
echo "    Login at: https://localhost"
