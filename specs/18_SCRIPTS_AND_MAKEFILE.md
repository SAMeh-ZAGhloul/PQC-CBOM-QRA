# 18 -- Scripts & Makefile

> Read `00_MASTER_SPEC.md`, `01_PROJECT_STRUCTURE.md`, `02_DOCKER_COMPOSE.md` first.

---

## Overview

All operator workflows are exposed through `make` targets.
Scripts live in `scripts/` and are called by both the Makefile
and the `backup-cron` container. Every script is idempotent --
safe to run multiple times.

---

## Makefile (complete)

```makefile
.PHONY: setup pull-model up down restart logs logs-api logs-scanner \
        logs-zeek logs-workers status migrate migrate-new backup \
        scale-scanners build lint test type-check clean reset \
        shell-api shell-db shell-rabbitmq open-portainer trust-cert

# ── Variables ──────────────────────────────────────────────────────────────
COMPOSE       := docker compose
API_CONTAINER := cbom-api
DB_CONTAINER  := cbom-postgres
MQ_CONTAINER  := cbom-rabbitmq

# ── Setup ──────────────────────────────────────────────────────────────────

## First-time setup: generate certs, secrets, start infra, seed DB, init MinIO
setup:
	@echo "==> [1/5] Generating TLS certificates and JWT keys..."
	@bash scripts/gen-certs.sh
	@echo ""
	@echo "==> [2/5] Starting infrastructure services..."
	@$(COMPOSE) up -d postgres redis rabbitmq minio
	@echo "==> Waiting 15s for services to initialize..."
	@sleep 15
	@echo ""
	@echo "==> [3/5] Running database migrations..."
	@$(COMPOSE) run --rm --no-deps api alembic upgrade head
	@echo ""
	@echo "==> [4/5] Seeding database with admin user and default groups..."
	@bash scripts/seed-db.sh
	@echo ""
	@echo "==> [5/5] Initializing MinIO buckets..."
	@$(COMPOSE) up -d minio
	@sleep 5
	@bash scripts/init-minio.sh
	@echo ""
	@echo "==> Setup complete!"
	@echo "    Next step: make pull-model  (downloads LFM2.5-1.2B GGUF, ~1.2 GB)"

## Pull LFM2.5-1.2B-Instruct GGUF model into llama.cpp (run once, ~1.2 GB download)
pull-model:
	@echo "==> Starting llama.cpp container..."
	@$(COMPOSE) up -d llama-cpp
	@echo "==> Waiting for llama.cpp to be ready..."
	@sleep 15
	@bash scripts/model-pull.sh
	@echo "==> Model ready. Run: make up"

# ── Lifecycle ──────────────────────────────────────────────────────────────

## Start all 19 containers (build images if needed)
up:
	@$(COMPOSE) up -d --build
	@echo ""
	@echo "==> Platform started."
	@echo "    Dashboard:  https://localhost"
	@echo "    Portainer:  https://localhost:9443"
	@echo "    Traffic sim: http://localhost:8080"
	@echo ""
	@make status

## Stop all containers (data preserved in volumes)
down:
	@$(COMPOSE) down

## Restart a specific service: make restart SERVICE=api
restart:
	@$(COMPOSE) restart $(SERVICE)

## Restart all scanner workers
restart-workers:
	@$(COMPOSE) restart worker-ast worker-binary worker-cert worker-db

## Restart the full platform (down + up)
bounce:
	@$(COMPOSE) down
	@$(COMPOSE) up -d --build

# ── Observability ──────────────────────────────────────────────────────────

## Tail all container logs (Ctrl+C to stop)
logs:
	@$(COMPOSE) logs -f --tail=100

## Tail API logs only
logs-api:
	@$(COMPOSE) logs -f --tail=100 api

## Tail all scanner worker logs
logs-scanner:
	@$(COMPOSE) logs -f --tail=100 worker-ast worker-binary worker-cert worker-db

## Tail Zeek logs
logs-zeek:
	@$(COMPOSE) logs -f --tail=100 zeek

## Tail all worker-type containers
logs-workers:
	@$(COMPOSE) logs -f --tail=100 worker-ast worker-binary worker-cert worker-db \
	    worker-magika cbom-generator scoring-engine orchestrator

## Show container status table
status:
	@echo ""
	@$(COMPOSE) ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
	@echo ""

## Show resource usage per container
resources:
	@docker stats --no-stream --format \
	    "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# ── Database ───────────────────────────────────────────────────────────────

## Apply all pending Alembic migrations
migrate:
	@$(COMPOSE) exec $(API_CONTAINER) alembic upgrade head

## Create a new Alembic migration: make migrate-new MSG="add scan config column"
migrate-new:
	@$(COMPOSE) exec $(API_CONTAINER) alembic revision --autogenerate -m "$(MSG)"

## Show current migration revision
migrate-status:
	@$(COMPOSE) exec $(API_CONTAINER) alembic current

## Downgrade one migration step
migrate-down:
	@$(COMPOSE) exec $(API_CONTAINER) alembic downgrade -1

## Open interactive psql shell
shell-db:
	@DB_PASS=$$(cat secrets/db_password.txt); \
	 $(COMPOSE) exec $(DB_CONTAINER) psql -U cbom -d cbom

## Dump full schema
db-schema:
	@DB_PASS=$$(cat secrets/db_password.txt); \
	 $(COMPOSE) exec $(DB_CONTAINER) pg_dump -U cbom -d cbom --schema-only

# ── Backup ─────────────────────────────────────────────────────────────────

## Run manual backup (pg_dump -> MinIO)
backup:
	@$(COMPOSE) exec backup-cron /backup.sh

## List all backups in MinIO
backup-list:
	@$(COMPOSE) exec minio mc ls cbom/backups/postgres/ 2>/dev/null || \
	 echo "MinIO client not configured. Check init-minio.sh."

## Restore from a specific backup: make restore BACKUP=cbom-20250101-020000.sql.gz
restore:
	@echo "==> Restoring from: $(BACKUP)"
	@$(COMPOSE) exec backup-cron bash -c \
	    "aws s3 cp s3://backups/postgres/$(BACKUP) /tmp/restore.sql.gz \
	     --endpoint-url http://minio:9000 --no-verify-ssl && \
	     gunzip /tmp/restore.sql.gz && \
	     psql -h postgres -U cbom -d cbom < /tmp/restore.sql && \
	     rm /tmp/restore.sql"

# ── Scaling ────────────────────────────────────────────────────────────────

## Scale scanner workers: make scale-scanners N=4
scale-scanners:
	@$(COMPOSE) scale worker-ast=$(N) worker-binary=$(N) worker-cert=$(N) worker-db=$(N)
	@echo "==> Scaled all scanner workers to $(N) replicas"

## Scale only AST workers: make scale-ast N=6
scale-ast:
	@$(COMPOSE) scale worker-ast=$(N)

# ── Development ────────────────────────────────────────────────────────────

## Build all Docker images (no cache)
build:
	@$(COMPOSE) build --no-cache

## Build a specific service image: make build-svc SVC=api
build-svc:
	@$(COMPOSE) build --no-cache $(SVC)

## Run ruff linter on all Python services
lint:
	@for svc in api orchestrator scanners magika-service cbom-generator scoring-engine traffic-sim; do \
	    echo "==> Linting $$svc..."; \
	    $(COMPOSE) run --rm --no-deps $$svc ruff check src/ || exit 1; \
	done

## Run mypy type checker on all Python services
type-check:
	@for svc in api orchestrator scanners magika-service cbom-generator scoring-engine; do \
	    echo "==> Type checking $$svc..."; \
	    $(COMPOSE) run --rm --no-deps $$svc mypy src/ || exit 1; \
	done

## Run all tests
test:
	@for svc in api orchestrator scanners magika-service cbom-generator scoring-engine; do \
	    echo "==> Testing $$svc..."; \
	    $(COMPOSE) run --rm --no-deps $$svc pytest tests/ -v --tb=short || exit 1; \
	done

## Run tests for a specific service: make test-svc SVC=api
test-svc:
	@$(COMPOSE) run --rm --no-deps $(SVC) pytest tests/ -v --tb=short

## Run tests with coverage report
test-coverage:
	@$(COMPOSE) run --rm --no-deps api \
	    pytest tests/ --cov=cbom_api --cov-report=html --cov-report=term-missing

# ── Shells ─────────────────────────────────────────────────────────────────

## Open shell in API container
shell-api:
	@$(COMPOSE) exec $(API_CONTAINER) bash

## Open shell in RabbitMQ container
shell-rabbitmq:
	@$(COMPOSE) exec $(MQ_CONTAINER) bash

## Open shell in llama.cpp container
shell-llama:
	@$(COMPOSE) exec cbom-llama-cpp bash

## List loaded models via llama.cpp API
llama-models:
	@$(COMPOSE) exec cbom-llama-cpp curl -sf http://localhost:11434/v1/models

## Run CBOM platform CLI (when implemented)
cbom-cli:
	@$(COMPOSE) exec $(API_CONTAINER) python -m cbom_api.cli $(ARGS)

# ── Browser shortcuts ──────────────────────────────────────────────────────

## Open Portainer in default browser
open-portainer:
	@echo "Opening https://localhost:9443"
	@(which xdg-open && xdg-open https://localhost:9443) || \
	 (which open && open https://localhost:9443) || \
	 echo "Navigate to: https://localhost:9443"

## Open CBOM dashboard
open-dashboard:
	@(which xdg-open && xdg-open https://localhost) || \
	 (which open && open https://localhost) || \
	 echo "Navigate to: https://localhost"

## Open Traffic sim UI
open-traffic:
	@(which xdg-open && xdg-open http://localhost:8080) || \
	 (which open && open http://localhost:8080) || \
	 echo "Navigate to: http://localhost:8080"

# ── Trust self-signed certificate ─────────────────────────────────────────

## Add self-signed CA to system trust store
trust-cert:
	@echo "==> Adding CBOM CA to system trust store..."
	@if [ "$$(uname)" = "Darwin" ]; then \
	    sudo security add-trusted-cert -d -r trustRoot \
	        -k /Library/Keychains/System.keychain traefik/certs/ca.crt; \
	    echo "==> Added to macOS Keychain."; \
	elif [ "$$(uname)" = "Linux" ]; then \
	    sudo cp traefik/certs/ca.crt /usr/local/share/ca-certificates/cbom-ca.crt; \
	    sudo update-ca-certificates; \
	    echo "==> Added to Linux CA store."; \
	else \
	    echo "==> Windows: Import traefik/certs/ca.crt into Trusted Root CAs via certmgr.msc"; \
	fi

# ── Cleanup ────────────────────────────────────────────────────────────────

## Remove local Docker images (keeps volumes)
clean:
	@$(COMPOSE) down --rmi local --remove-orphans

## DESTRUCTIVE: Stop and delete ALL data volumes
reset:
	@echo ""
	@echo "WARNING: This will DELETE all databases, logs, and stored data."
	@echo "Press Ctrl+C to cancel. Proceeding in 5 seconds..."
	@sleep 5
	@$(COMPOSE) down -v --remove-orphans
	@echo "==> All volumes deleted. Run 'make setup' to start fresh."

## Remove generated certs and secrets (re-run gen-certs.sh to regenerate)
clean-secrets:
	@rm -f traefik/certs/ca.crt traefik/certs/ca.key \
	         traefik/certs/server.crt traefik/certs/server.key traefik/certs/ca.srl
	@rm -f secrets/jwt_private_key.pem secrets/jwt_public_key.pem \
	         secrets/db_password.txt secrets/redis_password.txt \
	         secrets/rabbitmq_password.txt secrets/minio_password.txt
	@echo "==> Certs and secrets removed. Run 'make setup' to regenerate."

# ── Help ───────────────────────────────────────────────────────────────────

## Show this help
help:
	@echo ""
	@echo "CBOM Discovery Platform -- Make Targets"
	@echo "========================================"
	@grep -E '^##' Makefile | sed 's/## /  /'
	@echo ""
```

---

## scripts/gen-certs.sh (complete)

```bash
#!/usr/bin/env bash
# Generate self-signed CA + wildcard TLS cert + RSA JWT key pair.
# Safe to re-run: will NOT overwrite existing files unless --force is passed.

set -euo pipefail

CERTS_DIR="./traefik/certs"
SECRETS_DIR="./secrets"
DOMAIN="${DOMAIN:-localhost}"
DAYS=825
FORCE="${1:-}"

mkdir -p "$CERTS_DIR" "$SECRETS_DIR"

# ── Helper ──────────────────────────────────────────────────────────────────
needs_gen() {
    [[ "$FORCE" == "--force" ]] || [[ ! -f "$1" ]]
}

# ── TLS Certificates ────────────────────────────────────────────────────────
if needs_gen "$CERTS_DIR/ca.crt"; then
    echo "==> Generating CA private key..."
    openssl genrsa -out "$CERTS_DIR/ca.key" 4096 2>/dev/null

    echo "==> Generating self-signed CA certificate..."
    openssl req -new -x509 \
        -key "$CERTS_DIR/ca.key" \
        -out "$CERTS_DIR/ca.crt" \
        -days $DAYS \
        -subj "/C=XX/O=CBOM Platform CA/CN=CBOM Root CA" 2>/dev/null
else
    echo "==> CA cert exists, skipping (use --force to regenerate)"
fi

if needs_gen "$CERTS_DIR/server.crt"; then
    echo "==> Generating server private key..."
    openssl genrsa -out "$CERTS_DIR/server.key" 4096 2>/dev/null

    echo "==> Generating server CSR..."
    openssl req -new \
        -key "$CERTS_DIR/server.key" \
        -out "$CERTS_DIR/server.csr" \
        -subj "/C=XX/O=CBOM Platform/CN=${DOMAIN}" 2>/dev/null

    echo "==> Signing server certificate..."
    cat > /tmp/cbom_san.cnf << EOF
[SAN]
subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN},DNS:localhost,IP:127.0.0.1,IP:::1
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
        -extfile /tmp/cbom_san.cnf 2>/dev/null

    rm -f "$CERTS_DIR/server.csr" /tmp/cbom_san.cnf
    echo "==> Server certificate generated."
fi

# ── JWT RS256 Key Pair ───────────────────────────────────────────────────────
if needs_gen "$SECRETS_DIR/jwt_private_key.pem"; then
    echo "==> Generating JWT RS256 private key..."
    openssl genrsa -out "$SECRETS_DIR/jwt_private_key.pem" 4096 2>/dev/null
    openssl rsa -in "$SECRETS_DIR/jwt_private_key.pem" \
                -pubout -out "$SECRETS_DIR/jwt_public_key.pem" 2>/dev/null
    echo "==> JWT key pair generated."
fi

# ── Random Service Passwords ─────────────────────────────────────────────────
gen_password() {
    local file="$1"
    local len="${2:-32}"
    if needs_gen "$file"; then
        openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-"$len" > "$file"
        chmod 600 "$file"
        echo "==> Generated: $file"
    fi
}

gen_password "$SECRETS_DIR/db_password.txt"       32
gen_password "$SECRETS_DIR/redis_password.txt"    32
gen_password "$SECRETS_DIR/rabbitmq_password.txt" 32
gen_password "$SECRETS_DIR/minio_password.txt"    32   # MinIO requires >= 8 chars

echo ""
echo "==> All certificates and secrets ready."
echo ""
echo "Certificate summary:"
openssl x509 -in "$CERTS_DIR/server.crt" -noout -subject -issuer -dates 2>/dev/null
echo ""
echo "Next: Add CA to your browser trust store:"
echo "  macOS: sudo security add-trusted-cert -d -r trustRoot \\"
echo "         -k /Library/Keychains/System.keychain $CERTS_DIR/ca.crt"
echo "  Linux: sudo cp $CERTS_DIR/ca.crt /usr/local/share/ca-certificates/cbom-ca.crt"
echo "         sudo update-ca-certificates"
echo "  Or run: make trust-cert"
```

---

## scripts/model-pull.sh (complete)

```bash
#!/usr/bin/env bash
# Wait for llama.cpp to finish loading its GGUF model from HuggingFace Hub.
# The model auto-downloads on first container start; this script waits
# for it to be ready and then verifies it.
# Run after: docker compose up -d llama-cpp

set -euo pipefail

CONTAINER="cbom-llama-cpp"
MAX_WAIT=300
WAIT=0

echo "==> Waiting for llama.cpp server to be ready (max ${MAX_WAIT}s)..."
echo "    Model will auto-download on first start (~1.2 GB)..."
until docker exec "$CONTAINER" curl -sf http://localhost:11434/health > /dev/null 2>&1; do
    if [[ $WAIT -ge $MAX_WAIT ]]; then
        echo "ERROR: llama.cpp did not become ready within ${MAX_WAIT}s"
        echo "Check: docker logs $CONTAINER"
        exit 1
    fi
    sleep 5
    WAIT=$((WAIT + 5))
done

echo ""
echo "==> llama.cpp ready. Verifying loaded model..."
docker exec "$CONTAINER" curl -sf http://localhost:11434/v1/models

echo ""
echo "==> Model load complete. cbom-slm is ready for inference."
echo "    GPU support: $(docker exec $CONTAINER nvidia-smi -L 2>/dev/null | head -1 || echo 'Not available (CPU mode)')"
```

---

## scripts/init-minio.sh (complete)

```bash
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
```

---

## scripts/seed-db.sh (complete)

```bash
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
```

---

## scripts/backup.sh (complete)

```bash
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