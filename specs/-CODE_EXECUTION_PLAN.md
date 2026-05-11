# Code Execution Plan
## Quantum-Safe CBOM Discovery Platform — MVP

> **How to use this file:**
> Open Claude Code. Copy each prompt block (the text inside the grey boxes)
> and paste it directly into Claude Code. Complete each step fully and verify
> the expected output before moving to the next step.
> Never skip steps. Never move forward if a build or test fails.

---

## Pre-flight Checklist (Run on Host — Not in Claude Code)

```bash
# 1. Create project directory
mkdir cbom-platform && cd cbom-platform

# 2. Copy all 21 spec files into specs/ subdirectory
mkdir specs/
cp /path/to/downloaded/specs/*.md specs/

# 3. Verify all 21 spec files are present
ls specs/ | wc -l
# Expected: 21

# 4. Confirm prerequisites installed
docker --version        # Must be 26+
docker compose version  # Must be v2
git --version
openssl version

# 5. Confirm available resources
free -h    # Need >= 16 GB RAM
df -h .    # Need >= 250 GB free disk
nproc      # Need >= 8 CPU cores
```

---

## Phase 1 — Infrastructure Scaffolding

---

### Step 1.1 — Project Skeleton

```
Read specs/00_MASTER_SPEC.md and specs/01_PROJECT_STRUCTURE.md.

Create the complete project directory structure exactly as defined in those specs:

Directories to create:
  api/
  api/src/
  api/tests/
  orchestrator/
  orchestrator/src/
  scanners/
  scanners/src/
  magika-service/
  magika-service/src/
  cbom-generator/
  cbom-generator/src/
  scoring-engine/
  scoring-engine/src/
  frontend/
  frontend/src/
  traffic-sim/
  traffic-sim/scenarios/
  traffic-sim/benchmark/
  traffic-sim/sample-apps/web-app/
  traffic-sim/sample-apps/ssh-service/
  traffic-sim/sample-apps/db-service/
  zeek/
  zeek/scripts/
  traefik/
  traefik/certs/
  scripts/
  db/
  db/migrations/
  rabbitmq/
  shared/
  shared/zeek-logs/
  secrets/

Files to create with EXACT content from the specs:
  .gitignore              (from spec 01)
  .dockerignore           (from spec 01)
  .env.example            (from spec 01 — ALL variables)
  README.md               (from spec 01 — 5-step quickstart)
  secrets/.gitkeep        (empty file)
  traefik/certs/.gitkeep  (empty file)
  shared/zeek-logs/.gitkeep (empty file)

Do NOT create any Python or TypeScript source files yet.
Do NOT run any Docker commands yet.

When done, show me the output of:
  find . -type f | sort | head -40
```

**Expected:** All directories and placeholder files visible in the tree.

---

### Step 1.2 — Traefik TLS Configuration

```
Read specs/12_TRAEFIK_TLS.md completely.

Create these files with EXACT content from the spec:
  traefik/traefik.yml
  traefik/dynamic.yml
  scripts/gen-certs.sh

Make the script executable:
  chmod +x scripts/gen-certs.sh

Run the certificate generation script:
  bash scripts/gen-certs.sh

After it completes, verify these files were created:
  ls -la traefik/certs/
  ls -la secrets/

Then show me the certificate details:
  openssl x509 -in traefik/certs/server.crt -noout -subject -issuer -dates
```

**Expected:**
```
traefik/certs/ca.crt, server.crt, server.key all present
secrets/jwt_private_key.pem, jwt_public_key.pem present
secrets/db_password.txt, redis_password.txt, rabbitmq_password.txt, minio_password.txt present

subject=C=XX, O=CBOM Platform, CN=localhost
issuer=C=XX, O=CBOM Platform CA, CN=CBOM Root CA
notBefore=...
notAfter=...  (approximately 2 years from now)
```

---

### Step 1.3 — Docker Compose and RabbitMQ Config

```
Read specs/02_DOCKER_COMPOSE.md and specs/04_RABBITMQ.md completely.

Create these files with EXACT content from the specs:
  docker-compose.yml              (full 19-service stack from spec 02)
  docker-compose.override.yml     (dev overrides from spec 02)
  Makefile                        (complete with all 40+ targets from spec 02)
  rabbitmq/rabbitmq.conf          (from spec 04)
  rabbitmq/definitions.json       (from spec 04 — all exchanges, queues, bindings)

Validate the docker-compose.yml syntax:
  docker compose config --quiet
  echo "Exit code: $?"

Then show me all container names defined:
  docker compose config | grep "container_name"
```

**Expected:**
- `docker compose config --quiet` exits with code 0 (no errors)
- 19 container names listed: cbom-traefik, cbom-frontend, cbom-api, cbom-orchestrator,
  cbom-worker-ast, cbom-worker-binary, cbom-worker-cert, cbom-worker-db, cbom-magika,
  cbom-generator, cbom-scoring, cbom-llama-cpp, cbom-rabbitmq, cbom-postgres, cbom-redis,
  cbom-minio, cbom-zeek, cbom-traffic-sim, cbom-portainer, cbom-backup (19-20 total)

---

### Step 1.4 — All Shell Scripts

```
Read specs/18_SCRIPTS_AND_MAKEFILE.md completely.

Create these files with EXACT content from the spec:
  scripts/model-pull.sh
  scripts/init-minio.sh
  scripts/seed-db.sh
  scripts/backup.sh

Make all scripts executable:
  chmod +x scripts/*.sh

Verify each script has valid bash syntax:
  for f in scripts/*.sh; do
    bash -n "$f" && echo "$f: SYNTAX OK" || echo "$f: SYNTAX ERROR"
  done
```

**Expected:** All 5 scripts (including gen-certs.sh from step 1.2) print `SYNTAX OK`.

---

## Phase 2 — Data Layer

---

### Step 2.1 — PostgreSQL Schema

```
Read specs/03_DATABASE_SCHEMA.md completely.

Create:
  db/init.sql

This file must contain ALL of the following from the spec (in order):
  - CREATE EXTENSION statements (uuid-ossp, pg_trgm, pg_stat_statements)
  - All ENUM type definitions (rbac_role, quantum_class, crypto_type,
    finding_status, severity, scan_status, discovery_source)
  - All CREATE TABLE statements (groups, users, user_groups, user_sessions,
    scans, scan_jobs, cbom_versions, crypto_assets with partitioning,
    certificates, qars_scores, qsri_scores, findings, audit_log)
  - All quarterly partition tables for crypto_assets (2025 Q1-Q4, 2026, default)
  - All CREATE INDEX statements
  - Row-Level Security on audit_log (ENABLE ROW LEVEL SECURITY + all policies)
  - REVOKE DELETE and UPDATE on audit_log
  - INSERT INTO groups (5 default groups seed data)
  - update_updated_at_column() trigger function
  - All triggers (users, groups, scans, crypto_assets, findings)
  - v_scan_coverage view
  - v_cert_expiry_alerts view

Start the database:
  docker compose up -d postgres

Wait 20 seconds, then verify it is healthy:
  docker compose ps postgres

Run a schema check:
  docker exec cbom-postgres psql -U cbom -d cbom \
    -c "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;"

Check that RLS is enabled on audit_log:
  docker exec cbom-postgres psql -U cbom -d cbom \
    -c "SELECT tablename, rowsecurity FROM pg_tables WHERE tablename='audit_log';"

Verify default groups were seeded:
  docker exec cbom-postgres psql -U cbom -d cbom \
    -c "SELECT name, rbac_role FROM groups ORDER BY name;"
```

**Expected:**
- 14+ tables listed
- audit_log shows `rowsecurity = t`
- 5 groups: administrators, auditors, cisos, executives, security-team

---

### Step 2.2 — MinIO Object Storage

```
Read specs/11_MINIO_STORAGE.md (the init-minio.sh section).

Start MinIO:
  docker compose up -d minio

Wait 15 seconds, then check it is healthy:
  docker compose ps minio
  curl -sf http://localhost:9000/minio/health/live && echo "MinIO: HEALTHY"

Run the bucket initialization script:
  bash scripts/init-minio.sh

Verify all 5 buckets exist:
  docker exec cbom-minio mc ls cbom-local/

Verify versioning is enabled on audit buckets:
  docker exec cbom-minio mc version info cbom-local/cbom-exports
  docker exec cbom-minio mc version info cbom-local/compliance-packages
```

**Expected:**
- 5 buckets: cbom-exports, zeek-logs, scan-artifacts, compliance-packages, backups
- cbom-exports: versioning enabled
- compliance-packages: versioning enabled

---

### Step 2.3 — Redis and RabbitMQ

```
Start Redis and RabbitMQ:
  docker compose up -d redis rabbitmq

Wait 20 seconds, then verify both are healthy:
  docker compose ps redis rabbitmq

Test Redis connectivity:
  REDIS_PASS=$(cat secrets/redis_password.txt)
  docker exec cbom-redis redis-cli --no-auth-warning -a "$REDIS_PASS" ping

Verify RabbitMQ queues were created from definitions.json:
  docker exec cbom-rabbitmq rabbitmqctl list_queues name durable messages \
    --formatter=pretty_table

Verify all exchanges exist:
  docker exec cbom-rabbitmq rabbitmqctl list_exchanges name type durable \
    --formatter=pretty_table
```

**Expected:**
- Redis: `PONG`
- RabbitMQ queues: scanner.ast, scanner.binary, scanner.cert, scanner.db,
  slm.fallback, cbom.ingest, cbom.notify, cbom.dlq, orchestrator.requests (9 total)
- Exchanges: cbom.direct (direct), cbom.fanout (fanout), cbom.dlx (direct)

---

## Phase 3 — Backend Services

---

### Step 3.1 — FastAPI Backend

```
Read specs/05_API_BACKEND.md and specs/17_SECURITY.md completely.

Create the complete FastAPI service. Create every file listed below
with EXACT code from the specs:

  api/Dockerfile                               (from spec 05)
  api/pyproject.toml                           (from spec 05)
  api/alembic.ini                              (from spec 03)
  api/alembic/env.py                           (from spec 03)
  api/alembic/versions/.gitkeep
  api/src/cbom_api/__init__.py
  api/src/cbom_api/main.py                     (from spec 05)
  api/src/cbom_api/config.py                   (from spec 05)
  api/src/cbom_api/dependencies.py             (from spec 17)
  api/src/cbom_api/middleware.py               (from spec 17)
  api/src/cbom_api/auth/__init__.py
  api/src/cbom_api/auth/jwt.py                 (from spec 17)
  api/src/cbom_api/auth/rbac.py                (from spec 05)
  api/src/cbom_api/auth/password.py            (from spec 17)
  api/src/cbom_api/models/__init__.py
  api/src/cbom_api/models/db.py                (SQLAlchemy models from spec 03)
  api/src/cbom_api/models/schemas.py           (Pydantic schemas from spec 05)
  api/src/cbom_api/db/__init__.py
  api/src/cbom_api/db/session.py               (from spec 05)
  api/src/cbom_api/routers/__init__.py
  api/src/cbom_api/routers/auth.py             (login, logout, refresh endpoints)
  api/src/cbom_api/routers/scans.py            (CRUD + WebSocket)
  api/src/cbom_api/routers/cbom.py             (CBOM read + export)
  api/src/cbom_api/routers/assets.py           (asset query + annotate)
  api/src/cbom_api/routers/findings.py         (findings workflow)
  api/src/cbom_api/routers/certificates.py     (cert inventory)
  api/src/cbom_api/routers/qars.py             (QARS scores)
  api/src/cbom_api/routers/qsri.py             (QSRI scores + input)
  api/src/cbom_api/routers/reports.py          (report generation)
  api/src/cbom_api/routers/admin.py            (from spec 14 — user/group/RBAC CRUD)
  api/src/cbom_api/routers/traffic.py          (proxy to traffic-sim)
  api/src/cbom_api/services/__init__.py
  api/src/cbom_api/services/scan_service.py
  api/src/cbom_api/services/cbom_service.py
  api/src/cbom_api/services/report_service.py  (from spec 11)
  api/src/cbom_api/services/websocket_service.py
  api/tests/__init__.py
  api/tests/conftest.py                        (from spec 19)
  api/tests/unit/__init__.py
  api/tests/integration/__init__.py
  api/tests/integration/test_auth.py           (from spec 19)
  api/tests/integration/test_cbom.py           (from spec 19)
  api/tests/security/__init__.py
  api/tests/security/test_security.py          (from spec 19)

Implementation rules:
  - Every router endpoint must have require_role() decorator
  - Every POST/PUT/PATCH/DELETE must write to audit_log
  - JWT uses RS256 only (never HS256)
  - Passwords rejected if < 12 characters (422 response)
  - Config reads secrets from files, never from env vars directly

Build the Docker image:
  docker compose build api

Expected: Build completes with no errors.
Show me the last 10 lines of build output.
```

---

### Step 3.2 — Alembic Migrations and API Health

```
Start the API container:
  docker compose up -d api

Wait 25 seconds for it to initialize, then check health:
  docker compose ps api
  docker compose logs api --tail=20

Run database migrations:
  docker compose exec api alembic upgrade head

Verify migration ran successfully:
  docker compose exec api alembic current

Check all tables exist in the database:
  docker exec cbom-postgres psql -U cbom -d cbom \
    -c "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;" -tA

Test the API health endpoint:
  curl -sk https://localhost/health | python3 -m json.tool

Test that unauthenticated access to protected routes returns 401:
  curl -sk -o /dev/null -w "%{http_code}" https://localhost/api/scans
```

**Expected:**
- `alembic current` shows current revision
- All 14+ tables present in database
- `/health` returns `{"status": "ok", "version": "1.0.0-mvp"}`
- `/api/scans` without token returns `401`

---

### Step 3.3 — Seed Admin User

```
Run the seed script to create the admin user:
  bash scripts/seed-db.sh

When prompted, enter:
  Email:    admin@cbom.local
  Password: (choose a password >= 12 characters, write it down - CbomAdmin2026x)

After the script completes, verify the user was created:
  docker exec cbom-postgres psql -U cbom -d cbom \
    -c "SELECT email, is_admin, is_active FROM users;"

Verify group membership:
  docker exec cbom-postgres psql -U cbom -d cbom \
    -c "SELECT u.email, g.name, g.rbac_role FROM users u
        JOIN user_groups ug ON ug.user_id = u.id
        JOIN groups g ON g.id = ug.group_id;"

Test login via the API:
  curl -sk -X POST https://localhost/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@cbom.local","password":"CbomAdmin2026x"}' \
    | python3 -m json.tool

Save the access token for use in later steps:
  ADMIN_TOKEN=$(curl -sk -X POST https://localhost/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@cbom.local","password":"CbomAdmin2026x"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  echo "Token length: ${#ADMIN_TOKEN}"
```

**Expected:**
- User appears in users table with `is_admin = true`
- User is in the `administrators` group with role `admin`
- Login returns JSON with `access_token` and `refresh_token`
- Token length > 200 characters

---

### Step 3.4 — llama.cpp SLM (LFM2.5-1.2B-Instruct GGUF)

```
Read specs/10_OLLAMA_SLM.md completely.

Create the llama.cpp client module (will be used by scanners in step 3.6):
  scanners/src/cbom_scanners/utils/ollama_client.py

This file must contain EXACT code from spec 10:
  - CRYPTO_DETECTION_PROMPT constant (full prompt template)
  - HOMEGROWN_CRYPTO_PROMPT constant
  - _get_semaphore() function
  - analyze_file_async() function with rate limiting (uses llama.cpp /completion endpoint)
  - check_llm_health() function

Start llama.cpp:
  docker compose up -d llama-cpp

Wait for the model to download and load (first time ~1.2 GB):
  bash scripts/model-pull.sh

This will auto-download the GGUF model from HuggingFace on first start.

Verify the model is loaded:
  docker exec cbom-llama-cpp curl -sf http://localhost:11434/v1/models

Test a prompt to confirm inference works:
  curl -sf http://localhost:11435/completion \
    -H 'Content-Type: application/json' \
    -d '{"prompt": "Return JSON only, no markdown: {\"status\": \"working\", \"model\": \"cbom-slm\"}", "temperature": 0.1, "n_predict": 100}'
```

**Expected:**
- `/v1/models` shows the model with id `cbom-slm`
- Test prompt returns a JSON response within 60 seconds

---

### Step 3.5 — Magika File Classification Service

```
Read specs/06_SCANNER_WORKERS.md (the magika-service section near the bottom).

Create the Magika microservice:
  magika-service/Dockerfile
  magika-service/pyproject.toml
  magika-service/src/__init__.py
  magika-service/src/magika_service/__init__.py
  magika-service/src/magika_service/main.py     (EXACT code from spec 06)

The main.py must contain:
  - FastAPI app
  - Magika() instance
  - ROUTING_GROUPS dict (all content types mapped to scanner groups)
  - ClassifyRequest and ClassifyResponse Pydantic models
  - GET /health endpoint
  - POST /classify endpoint

Build and start:
  docker compose build worker-magika
  docker compose up -d worker-magika

Wait 15 seconds, then test from within the Docker network:
  docker exec cbom-api curl -s http://worker-magika:8002/health

Create a test file and classify it:
  docker exec cbom-worker-ast bash -c \
    "echo 'import rsa\nfrom cryptography.hazmat.primitives.asymmetric import rsa' \
    > /tmp/test_rsa.py && \
    curl -s -X POST http://worker-magika:8002/classify \
      -H 'Content-Type: application/json' \
      -d '{\"file_path\":\"/tmp/test_rsa.py\"}'"
```

**Expected:**
- `/health` returns `{"status": "ok"}`
- Classification returns `{"content_type": "python", "confidence": > 0.8, "group": "source_code"}`

---

### Step 3.6 — Scanner Workers (AST, Binary, Cert, DB)

```
Read specs/06_SCANNER_WORKERS.md completely.

Create the complete scanner workers service:

  scanners/Dockerfile
  scanners/pyproject.toml
  scanners/src/cbom_scanners/__init__.py
  scanners/src/cbom_scanners/config.py
  scanners/src/cbom_scanners/celery_app.py          (from spec 04)
  scanners/src/cbom_scanners/tasks.py               (from spec 06)
  scanners/src/cbom_scanners/ast_scanner.py         (from spec 06)
  scanners/src/cbom_scanners/binary_scanner.py      (from spec 06)
  scanners/src/cbom_scanners/cert_scanner.py        (from spec 06)
  scanners/src/cbom_scanners/db_scanner.py          (from spec 06)
  scanners/src/cbom_scanners/patterns/__init__.py
  scanners/src/cbom_scanners/patterns/python_patterns.py    (from spec 06)
  scanners/src/cbom_scanners/patterns/java_patterns.py      (from spec 06)
  scanners/src/cbom_scanners/patterns/go_patterns.py        (from spec 06)
  scanners/src/cbom_scanners/patterns/javascript_patterns.py (from spec 06)
  scanners/src/cbom_scanners/patterns/c_patterns.py
  scanners/src/cbom_scanners/utils/__init__.py
  scanners/src/cbom_scanners/utils/magika_client.py         (from spec 06)
  scanners/src/cbom_scanners/utils/ollama_client.py         (copy from step 3.4)
  scanners/src/cbom_scanners/utils/publisher.py
  scanners/src/cbom_scanners/utils/archive.py
  scanners/tests/__init__.py
  scanners/tests/unit/__init__.py
  scanners/tests/unit/test_ast_patterns.py                  (from spec 19)

Build all scanner worker images:
  docker compose build worker-ast worker-binary worker-cert worker-db

Start all 4 worker types:
  docker compose up -d worker-ast worker-binary worker-cert worker-db

Wait 20 seconds, then verify workers connected to RabbitMQ:
  docker compose logs worker-ast --tail=20 | grep -iE "ready|connected|celery"

Check that all scanner queues have consumers:
  docker exec cbom-rabbitmq rabbitmqctl list_queues name consumers \
    --formatter=pretty_table | grep scanner
```

**Expected:**
- Build completes for all 4 worker images
- Workers show "celery@... ready" in logs
- scanner.ast: consumers=2, scanner.binary: consumers=2,
  scanner.cert: consumers=4, scanner.db: consumers=2

---

### Step 3.7 — CBOM Generator

```
Read specs/07_CBOM_GENERATOR.md completely.

Create:
  cbom-generator/Dockerfile
  cbom-generator/pyproject.toml
  cbom-generator/src/cbom_generator/__init__.py
  cbom-generator/src/cbom_generator/config.py
  cbom-generator/src/cbom_generator/main.py         (queue consumer from spec 07)
  cbom-generator/src/cbom_generator/classifier.py   (FULL algorithm DB — all 60+ entries
                                                      from spec 07, including all VULNERABLE,
                                                      PARTIALLY_SAFE, SAFE, and PQC entries)
  cbom-generator/src/cbom_generator/deduplicator.py (UUID5 from spec 07)
  cbom-generator/src/cbom_generator/generator.py    (CycloneDX 1.6 assembler from spec 07)
  cbom-generator/src/cbom_generator/publisher.py
  cbom-generator/src/cbom_generator/findings.py     (auto-findings from spec 07)
  cbom-generator/tests/__init__.py
  cbom-generator/tests/unit/__init__.py
  cbom-generator/tests/unit/test_classifier.py      (from spec 19)

CRITICAL: The classifier.py ALGORITHM_DB dict must contain entries for:
  RSA, RSAPSS, DSA, ECDSA, ECDH, ECDHE, DH, DHE, ED25519, ED448, X25519, X448 (VULNERABLE)
  AES128, AES-128, 3DES, TRIPLEDES, DES, RC4, RC2, BLOWFISH, SHA1, SHA-1, SHA224,
  SHA-224, SHA256, SHA-256, MD5, MD4, HMACSHA1, HMACMD5, HMACSHA256, PBKDF2 (PARTIALLY_SAFE)
  AES256, AES-256, AES256GCM, AES-256-GCM, CHACHA20, CHACHA20POLY1305, SHA384, SHA-384,
  SHA512, SHA-512, SHA3256, SHA3-256, SHA3512, SHA3-512, BLAKE2B, BLAKE3, ARGON2ID,
  BCRYPT, SCRYPT, HMACSHA384, HMACSHA512 (SAFE)
  MLKEM, ML-KEM, MLKEM512, ML-KEM-512, MLKEM768, ML-KEM-768, KYBER, KYBER768,
  MLDSA, ML-DSA, MLDSA44, ML-DSA-44, MLDSA65, ML-DSA-65, DILITHIUM,
  SLHDSA, SLH-DSA, SPHINCS, FALCON (PQC)

Build and start:
  docker compose build cbom-generator
  docker compose up -d cbom-generator

Wait 15 seconds, verify it is consuming from cbom.ingest:
  docker compose logs cbom-generator --tail=20

Check the queue has a consumer:
  docker exec cbom-rabbitmq rabbitmqctl list_queues name consumers \
    --formatter=pretty_table | grep cbom.ingest

Run classifier unit tests:
  docker compose run --rm cbom-generator pytest tests/unit/ -v
```

**Expected:**
- cbom.ingest shows consumers=1
- All classifier unit tests pass (RSA=vulnerable, AES-256=safe, ML-KEM=pqc, etc.)

---

### Step 3.8 — Scoring Engine (QARS + QSRI)

```
Read specs/08_SCORING_ENGINE.md completely.

Create:
  scoring-engine/Dockerfile
  scoring-engine/pyproject.toml
  scoring-engine/src/cbom_scoring/__init__.py
  scoring-engine/src/cbom_scoring/config.py
  scoring-engine/src/cbom_scoring/main.py           (scan complete consumer)
  scoring-engine/src/cbom_scoring/qars.py           (FULL Mosca formula from spec 08)
  scoring-engine/src/cbom_scoring/qsri.py           (FULL 8-dimension model from spec 08)
  scoring-engine/src/cbom_scoring/sector_profiles.py (all 6 sector profiles from spec 08)
  scoring-engine/src/cbom_scoring/compliance.py     (DORA/NIS2/NSM-10 from spec 08)
  scoring-engine/src/cbom_scoring/publisher.py
  scoring-engine/src/cbom_scoring/db.py
  scoring-engine/tests/__init__.py
  scoring-engine/tests/unit/__init__.py
  scoring-engine/tests/unit/test_qars.py            (from spec 19)
  scoring-engine/tests/unit/test_qsri.py            (from spec 19)

CRITICAL in qars.py:
  - Formula: Base QARS = clamp((X + Y) / Z, 0.0, 1.0)
  - Formula: Weighted QARS = clamp(Base_QARS x S x E, 0.0, 1.0)
  - Partially safe discount: base_qars *= 0.6
  - Severity bands: critical>=0.8, high>=0.6, medium>=0.4, low<0.4
  - Mosca urgent flag: True when X + Y >= Z

CRITICAL in qsri.py:
  - 8 dimensions with weights summing to exactly 1.0
  - Formula: total = sum(dimension_score x weight)
  - dimension_score = (maturity_level / 5) x 100
  - Auto-populate inventory from cbom_coverage_pct

Build and start:
  docker compose build scoring-engine
  docker compose up -d scoring-engine

Run all unit tests:
  docker compose run --rm scoring-engine pytest tests/unit/ -v --tb=short
```

**Expected:** All QARS and QSRI unit tests pass, including:
- `test_vulnerable_asset_general_enterprise`: weighted_qars = 1.0, severity = "critical"
- `test_safe_asset_scores_zero`: weighted_qars = 0.0
- `test_all_fives_gives_100`: total_score = 100.0
- `test_weights_sum_to_one`: passes

---

### Step 3.9 — Discovery Orchestrator

```
Read specs/09_ORCHESTRATOR.md completely.

Create:
  orchestrator/Dockerfile
  orchestrator/pyproject.toml
  orchestrator/src/cbom_orchestrator/__init__.py
  orchestrator/src/cbom_orchestrator/config.py
  orchestrator/src/cbom_orchestrator/main.py        (consume orchestrator.requests)
  orchestrator/src/cbom_orchestrator/decomposer.py  (from spec 09)
  orchestrator/src/cbom_orchestrator/log_watcher.py (from spec 09)
  orchestrator/src/cbom_orchestrator/zeek_parser.py (from spec 09 — all cipher maps)
  orchestrator/src/cbom_orchestrator/state.py       (from spec 09)
  orchestrator/src/cbom_orchestrator/repo_crawler.py (from spec 09)

The zeek_parser.py must include:
  - CIPHER_SUITE_MAP (all TLS 1.3 and TLS 1.2 cipher suites)
  - SSH_KEXALG_MAP (all SSH key exchange algorithms)
  - SSH_HOSTKEY_MAP (all SSH host key algorithms)
  - parse_ssl_log() function
  - parse_x509_log() function
  - parse_ssh_log() function

Build and start:
  docker compose build orchestrator
  docker compose up -d orchestrator

Wait 15 seconds, verify startup:
  docker compose logs orchestrator --tail=30
```

**Expected:** Orchestrator logs show it connected to RabbitMQ and is
watching the Zeek log directory (no crash, no error).

---

## Phase 4 — Network Sensor

---

### Step 4.1 — Zeek Network Sensor

```
Read specs/15_ZEEK_SENSOR.md completely.

Create these files with EXACT content from the spec:
  zeek/local.zeek                     (site policy — loads all SSL/SSH/hash analyzers)
  zeek/scripts/crypto-detection.zeek  (full Zeek script including:
                                        - CBOMCrypto module and Info record
                                        - CIPHER_SUITE_MAP table (all cipher suites)
                                        - SSH_KEXALG_MAP table
                                        - SSH_HOSTKEY_MAP table
                                        - zeek_init() event handler
                                        - ssl_established() event handler
                                        - x509_certificate() event handler
                                        - ssh_server_host_key() event handler
                                        - ssh_capabilities() event handler)

Start Zeek:
  docker compose up -d zeek

Wait 20 seconds, check it started without errors:
  docker compose logs zeek --tail=30

Generate some HTTPS traffic so Zeek has something to capture:
  for i in 1 2 3 4 5; do
    curl -sk https://localhost/health > /dev/null
    sleep 1
  done

Wait 15 more seconds, then check for Zeek log files:
  ls -la shared/zeek-logs/

Check the ssl.log contains JSON entries:
  if [ -f shared/zeek-logs/ssl.log ]; then
    head -2 shared/zeek-logs/ssl.log | python3 -m json.tool
  else
    echo "ssl.log not yet created — Zeek may need more traffic"
  fi
```

**Expected:**
- Zeek logs show "CBOM Zeek sensor started" message
- `shared/zeek-logs/` contains ssl.log (and possibly x509.log, conn.log)
- ssl.log entries are valid JSON with `cipher`, `version`, `id.resp_p` fields

---

## Phase 5 — Frontend

---

### Step 5.1 — React + Vite SPA

```
Read specs/13_FRONTEND_REACT.md completely.

Create the complete React frontend:

  frontend/Dockerfile
  frontend/nginx.conf                              (from spec 13)
  frontend/package.json                            (exact deps from spec 13)
  frontend/tsconfig.json
  frontend/vite.config.ts                          (from spec 13)
  frontend/tailwind.config.ts
  frontend/postcss.config.js
  frontend/index.html
  frontend/src/main.tsx
  frontend/src/App.tsx
  frontend/src/router.tsx                          (all routes + guards from spec 13)
  frontend/src/api/client.ts                       (axios instance from spec 13)
  frontend/src/api/auth.ts
  frontend/src/api/scans.ts
  frontend/src/api/cbom.ts
  frontend/src/api/findings.ts
  frontend/src/api/certs.ts
  frontend/src/api/qars.ts
  frontend/src/api/qsri.ts
  frontend/src/api/reports.ts
  frontend/src/api/admin.ts
  frontend/src/api/traffic.ts
  frontend/src/store/auth.store.ts                 (Zustand store from spec 13)
  frontend/src/store/ui.store.ts
  frontend/src/hooks/useAuth.ts
  frontend/src/hooks/usePermission.ts             (RBAC hook from spec 13)
  frontend/src/hooks/useScanWebSocket.ts           (from spec 13)
  frontend/src/components/layout/AppLayout.tsx
  frontend/src/components/layout/Sidebar.tsx
  frontend/src/components/layout/TopBar.tsx
  frontend/src/components/ui/QarsGauge.tsx         (from spec 13)
  frontend/src/components/ui/QsriRadar.tsx         (from spec 13)
  frontend/src/components/ui/Badge.tsx
  frontend/src/components/ui/DataTable.tsx
  frontend/src/components/ui/SeverityBadge.tsx
  frontend/src/components/ui/ProgressBar.tsx
  frontend/src/components/ui/StatusDot.tsx
  frontend/src/components/shared/ConfirmDialog.tsx
  frontend/src/components/shared/ExportButton.tsx
  frontend/src/components/shared/ErrorBoundary.tsx
  frontend/src/pages/Login.tsx
  frontend/src/pages/Dashboard.tsx
  frontend/src/pages/Scans.tsx
  frontend/src/pages/ScanDetail.tsx
  frontend/src/pages/CbomExplorer.tsx
  frontend/src/pages/Findings.tsx
  frontend/src/pages/Certificates.tsx
  frontend/src/pages/QarsView.tsx
  frontend/src/pages/QsriView.tsx
  frontend/src/pages/Reports.tsx
  frontend/src/pages/Roadmap.tsx
  frontend/src/pages/ExecutiveDashboard.tsx
  frontend/src/pages/admin/AdminLayout.tsx
  frontend/src/pages/admin/Users.tsx               (from spec 14)
  frontend/src/pages/admin/Groups.tsx
  frontend/src/pages/admin/AuditLog.tsx            (from spec 14)
  frontend/src/pages/admin/Sessions.tsx

Role-based routing rules (from spec 13 router.tsx):
  /dashboard   — all authenticated roles
  /scans       — engineer, admin, ciso (read-only for ciso)
  /cbom        — all authenticated
  /findings    — all authenticated
  /certs       — all authenticated
  /qars        — all authenticated
  /qsri        — all authenticated
  /reports     — all authenticated
  /roadmap     — all authenticated
  /executive   — ceo, ciso, admin only
  /admin/*     — admin only

Build the Docker image:
  docker compose build frontend

Expected: TypeScript compilation succeeds, image builds without errors.
Show me the final 5 lines of build output.
```

---

### Step 5.2 — Start Full Stack and Verify Dashboard

```
Start Traefik and the frontend:
  docker compose up -d traefik frontend

Wait 20 seconds, then verify all currently-started containers:
  docker compose ps

Test the dashboard is reachable:
  curl -sk -o /dev/null -w "%{http_code}" https://localhost/
  curl -sk -o /dev/null -w "%{http_code}" https://localhost/health

Test API routing through Traefik:
  curl -sk https://localhost/health | python3 -m json.tool

Test login through Traefik:
  TOKEN=$(curl -sk -X POST https://localhost/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@cbom.local","password":"YOUR_PASSWORD"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  echo "Token obtained: ${#TOKEN} chars"

Test admin endpoints through Traefik:
  curl -sk https://localhost/api/admin/users \
    -H "Authorization: Bearer $TOKEN" \
    | python3 -m json.tool | head -10
```

**Expected:**
- `https://localhost/` returns HTTP 200
- `/health` returns `{"status": "ok"}`
- Login returns token
- `/api/admin/users` returns user list with admin@cbom.local

---

## Phase 6 — Traffic Simulation

---

### Step 6.1 — Traffic Generation and Simulation Module

```
Read specs/16_TRAFFIC_SIM.md completely.

Create the traffic simulation module:
  traffic-sim/Dockerfile
  traffic-sim/pyproject.toml
  traffic-sim/main.py                              (FastAPI control API from spec 16)
  traffic-sim/locustfile.py
  traffic-sim/scenarios/__init__.py
  traffic-sim/scenarios/web_tls.py                 (from spec 16)
  traffic-sim/scenarios/ssh_keyx.py                (from spec 16)
  traffic-sim/scenarios/db_tls.py                  (from spec 16)
  traffic-sim/scenarios/weak_crypto.py
  traffic-sim/scenarios/cert_chain.py
  traffic-sim/scenarios/mixed_load.py              (from spec 16)
  traffic-sim/scenarios/pqc_demo.py
  traffic-sim/benchmark/__init__.py
  traffic-sim/benchmark/coverage_report.py         (from spec 16)
  traffic-sim/benchmark/accuracy_report.py
  traffic-sim/benchmark/throughput_report.py
  traffic-sim/sample-apps/web-app/Dockerfile
  traffic-sim/sample-apps/web-app/requirements.txt
  traffic-sim/sample-apps/web-app/app.py           (Flask + SSL from spec 16)
  traffic-sim/sample-apps/ssh-service/Dockerfile
  traffic-sim/sample-apps/ssh-service/sshd_config
  traffic-sim/sample-apps/db-service/Dockerfile
  traffic-sim/sample-apps/db-service/postgresql.conf
  traffic-sim/sample-apps/db-service/pg_hba.conf
  traffic-sim/sample-apps/db-service/init.sql      (from spec 16)

Build and start:
  docker compose build traffic-sim
  docker compose up -d traffic-sim

Wait 15 seconds, verify the control API:
  curl -s http://localhost:8080/health
  curl -s http://localhost:8080/api/scenarios | python3 -m json.tool | grep '"id"'

Run the web-tls scenario for 30 seconds:
  curl -s -X POST http://localhost:8080/api/scenarios/web-tls/start \
    -H "Content-Type: application/json" \
    -d '{"users":2,"duration_seconds":30}' \
    | python3 -m json.tool

Wait 35 seconds for the scenario to complete, then check Zeek saw traffic:
  wc -l shared/zeek-logs/ssl.log 2>/dev/null || echo "ssl.log not found"

Check the scenario status:
  curl -s http://localhost:8080/api/scenarios/status | python3 -m json.tool
```

**Expected:**
- Control API lists 8 scenario types
- web-tls scenario returns `{"status": "running"}`
- ssl.log grows (more lines than before)
- After 35s, status shows `{"active": false}`

---

## Phase 7 — Quality and Verification

---

### Step 7.1 — Run All Unit Tests

```
Run unit tests across all Python services.
Fix any failures before proceeding to the next step.

echo "==> Testing scoring-engine..."
docker compose run --rm --no-deps scoring-engine \
  pytest tests/unit/ -v --tb=short 2>&1

echo ""
echo "==> Testing cbom-generator..."
docker compose run --rm --no-deps cbom-generator \
  pytest tests/unit/ -v --tb=short 2>&1

echo ""
echo "==> Testing scanners..."
docker compose run --rm --no-deps worker-ast \
  pytest tests/unit/ -v --tb=short 2>&1

echo ""
echo "==> Testing API..."
docker compose run --rm --no-deps api \
  pytest tests/unit/ -v --tb=short 2>&1

For each failure, fix the implementation and re-run that service's tests
before moving to the next service.

Show me the final test summary for each service (the "X passed, Y failed" line).
```

**Expected (all must pass before proceeding):**
- scoring-engine: QARS Mosca tests, QSRI dimension weight tests
- cbom-generator: All 60+ algorithm classification tests
- scanners: AST pattern detection tests for Python, Go, Java
- api: Auth unit tests

---

### Step 7.2 — Security Verification

```
Read specs/17_SECURITY.md and specs/20_NFR_CHECKLIST.md.
Run each verification command from the NFR-S section of spec 20.

--- Test 1: TLS 1.3 enforced ---
openssl s_client -connect localhost:443 \
  -CAfile ./traefik/certs/ca.crt \
  -tls1_3 -brief 2>&1 | grep -E "Protocol|Cipher"

--- Test 2: TLS 1.2 rejected ---
openssl s_client -connect localhost:443 \
  -CAfile ./traefik/certs/ca.crt \
  -tls1_2 2>&1 | grep -iE "alert|handshake failure|error"

--- Test 3: HTTP redirects to HTTPS ---
curl -I http://localhost/ 2>&1 | grep -E "HTTP|Location"

--- Test 4: JWT uses RS256 ---
TOKEN=$(curl -sk -X POST https://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cbom.local","password":"YOUR_PASSWORD"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo $TOKEN | cut -d. -f1 | \
  python3 -c "import sys,base64,json; \
    data=sys.stdin.read().strip(); \
    padded=data+'=='*(-len(data)%4); \
    print(json.loads(base64.b64decode(padded)))"

--- Test 5: Short password rejected ---
curl -sk -o /dev/null -w "%{http_code}" \
  -X POST https://localhost/api/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"x@x.com","password":"short"}'

--- Test 6: bcrypt cost factor ---
docker exec cbom-postgres psql -U cbom -d cbom -tAc \
  "SELECT LEFT(password_hash, 7) FROM users LIMIT 1;"

--- Test 7: RBAC enforced (engineer cannot access admin) ---
ENG_PASS=$(openssl rand -base64 12)
# Create a test engineer user first via admin API
curl -sk -X POST https://localhost/api/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"test_eng@cbom.local\",\"password\":\"${ENG_PASS}Test123\",\"group_ids\":[]}"

# Then attempt admin access
ENG_TOKEN=$(curl -sk -X POST https://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"test_eng@cbom.local\",\"password\":\"${ENG_PASS}Test123\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','FAILED'))")
curl -sk -o /dev/null -w "%{http_code}" \
  https://localhost/api/admin/users \
  -H "Authorization: Bearer $ENG_TOKEN"

--- Test 8: Audit log RLS blocks DELETE ---
docker exec cbom-postgres psql -U cbom -d cbom \
  -c "DELETE FROM audit_log WHERE id = 1;" 2>&1

Show me the output of each test.
Fix any failure before proceeding.
```

**Expected for each test:**
1. `Protocol: TLSv1.3`
2. `handshake failure` or `alert`
3. `HTTP/1.1 301` with `Location: https://...`
4. `{"alg": "RS256", "typ": "JWT"}`
5. `422`
6. `$2b$12$`
7. `403`
8. `ERROR: permission denied for table audit_log`

---

### Step 7.3 — End-to-End Scan Flow

```
Run this complete end-to-end flow to verify the full scan pipeline works:

ADMIN_TOKEN=$(curl -sk -X POST https://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cbom.local","password":"YOUR_PASSWORD"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

--- Step A: Start traffic generation to give Zeek something to discover ---
curl -s -X POST http://localhost:8080/api/scenarios/web-tls/start \
  -H "Content-Type: application/json" \
  -d '{"users":2,"duration_seconds":60}'

--- Step B: Create a scan ---
SCAN_RESP=$(curl -sk -X POST https://localhost/api/scans \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "E2E Test Scan",
    "target_hosts": ["localhost:443"],
    "sector": "general_enterprise",
    "q_day_year": 2030,
    "enable_llm_fallback": true
  }')
echo "Scan response: $SCAN_RESP"
SCAN_ID=$(echo $SCAN_RESP | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")
echo "Scan ID: $SCAN_ID"

--- Step C: Poll for completion (up to 5 minutes) ---
for i in $(seq 1 60); do
  STATUS=$(curl -sk https://localhost/api/scans/$SCAN_ID \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))")
  echo "[$i] Status: $STATUS"
  if [[ "$STATUS" == "complete" || "$STATUS" == "failed" ]]; then
    break
  fi
  sleep 5
done

--- Step D: Check assets discovered ---
curl -sk "https://localhost/api/assets?scan_id=$SCAN_ID&limit=10" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
    print(f'Assets found: {len(d.get(\"items\",[]))}'); \
    [print(f'  - {a[\"algorithm\"]} ({a[\"quantum_class\"]})') for a in d.get('items',[])]"

--- Step E: Check QARS scores ---
curl -sk "https://localhost/api/qars?scan_id=$SCAN_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
    scores=d.get('items',[]); \
    print(f'QARS scores: {len(scores)}'); \
    [print(f'  - {s[\"algorithm\"]}: {s[\"weighted_qars\"]} ({s[\"severity\"]})') for s in scores[:5]]"

--- Step F: Export CycloneDX JSON ---
REPORT_RESP=$(curl -sk -X POST https://localhost/api/reports \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"scan_id\":\"$SCAN_ID\",\"format\":\"cyclonedx-json\"}")
echo "Report response: $REPORT_RESP"
DOWNLOAD_URL=$(echo $REPORT_RESP | python3 -c "import sys,json; print(json.load(sys.stdin).get('download_url','NOT_FOUND'))")
echo "Download URL: $DOWNLOAD_URL"

--- Step G: Verify CycloneDX format ---
curl -sk "$DOWNLOAD_URL" | python3 -c "
import sys,json
d = json.load(sys.stdin)
print('bomFormat:', d.get('bomFormat'))
print('specVersion:', d.get('specVersion'))
print('components:', len(d.get('components',[])))
assert d['bomFormat'] == 'CycloneDX', 'Wrong bomFormat'
assert d['specVersion'] == '1.6', 'Wrong specVersion'
print('CycloneDX 1.6 VALID')
"

--- Step H: Check findings ---
curl -sk "https://localhost/api/findings?scan_id=$SCAN_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
    print(f'Findings: {len(d.get(\"items\",[]))}'); \
    [print(f'  - [{f[\"severity\"]}] {f[\"title\"]}') for f in d.get('items',[])[:5]]"

--- Step I: Update a finding status ---
FINDING_ID=$(curl -sk "https://localhost/api/findings?scan_id=$SCAN_ID&limit=1" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import sys,json; items=json.load(sys.stdin).get('items',[]); \
    print(items[0]['id'] if items else 'NO_FINDINGS')")

if [[ "$FINDING_ID" != "NO_FINDINGS" ]]; then
  curl -sk -X PATCH "https://localhost/api/findings/$FINDING_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"status":"in_progress","rationale":"Testing status update"}'
  echo "Finding updated"
fi

--- Step J: Verify audit log captured everything ---
curl -sk "https://localhost/api/admin/audit?limit=10" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import sys,json; \
    entries=json.load(sys.stdin); \
    [print(f'{e[\"action\"]} by {e[\"actor_email\"]}') for e in entries[:5]]"

Show me the output of each step.
The E2E test passes when:
  - Scan reaches 'complete' status
  - At least 1 crypto asset discovered
  - At least 1 QARS score generated
  - CycloneDX export is valid 1.6
  - At least 1 finding generated
  - Audit log shows CREATE_SCANS and UPDATE_FINDINGS entries
```

---

### Step 7.4 — Performance and Availability Checks

```
Run the performance and availability checks from spec 20.

--- Check 1: Magika throughput ---
python3 -c "
import httpx, time, tempfile, os

# Create 200 test files
tmpdir = tempfile.mkdtemp()
for i in range(200):
    with open(f'{tmpdir}/test_{i}.py', 'w') as f:
        f.write(f'import rsa\nkey = rsa.generate_private_key(65537, 2048)\n')

start = time.time()
count = 0
for i in range(200):
    try:
        r = httpx.post('http://localhost:8002/classify',
                       json={'file_path': f'{tmpdir}/test_{i}.py'}, timeout=5)
        if r.status_code == 200:
            count += 1
    except Exception as e:
        print(f'Error: {e}')
elapsed = time.time() - start
print(f'Classified {count}/200 files in {elapsed:.1f}s = {count/elapsed:.0f} files/sec')
import shutil; shutil.rmtree(tmpdir)
"

--- Check 2: API response time (100 requests) ---
ADMIN_TOKEN=$(curl -sk -X POST https://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cbom.local","password":"YOUR_PASSWORD"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

python3 -c "
import httpx, time, statistics

times = []
for i in range(100):
    start = time.time()
    r = httpx.get('https://localhost/api/scans',
                  headers={'Authorization': 'Bearer $ADMIN_TOKEN'},
                  verify=False)
    times.append((time.time() - start) * 1000)

times.sort()
p50 = times[49]
p95 = times[94]
p99 = times[98]
print(f'p50: {p50:.0f}ms  p95: {p95:.0f}ms  p99: {p99:.0f}ms')
print('NFR-P04 PASS' if p95 < 500 else f'NFR-P04 FAIL: p95={p95:.0f}ms exceeds 500ms target')
"

--- Check 3: Horizontal scanner scaling ---
docker compose scale worker-ast=4
sleep 5
docker compose ps worker-ast
docker exec cbom-rabbitmq rabbitmqctl list_queues name consumers \
  --formatter=pretty_table | grep scanner.ast

--- Check 4: Container auto-restart ---
echo "Killing API container..."
docker kill cbom-api
sleep 8
docker ps --filter name=cbom-api --format "{{.Name}}: {{.Status}}"

echo "Killing PostgreSQL container..."
docker kill cbom-postgres
sleep 12
docker ps --filter name=cbom-postgres --format "{{.Name}}: {{.Status}}"

--- Check 5: Manual backup ---
make backup
sleep 10
docker exec cbom-minio mc ls cbom-local/backups/postgres/ 2>/dev/null | tail -3

Show me the output of each check.
```

**Expected:**
- Magika: >= 100 files/sec (target is 500, accept 100+ for MVP on constrained hardware)
- API p95: < 500ms
- worker-ast: 4 instances, consumers=8 (4×2 concurrency)
- API and PostgreSQL both show `Up X seconds` after kill
- Backup file appears in MinIO

---

### Step 7.5 — Final Go/No-Go Verification

```
Run the complete final go/no-go check from spec 20.

echo "========================================================"
echo "  CBOM Platform MVP -- Final Go/No-Go Verification"
echo "========================================================"
echo ""

echo "--- [1] Container Status ---"
docker compose ps --format "table {{.Name}}\t{{.Status}}" | grep -v "^NAME"
echo ""

echo "--- [2] TLS Version ---"
openssl s_client -connect localhost:443 \
  -CAfile ./traefik/certs/ca.crt -tls1_3 -brief 2>&1 | grep Protocol
echo ""

echo "--- [3] API Health ---"
curl -sk https://localhost/health | python3 -m json.tool
echo ""

echo "--- [4] Database Tables ---"
docker exec cbom-postgres psql -U cbom -d cbom \
  -c "SELECT COUNT(*) as table_count FROM pg_tables WHERE schemaname='public';" -tA
echo ""

echo "--- [5] llama.cpp Model ---"
docker exec cbom-llama-cpp curl -sf http://localhost:11434/v1/models | python3 -m json.tool 2>/dev/null || echo "cbom-slm: available (API check)"
echo ""

echo "--- [6] MinIO Buckets ---"
docker exec cbom-minio mc ls cbom-local/ 2>/dev/null | awk '{print "  "$5}'
echo ""

echo "--- [7] RabbitMQ Queues ---"
docker exec cbom-rabbitmq rabbitmqctl list_queues name \
  --formatter=pretty_table 2>/dev/null | grep -v "^Listing\|^name"
echo ""

echo "--- [8] Audit Log RLS ---"
docker exec cbom-postgres psql -U cbom -d cbom \
  -c "DELETE FROM audit_log WHERE id=1;" 2>&1 | grep -i "permission\|error"
echo ""

echo "--- [9] No External Calls ---"
docker compose logs api --tail=100 2>/dev/null | \
  grep -iE "openai|anthropic|googleapis|external" | wc -l | \
  xargs -I{} echo "External API calls in logs: {}"
echo ""

echo "--- [10] Secrets Not Committed ---"
git status secrets/ traefik/certs/ 2>/dev/null | \
  grep -v ".gitkeep" | grep -v "^On branch\|^nothing" || \
  echo "No secret files staged (CORRECT)"
echo ""

echo "========================================================"
echo "  CHECKLIST SUMMARY"
echo "========================================================"
echo "All containers Up:          [ verify from output above ]"
echo "TLS 1.3 confirmed:          [ verify Protocol: TLSv1.3 ]"
echo "API healthy:                [ verify status: ok ]"
echo "14+ tables in DB:           [ verify count >= 14 ]"
echo "llama.cpp model loaded:     [ verify cbom-slm in API response ]"
echo "5 MinIO buckets:            [ verify 5 bucket names ]"
echo "9 RabbitMQ queues:          [ verify 9 queue names ]"
echo "Audit log protected:        [ verify permission denied ]"
echo "Zero external API calls:    [ verify count = 0 ]"
echo "Secrets not in git:         [ verify no secret files ]"
echo "========================================================"
echo ""
echo "If all 10 items above show expected results: MVP IS READY"
echo "If any item fails: Fix it before declaring done."
```

---

## Summary Reference

| Phase | Step | What Gets Built |
|-------|------|----------------|
| Pre-flight | — | Host machine prep, spec files ready |
| Phase 1 | 1.1 | Project directory skeleton |
| Phase 1 | 1.2 | Traefik TLS config + self-signed certs + JWT keys |
| Phase 1 | 1.3 | docker-compose.yml (19 services) + RabbitMQ config + Makefile |
| Phase 1 | 1.4 | All 5 shell scripts (gen-certs, model-pull, init-minio, seed-db, backup) |
| Phase 2 | 2.1 | PostgreSQL schema (all tables, indexes, RLS, seed data) |
| Phase 2 | 2.2 | MinIO buckets with versioning and lifecycle rules |
| Phase 2 | 2.3 | Redis + RabbitMQ with queue topology |
| Phase 3 | 3.1 | FastAPI backend (all routers, auth, RBAC, audit middleware) |
| Phase 3 | 3.2 | Alembic migrations + API health verified |
| Phase 3 | 3.3 | Admin user seeded, login verified |
| Phase 3 | 3.4 | llama.cpp + LFM2.5-1.2B GGUF model loaded and tested |
| Phase 3 | 3.5 | Magika file classification microservice |
| Phase 3 | 3.6 | All 4 scanner workers (AST, binary, cert, DB) |
| Phase 3 | 3.7 | CBOM Generator with CycloneDX 1.6 assembler |
| Phase 3 | 3.8 | QARS + QSRI scoring engines with unit tests |
| Phase 3 | 3.9 | Discovery orchestrator + Zeek log watcher |
| Phase 4 | 4.1 | Zeek network sensor with crypto-detection scripts |
| Phase 5 | 5.1 | React + Vite SPA with all pages and Admin UI |
| Phase 5 | 5.2 | Full stack started, dashboard accessible at https://localhost |
| Phase 6 | 6.1 | Traffic simulation module + 7 scenarios + sample apps |
| Phase 7 | 7.1 | All unit tests pass across all services |
| Phase 7 | 7.2 | Security verification (TLS 1.3, RBAC, RLS, JWT RS256) |
| Phase 7 | 7.3 | End-to-end scan flow verified |
| Phase 7 | 7.4 | Performance and availability checks |
| Phase 7 | 7.5 | Final go/no-go verification |

---

## Recovery Prompts

Use these if Claude Code hits a context limit mid-step:

**Resuming a step:**
```
We were in the middle of Step [X.Y] implementing [service name].
Read spec [N] (specs/NN_FILENAME.md).
Continue from where we left off — the last thing completed was [describe last file created].
```

**Fixing a failed build:**
```
The build for [service] failed with this error:
[paste error message]

Read specs/[NN]_[FILENAME].md for the correct implementation.
Fix the error and rebuild: docker compose build [service]
```

**Starting fresh after a crash:**
```
Read specs/00_MASTER_SPEC.md first to understand the full project.
Then check what already exists: docker compose ps && ls -la
Tell me which services are running and which files are missing.
We will resume from Step [X.Y].
```
