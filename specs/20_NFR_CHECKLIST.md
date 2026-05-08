# 20 -- NFR Acceptance Checklist

> Final spec. Read all prior specs before using this checklist.
> This file is Claude Code's definition of "done" for the MVP.

---

## How to Use This Checklist

Each NFR has:
- **Requirement** -- what must be true
- **How to verify** -- exact command or test to run
- **Expected result** -- what passing looks like
- **Status** -- Claude Code marks `[x]` when verified

Run the full checklist before declaring the MVP complete.
All `MUST` items must pass. `SHOULD` items are best-effort for MVP.

---

## NFR-S: Security

### NFR-S01 — TLS 1.3 in Transit

**Requirement:** All external traffic uses TLS 1.3 minimum. TLS 1.2 is rejected.

**Verify:**
```bash
# Confirm TLS 1.3 is used
openssl s_client -connect localhost:443 \
  -CAfile ./traefik/certs/ca.crt \
  -tls1_3 -brief 2>&1 | grep -E "Protocol|Cipher"

# Confirm TLS 1.2 is rejected
openssl s_client -connect localhost:443 \
  -CAfile ./traefik/certs/ca.crt \
  -tls1_2 2>&1 | grep -i "alert\|error\|handshake failure"

# Confirm HTTP redirects to HTTPS
curl -I http://localhost/ 2>&1 | grep -E "HTTP|Location"
```

**Expected:**
```
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384

# TLS 1.2 attempt:
140...alert handshake failure

# HTTP redirect:
HTTP/1.1 301 Moved Permanently
Location: https://localhost/
```

- [ ] TLS 1.3 confirmed
- [ ] TLS 1.2 rejected
- [ ] HTTP redirects to HTTPS

---

### NFR-S02 — AES-256-GCM at Rest

**Requirement:** MinIO uses SSE-S3 AES-256. PostgreSQL data on encrypted host volume.

**Verify:**
```bash
# Check MinIO encryption on a test upload
echo "test" | docker exec -i cbom-minio mc pipe cbom-local/cbom-exports/test.txt
docker exec cbom-minio mc stat cbom-local/cbom-exports/test.txt | grep -i encrypt

# Verify PostgreSQL data directory path (operator confirms host volume encryption)
docker exec cbom-postgres psql -U cbom -d cbom -c "SHOW data_directory;"
```

**Expected:**
```
Encryption: SSE-S3

data_directory
-----------------------------
/var/lib/postgresql/data/pgdata
```

- [ ] MinIO SSE-S3 enabled on uploaded objects
- [ ] PostgreSQL data directory confirmed (host volume encryption documented)

---

### NFR-S03 — RBAC, 5 Roles

**Requirement:** Five predefined roles enforced. Wrong role returns 403.

**Verify:**
```bash
# Get engineer token
ENG_TOKEN=$(curl -sk -X POST https://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"engineer@test.com","password":"TestPass123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Engineer attempting admin endpoint -> 403
curl -sk -o /dev/null -w "%{http_code}" \
  https://localhost/api/admin/users \
  -H "Authorization: Bearer $ENG_TOKEN"

# Auditor attempting scan creation -> 403
AUD_TOKEN=$(curl -sk -X POST https://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"auditor@test.com","password":"TestPass123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -sk -o /dev/null -w "%{http_code}" \
  -X POST https://localhost/api/scans \
  -H "Authorization: Bearer $AUD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test"}'
```

**Expected:** `403` for both calls.

- [ ] Engineer cannot access admin endpoints (403)
- [ ] Auditor cannot create scans (403)
- [ ] All 5 roles seeded in database: `SELECT name, rbac_role FROM groups;`

---

### NFR-S04 — Auth (JWT + Password)

**Requirement:** JWT RS256, bcrypt cost 12, passwords >= 12 chars enforced.

**Verify:**
```bash
# Decode JWT header to confirm RS256
TOKEN=$(curl -sk -X POST https://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cbom.local","password":"YourAdminPass"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool

# Verify short password is rejected
curl -sk -o /dev/null -w "%{http_code}" \
  -X POST https://localhost/api/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"x@x.com","password":"short"}'

# Verify bcrypt cost in DB
docker exec cbom-postgres psql -U cbom -d cbom -tAc \
  "SELECT LEFT(password_hash, 7) FROM users LIMIT 1;"
```

**Expected:**
```json
{"alg": "RS256", "typ": "JWT"}

422   # short password rejected

$2b$12$  # bcrypt cost factor 12
```

- [ ] JWT uses RS256 algorithm
- [ ] Short password (< 12 chars) returns 422
- [ ] Password hash starts with `$2b$12$` (bcrypt cost 12)

---

### NFR-S05 — Audit Log, Append-Only

**Requirement:** Audit log written for all mutations. DELETE/UPDATE blocked by RLS.

**Verify:**
```bash
# Create a scan and check audit log entry appears
curl -sk -X POST https://localhost/api/scans \
  -H "Authorization: Bearer $ENG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"audit-test","target_hosts":["localhost:443"]}'

# Check audit log
docker exec cbom-postgres psql -U cbom -d cbom -c \
  "SELECT action, resource_type, actor_email, created_at
   FROM audit_log ORDER BY created_at DESC LIMIT 5;"

# Attempt DELETE on audit_log (must fail)
docker exec cbom-postgres psql -U cbom -d cbom -c \
  "DELETE FROM audit_log WHERE id = 1;" 2>&1
```

**Expected:**
```
action       | resource_type | actor_email
-------------+---------------+--------------
CREATE_SCANS | scans         | engineer@...

# DELETE attempt:
ERROR:  permission denied for table audit_log
```

- [ ] Audit entry created for POST /api/scans
- [ ] Direct DELETE on audit_log returns permission denied
- [ ] Audit log contains actor_email, action, resource_type, created_at

---

### NFR-S07 — Data Residency (No External Calls)

**Requirement:** No runtime traffic to external hosts. All services on-prem.

**Verify:**
```bash
# Monitor outbound network traffic during a full scan
docker run --rm --network host \
  nicolaka/netshoot \
  tcpdump -i any -nn 'not (host 127.0.0.1 or net 172.16.0.0/12 or net 192.168.0.0/16 or net 10.0.0.0/8)' \
  -c 100 &

# Trigger a scan
curl -sk -X POST https://localhost/api/scans \
  -H "Authorization: Bearer $ENG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"residency-test","enable_llm_fallback":true}'

sleep 30
kill %1
```

**Expected:** No packets captured to external IPs (0 packets or only internal addresses).

- [ ] Zero external network calls during scan with LLM fallback enabled
- [ ] Ollama model loaded from local volume (no download during scan)

---

## NFR-P: Performance

### NFR-P01 — 10,000 Files in Under 4 Hours

**Verify:**
```bash
# Generate 10,000 small Python files with crypto patterns
python3 -c "
import os, random
os.makedirs('/tmp/perf-test', exist_ok=True)
algos = ['rsa.generate_private_key(65537, 2048)', 'hashlib.sha256()', 'AES.new(key, AES.MODE_GCM)']
for i in range(10000):
    with open(f'/tmp/perf-test/test_{i}.py', 'w') as f:
        f.write(f'import hashlib\nimport rsa\nfrom Crypto.Cipher import AES\n{random.choice(algos)}\n')
"

# Time the scan
time curl -sk -X POST https://localhost/api/scans \
  -H "Authorization: Bearer $ENG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"perf-test","target_repos":["/tmp/perf-test"]}'
```

**Expected:** Scan of 10,000 files completes in under 4 hours (14,400 seconds).

- [ ] 10,000-file scan completes in < 4 hours with 4 AST workers

---

### NFR-P02 — Magika >= 500 Files/Second

**Verify:**
```bash
# Benchmark Magika classification speed
python3 -c "
import httpx, time, os, glob

files = glob.glob('/tmp/perf-test/*.py')[:1000]
start = time.time()
for f in files:
    httpx.post('http://localhost:8002/classify', json={'file_path': f}, timeout=5)
elapsed = time.time() - start
print(f'Classified {len(files)} files in {elapsed:.1f}s = {len(files)/elapsed:.0f} files/sec')
"
```

**Expected:** >= 500 files/second throughput.

- [ ] Magika throughput >= 500 files/sec confirmed

---

### NFR-P04 — API p95 Response < 500ms

**Verify:**
```bash
# Install vegeta load tester
# Then run 100 concurrent users for 60 seconds
echo "GET https://localhost/api/scans" | \
  vegeta attack -rate=100 -duration=60s \
    -header="Authorization: Bearer $ENG_TOKEN" \
    -insecure | \
  vegeta report -type=text

# Or using Apache Bench:
ab -n 1000 -c 100 \
   -H "Authorization: Bearer $ENG_TOKEN" \
   https://localhost/api/scans 2>&1 | grep -E "p99|p95|Time per request"
```

**Expected:** p95 response time < 500ms at 100 concurrent users.

- [ ] p95 API response < 500ms at 100 concurrent users

---

### NFR-P05 — Horizontal Scanner Scaling

**Verify:**
```bash
# Scale AST workers to 4 replicas
docker compose scale worker-ast=4

# Verify 4 instances running
docker compose ps worker-ast

# Run scan and confirm all 4 workers pick up jobs (check logs)
docker compose logs worker-ast --tail=50 | grep "task received"
```

**Expected:** 4 `cbom-worker-ast` containers running and all processing jobs.

- [ ] `docker compose scale worker-ast=4` works without errors
- [ ] All 4 worker instances visible in `docker compose ps`
- [ ] Jobs distributed across all 4 workers (visible in logs)

---

## NFR-A: Availability

### NFR-A01 — 99.9% Uptime (restart: unless-stopped)

**Verify:**
```bash
# Kill API container and confirm it auto-restarts
docker kill cbom-api
sleep 5
docker ps --filter name=cbom-api --format "{{.Status}}"

# Kill PostgreSQL and confirm it auto-restarts
docker kill cbom-postgres
sleep 10
docker ps --filter name=cbom-postgres --format "{{.Status}}"
```

**Expected:** Both containers show `Up X seconds` (restarted automatically).

- [ ] API container restarts automatically after kill
- [ ] PostgreSQL restarts automatically after kill
- [ ] All containers have `restart: unless-stopped` in docker-compose.yml

---

### NFR-A02 — RTO 4h, RPO 1h

**Verify:**
```bash
# Create test data
curl -sk -X POST https://localhost/api/scans \
  -H "Authorization: Bearer $ENG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"rpo-test"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])"

# Run manual backup
make backup

# Confirm backup exists in MinIO
docker exec cbom-minio mc ls cbom-local/backups/postgres/ | tail -5

# Simulate restore (test only -- do not run on production data)
# make restore BACKUP=cbom-YYYYMMDD-HHMMSS.sql.gz
```

**Expected:** Backup file appears in MinIO within 60 seconds of `make backup`.

- [ ] Manual backup completes successfully
- [ ] Backup file visible in MinIO `backups/postgres/` bucket
- [ ] Restore script (`scripts/backup.sh`) documented and tested

---

### NFR-A03 — Zeek 24h Local Buffer

**Verify:**
```bash
# Stop orchestrator (simulates connectivity loss)
docker compose stop orchestrator

# Generate traffic (Zeek should keep logging)
curl -sk https://localhost/api/health > /dev/null

sleep 10

# Confirm Zeek still writing logs
ls -la shared/zeek-logs/ | tail -5

# Restart orchestrator and confirm it picks up buffered logs
docker compose start orchestrator
sleep 15
docker compose logs orchestrator --tail=30 | grep -i "log\|processed\|asset"
```

**Expected:** Zeek logs accumulate while orchestrator is down. Orchestrator processes them on restart.

- [ ] Zeek continues writing logs when orchestrator is stopped
- [ ] Orchestrator processes accumulated logs on restart

---

## NFR-C: Compliance

### NFR-C01 — CycloneDX 1.6 Compliance

**Verify:**
```bash
# Run a scan, then export CBOM
SCAN_ID=$(curl -sk -X POST https://localhost/api/scans \
  -H "Authorization: Bearer $ENG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"cyclonedx-test","target_hosts":["localhost:443"]}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")

sleep 30  # Wait for scan

# Export CycloneDX JSON
curl -sk https://localhost/api/cbom/$SCAN_ID \
  -H "Authorization: Bearer $ENG_TOKEN" \
  -o /tmp/cbom-test.json

# Validate against CycloneDX schema
pip install cyclonedx-python-lib --quiet
python3 -c "
import json
from cyclonedx.validation.json import JsonValidator
with open('/tmp/cbom-test.json') as f:
    data = f.read()
validator = JsonValidator()
result = validator.validate_as_string(data)
print('Valid:', result.valid)
if not result.valid:
    print('Errors:', result.errors)
"

# Confirm specVersion is 1.6
python3 -c "import json; d=json.load(open('/tmp/cbom-test.json')); print('specVersion:', d.get('specVersion'))"
```

**Expected:**
```
Valid: True
specVersion: 1.6
```

- [ ] CycloneDX JSON validates against 1.6 schema
- [ ] `specVersion` field equals `"1.6"`
- [ ] `bomFormat` field equals `"CycloneDX"`
- [ ] All assets have `cryptoProperties.assetType` populated

---

### NFR-C02 — NIST FIPS 203/204/205 PQC Recommendations

**Verify:**
```bash
# Check that all vulnerable assets have NIST-approved PQC replacements
docker exec cbom-postgres psql -U cbom -d cbom -c "
  SELECT DISTINCT algorithm, pqc_replacement
  FROM crypto_assets
  WHERE quantum_class = 'vulnerable'
  ORDER BY algorithm;
"
```

**Expected:** Every vulnerable algorithm maps to ML-KEM-xxx (FIPS 203) or ML-DSA-xx (FIPS 204) or SLH-DSA (FIPS 205). No non-NIST replacements.

- [ ] RSA -> ML-KEM-768 (FIPS 203) or ML-DSA-65 (FIPS 204)
- [ ] ECDSA -> ML-DSA-65 (FIPS 204)
- [ ] ECDH -> ML-KEM-768 (FIPS 203)
- [ ] DH -> ML-KEM-768 (FIPS 203)
- [ ] ED25519 -> ML-DSA-44 (FIPS 204)
- [ ] No non-NIST PQC recommendations present

---

### NFR-C03 — GDPR Article 32 (On-Prem, No Data Exfiltration)

**Verify:**
```bash
# Confirm no external DNS queries during operation
docker exec cbom-api cat /etc/resolv.conf

# Confirm no external API calls in API logs
docker compose logs api --tail=200 | grep -i "http.*external\|api.openai\|anthropic\|googleapis" | wc -l
```

**Expected:**
```
# resolv.conf: only internal/Docker DNS resolver
nameserver 127.0.0.11

# External API call count:
0
```

- [ ] All DNS resolution is internal (Docker internal resolver only)
- [ ] Zero external API calls in application logs
- [ ] Ollama serves model locally (no external inference API)

---

## NFR-U: Usability

### NFR-U01 — 30-Minute Onboarding

**Verify:** Time a fresh deployment from git clone to first successful login.

```bash
# Fresh clone
time (
  git clone <repo> /tmp/cbom-fresh && \
  cd /tmp/cbom-fresh && \
  cp .env.example .env && \
  make setup && \
  make pull-model && \
  make up
)
```

**Expected:** Total time <= 30 minutes (excluding model download on slow connections).

**Checklist:**
- [ ] `make setup` completes without manual intervention
- [ ] `make up` starts all 19 containers successfully
- [ ] First login works at `https://localhost` after setup
- [ ] README quickstart has exactly 5 steps (no more)

---

### NFR-U02 — CISO Dashboard in Business Language

**Verify:** Open the dashboard as a CISO user and confirm no algorithm names are visible on the default view.

```bash
# Login as CISO and fetch dashboard data
CISO_TOKEN=$(curl -sk -X POST https://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ciso@test.com","password":"TestPass123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Check dashboard summary endpoint
curl -sk https://localhost/api/qars \
  -H "Authorization: Bearer $CISO_TOKEN" | python3 -m json.tool | head -30
```

**Expected:** CISO dashboard shows:
- "Critical assets requiring immediate action: N" (not "RSA-2048 at location X")
- QSRI score as a single number (not raw dimension data)
- Compliance status as PASS/FAIL per framework (not control IDs)

- [ ] CISO view uses plain business language (no raw algorithm names in summary)
- [ ] QSRI displayed as 0-100 score with status label
- [ ] Compliance shown as DORA: ✓/✗, NIS2: ✓/✗, NSM-10: ✓/✗

---

## Final Go/No-Go Summary

Run this block after all individual checks above:

```bash
echo "==> CBOM Platform MVP -- Final Verification"
echo ""

# Service health
echo "--- Container Status ---"
docker compose ps --format "table {{.Name}}\t{{.Status}}" | grep -v "Exit\|unhealthy"

# TLS
echo ""
echo "--- TLS Version ---"
openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep Protocol

# API health
echo ""
echo "--- API Health ---"
curl -sk https://localhost/health | python3 -m json.tool

# Database
echo ""
echo "--- Database Tables ---"
docker exec cbom-postgres psql -U cbom -d cbom -c \
  "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;" -tA | tr '\n' ', '

# Ollama model
echo ""
echo "--- Ollama Model ---"
docker exec cbom-ollama ollama list | grep gemma2

# MinIO buckets
echo ""
echo "--- MinIO Buckets ---"
docker exec cbom-minio mc ls cbom-local/ 2>/dev/null | awk '{print $5}'

# Audit log RLS
echo ""
echo "--- Audit Log RLS ---"
docker exec cbom-postgres psql -U cbom -d cbom -c \
  "DELETE FROM audit_log WHERE id=1;" 2>&1 | grep -i "permission\|error"

echo ""
echo "==> Verification complete. Review any failures above."
```

**All of the following must be true for MVP sign-off:**

- [ ] All 19 containers show `Up` status (no `Exit` or `unhealthy`)
- [ ] TLS 1.3 confirmed
- [ ] API `/health` returns `{"status": "ok"}`
- [ ] All 14 database tables present
- [ ] Gemma 2 2B model listed in Ollama
- [ ] All 5 MinIO buckets present
- [ ] Audit log DELETE blocked by RLS
- [ ] All `MUST` NFR items above checked
- [ ] Unit test coverage >= 80% on critical modules
- [ ] E2E login + scan create flow passes
- [ ] Zero external network calls during operation
- [ ] `make setup` completes in <= 30 minutes from scratch
