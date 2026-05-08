# MVP Architecture: Quantum-Safe CBOM Discovery Platform

> **Document Type:** Solution Architecture — MVP
> **Version:** 1.0 | **Status:** Draft | **Classification:** Confidential | **Date:** June 2025
> **Derived from:** BRD v1.0 (Quantum-Safe CBOM Discovery Platform)
> **Architect:** Senior Solutions Architect

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Design Decisions & Constraints](#2-design-decisions--constraints)
3. [Tech Stack](#3-tech-stack)
4. [Service Catalogue (Docker Compose)](#4-service-catalogue-docker-compose)
5. [Module Descriptions](#5-module-descriptions)
   - 5.1 [Reverse Proxy — Traefik](#51-reverse-proxy--traefik)
   - 5.2 [Frontend — React + Vite](#52-frontend--react--vite)
   - 5.3 [Backend API — FastAPI](#53-backend-api--fastapi)
   - 5.4 [Admin UI (Embedded in React)](#54-admin-ui-embedded-in-react)
   - 5.5 [Discovery Orchestrator](#55-discovery-orchestrator)
   - 5.6 [Scanner Workers](#56-scanner-workers)
   - 5.7 [CBOM Generator](#57-cbom-generator)
   - 5.8 [QARS Scoring Engine](#58-qars-scoring-engine)
   - 5.9 [QSRI Scoring Engine](#59-qsri-scoring-engine)
   - 5.10 [Magika File Router](#510-magika-file-router)
   - 5.11 [SLM Service — Ollama + Gemma 2 2B](#511-slm-service--ollama--gemma-2-2b)
   - 5.12 [Message Broker — RabbitMQ](#512-message-broker--rabbitmq)
   - 5.13 [Primary Database — PostgreSQL 16](#513-primary-database--postgresql-16)
   - 5.14 [Object Storage — MinIO](#514-object-storage--minio)
   - 5.15 [Cache & Session Store — Redis](#515-cache--session-store--redis)
   - 5.16 [Network Sensor — Zeek](#516-network-sensor--zeek)
   - 5.17 [Traffic Generation & Simulation Module](#517-traffic-generation--simulation-module)
   - 5.18 [Monitoring — Portainer](#518-monitoring--portainer)
6. [Data Flows](#6-data-flows)
7. [Security Architecture](#7-security-architecture)
8. [NFR Implementation Map](#8-nfr-implementation-map)
9. [Docker Compose Service Map](#9-docker-compose-service-map)
10. [Directory Structure](#10-directory-structure)
11. [Hardware Requirements (MVP)](#11-hardware-requirements-mvp)
12. [MVP Scope Boundaries](#12-mvp-scope-boundaries)
13. [Post-MVP Upgrade Path](#13-post-mvp-upgrade-path)

---

## 1. Architecture Overview

The MVP is a **fully on-premises, Docker Compose-based** deployment of the Quantum-Safe CBOM Discovery Platform. All services run as containers on a single host (or small cluster). There are no cloud dependencies. Every piece of data — CBOM assets, scan results, SLM model weights, object storage — stays within the client's network boundary.

### Guiding Principles

| Principle | MVP Decision |
|-----------|-------------|
| Air-gapped ready | Zero external network calls at runtime. All models and base images pre-pulled. |
| Single-host MVP | Docker Compose only. Kubernetes upgrade path documented but not in scope. |
| TLS everywhere | Traefik terminates TLS 1.3 with a self-signed wildcard cert. All inter-service traffic on Docker internal network. |
| No API Gateway | Traefik handles routing, rate-limiting, and TLS termination. FastAPI handles auth. |
| Local SLM only | Ollama serves Gemma 2 2B. No external LLM API calls. |
| Simple auth | JWT-based auth in FastAPI. RBAC enforced per endpoint. Admin UI embedded in React. |

### Architecture Layers

```
+----------------------------------------------------------+
|  CLIENT BROWSER / CLI / REST CLIENT                      |
+----------------------------------------------------------+
          | HTTPS (TLS 1.3, self-signed cert, port 443)
+----------------------------------------------------------+
|  TRAEFIK v3  (Reverse Proxy + TLS Termination)           |
|  Port 443 -> Frontend :3000                              |
|  Port 443 -> API      :8000                              |
|  Port 443 -> MinIO    :9001                              |
+----------------------------------------------------------+
          |                     |
+---------+---------+   +-------+--------+
|  REACT FRONTEND   |   |  FASTAPI       |
|  + Admin UI       |   |  Backend API   |
|  Vite/Nginx:3000  |   |  Uvicorn:8000  |
+-------------------+   +-------+--------+
                                |
        +-----------------------+------------------------+
        |                       |                        |
+-------+-------+    +----------+--------+   +-----------+--------+
|  RabbitMQ     |    |  PostgreSQL 16    |   |  Redis 7           |
|  Message      |    |  Primary DB       |   |  Session + Cache   |
|  Broker :5672 |    |  :5432            |   |  :6379             |
+-------+-------+    +-------------------+   +--------------------+
        |
+-------+------------------+------------------+------------------+
|                           |                  |                  |
+-------+-------+  +--------+------+  +--------+------+  +-------+-------+
| Discovery     |  | Scanner       |  | CBOM          |  | Scoring       |
| Orchestrator  |  | Workers       |  | Generator     |  | Engine        |
| :8001         |  | (AST/Bin/Cert |  | :8003         |  | QARS+QSRI     |
|               |  |  DB/Magika)   |  |               |  | :8004         |
+---------------+  +---------------+  +---------------+  +-------+-------+
                                                                  |
                                               +------------------+
                                               |  Ollama SLM      |
                                               |  Gemma 2 2B      |
                                               |  :11434          |
                                               +------------------+
+----------------------------------------------------------+
|  MinIO Object Storage  (exports, logs, CBOM archives)    |
|  API :9000  |  Console :9001                             |
+----------------------------------------------------------+
+----------------------------------------------------------+
|  ZEEK Network Sensor  (host network mode)                |
|  Passive TLS/SSH/X.509 capture -> shared volume          |
+----------------------------------------------------------+
+----------------------------------------------------------+
|  TRAFFIC GEN & SIMULATION MODULE  (separate container)   |
|  Demo + benchmark scenarios  :8080                       |
+----------------------------------------------------------+
+----------------------------------------------------------+
|  PORTAINER  (Docker management UI)  :9443                |
+----------------------------------------------------------+
```

---

## 2. Design Decisions & Constraints

### Why Traefik (not Nginx) for TLS Termination

Traefik v3 was chosen over Nginx for the following reasons:

- **Zero-config Docker routing**: Traefik reads Docker labels to auto-configure routes. Adding a new service requires no Nginx config reload.
- **Self-signed cert built-in**: Traefik generates a self-signed wildcard cert automatically for MVP with one config line. Swap to ACME/custom CA for production with zero code change.
- **TLS 1.3 enforcement**: Configurable minimum TLS version with a single yaml option (`minVersion: VersionTLS13`).
- **Dashboard**: Built-in routing dashboard at `:8080` (internal only, not exposed externally).
- **No API Gateway needed**: Traefik handles path-based routing (`/api/*` to FastAPI, `/*` to React), rate limiting via middleware, and header injection.

### Why FastAPI (not Django/Flask)

- Async-native: handles concurrent scan job status polling without blocking.
- Auto-generates OpenAPI/Swagger docs for the REST API — useful for CLI SDK generation.
- Pydantic v2 models map directly to CycloneDX CBOM JSON schema.
- JWT middleware is 10 lines with `python-jose`.
- Performance: Uvicorn + FastAPI handles 10,000+ req/s on a single core — more than enough for MVP.

### Why RabbitMQ (not Kafka/Redis Streams)

- **Durable queues**: scan jobs survive service restarts. Kafka is operationally heavier for MVP scale.
- **Dead-letter queues**: failed scans are automatically routed to a DLQ for inspection.
- **Management UI**: built-in at `:15672` — operators can inspect queues, replay messages, and purge without CLI.
- **Work queue pattern**: perfect for fan-out to scanner workers (one job picked up by exactly one worker).
- **Celery native**: Python's Celery task queue uses RabbitMQ as its default broker, giving us retry logic, rate limiting, and task scheduling for free.

### Why MinIO (not NFS/local disk)

- **S3-compatible API**: boto3/s3fs clients work identically. Zero code change if a client later migrates to AWS S3.
- **Versioned buckets**: CBOM exports are versioned automatically — audit trail for free.
- **Console UI**: built-in web console for operators to browse exports, CBOM archives, and Zeek log files.
- **Multipart uploads**: large Zeek log files (multi-GB) upload efficiently.
- **Encryption at rest**: server-side encryption with AES-256 configurable via env vars.

### Why Ollama + Gemma 2 2B (not API-based LLM)

- **Air-gapped**: zero external API calls. Model weights stored on-disk.
- **Gemma 2 2B choice**: Google's Gemma 2 2B fits in 4 GB VRAM (or runs on CPU-only with 8 GB RAM). Its code understanding benchmark scores are competitive with Mistral 7B at half the memory footprint — ideal for an MVP host with constrained resources.
- **Fallback-only usage**: the SLM is only invoked when Magika + AST scanners cannot classify a file (estimated <5% of files). Low throughput requirement.
- **OpenAI-compatible API**: Ollama exposes `/v1/chat/completions`. If a client wants to swap to a larger model (Mistral 7B, CodeLlama 13B) in production, it is a one-line model name change.

### Why PostgreSQL 16 (plain, no TimescaleDB for MVP)

- TimescaleDB adds operational complexity for MVP. Plain PostgreSQL handles QARS time-series adequately with a `scan_results` table partitioned by `scan_date`.
- QARS trending (showing score improvement over time) is implemented as a simple time-ordered query — no hypertable required for MVP scale (<1M assets).
- TimescaleDB is documented as the v1.1 upgrade path.

### Why Portainer (not Prometheus + Grafana)

- Single container, zero config.
- Provides container log streaming, health status, resource usage, and manual container restarts.
- Prometheus + Grafana is the v1.1 upgrade path and is pre-wired (FastAPI exposes `/metrics` endpoint from Day 1 using `prometheus-fastapi-instrumentator`).

---

## 3. Tech Stack

### Summary Table

| Layer | Technology | Version | Justification |
|-------|-----------|---------|---------------|
| Reverse proxy / TLS | Traefik | v3.x | Docker-native routing, self-signed TLS 1.3, no config reload |
| Frontend | React + Vite | React 18, Vite 5 | Fast HMR, tree-shaking, admin UI embedded |
| UI component library | shadcn/ui + Tailwind CSS | Latest | Accessible, unstyled primitives — no vendor lock-in |
| State management | Zustand | v4 | Lightweight, no Redux boilerplate |
| Charts / radar | Recharts | v2 | QSRI radar, QARS trend charts — React-native |
| Backend API | FastAPI | v0.111+ | Async, OpenAPI auto-docs, Pydantic v2 |
| Task queue | Celery | v5 | Worker pool, retries, DLQ routing |
| ASGI server | Uvicorn | v0.29+ | Production ASGI, works with Gunicorn for multi-worker |
| Message broker | RabbitMQ | 3.13-management | Durable queues, DLQ, management UI |
| Primary database | PostgreSQL | 16-alpine | CBOM assets, users, findings, scan history |
| Cache + sessions | Redis | 7-alpine | JWT session blacklist, scan status cache |
| Object storage | MinIO | Latest AGPL | S3-compatible, versioned, AES-256 at rest |
| File router | Magika | v0.5+ | 200+ content types, 5ms/file |
| Network sensor | Zeek | 6.x | Passive TLS/SSH/X.509 capture |
| AST scanner | Tree-sitter | v0.22+ | Python/Java/Go/JS/C/C++ AST parsing |
| Local SLM | Ollama + Gemma 2 2B | Ollama 0.3+ | Air-gapped, 4 GB VRAM, code understanding |
| Auth | FastAPI + python-jose | JWT RS256 | Stateless JWT, RBAC middleware |
| Migrations | Alembic | v1.13+ | PostgreSQL schema versioning |
| Container runtime | Docker + Compose | Docker 26+, Compose v2 | MVP orchestration, no K8s |
| Container UI | Portainer CE | v2.x | Docker management, log streaming |
| Traffic simulation | Python + Locust | Locust v2 | HTTP/SSH/DB scenario scripting + benchmarking |

---

## 4. Service Catalogue (Docker Compose)

| Service Name | Image | Internal Port | Exposed Port | Purpose |
|-------------|-------|--------------|-------------|---------|
| `traefik` | traefik:v3 | 80, 443, 8080 | 443 | TLS termination, reverse proxy |
| `frontend` | custom/react | 3000 | — (via Traefik) | React SPA + Admin UI |
| `api` | custom/fastapi | 8000 | — (via Traefik) | REST API, auth, RBAC |
| `orchestrator` | custom/orchestrator | 8001 | — (internal) | Scan job scheduling |
| `worker-ast` | custom/scanner | — | — (internal) | AST scanner worker |
| `worker-binary` | custom/scanner | — | — (internal) | Binary scanner worker |
| `worker-cert` | custom/scanner | — | — (internal) | Certificate/TLS scanner |
| `worker-db` | custom/scanner | — | — (internal) | DB encryption scanner |
| `worker-magika` | custom/magika | 8002 | — (internal) | File type classification |
| `cbom-generator` | custom/cbom | 8003 | — (internal) | CycloneDX CBOM assembly |
| `scoring-engine` | custom/scoring | 8004 | — (internal) | QARS + QSRI computation |
| `ollama` | ollama/ollama | 11434 | — (internal) | Gemma 2 2B SLM serving |
| `rabbitmq` | rabbitmq:3.13-management | 5672, 15672 | 15672 (optional internal) | Message broker |
| `postgres` | postgres:16-alpine | 5432 | — (internal) | Primary database |
| `redis` | redis:7-alpine | 6379 | — (internal) | Cache + sessions |
| `minio` | minio/minio | 9000, 9001 | — (via Traefik) | Object storage |
| `zeek` | zeek/zeek:6 | — | — (host network) | Network capture sensor |
| `traffic-sim` | custom/traffic-sim | 8080 | 8080 | Traffic gen + benchmark UI |
| `portainer` | portainer/portainer-ce | 9000, 9443 | 9443 | Container management UI |

**Total: 19 containers**

---

## 5. Module Descriptions

### 5.1 Reverse Proxy — Traefik

**Image:** `traefik:v3`
**Role:** Single entry point for all external traffic. Terminates TLS 1.3 using a self-signed wildcard certificate generated at startup. Routes requests by path prefix to the appropriate backend service.

**Key configuration:**

```yaml
# traefik.yml
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    http:
      tls:
        options: tlsOptions
tls:
  options:
    tlsOptions:
      minVersion: VersionTLS13
      cipherSuites:
        - TLS_AES_256_GCM_SHA384
        - TLS_CHACHA20_POLY1305_SHA256
```

**Routing rules:**
- `Host(*) && PathPrefix(/api)` → `api:8000`
- `Host(*) && PathPrefix(/minio)` → `minio:9001`
- `Host(*)` → `frontend:3000`

**Self-signed cert:** Generated by Traefik on first start using `tls.certificates` with a locally-generated CA. For MVP, clients add the CA cert to their browser trust store. Script provided in `scripts/gen-certs.sh`.

---

### 5.2 Frontend — React + Vite

**Image:** `custom/frontend` (Nginx serving built React SPA)
**Role:** Single-page application serving all user-facing views. Role-based views rendered client-side based on JWT claims.

**Role-based views:**

| Role | Views Available |
|------|----------------|
| `admin` | All views + Admin UI (users, groups, RBAC) |
| `engineer` | Dashboard, Scans, CBOM Explorer, Findings, Certificates |
| `ciso` | QARS Dashboard, QSRI Radar, Compliance Reports, Migration Roadmap |
| `auditor` | Read-only Findings, Certificates, Compliance Export |
| `ceo` | Executive KPI Dashboard only |

**Key pages:**
- `/dashboard` — CBOM summary, QARS score, QSRI gauge
- `/scans` — Start/schedule/view scans, real-time progress via WebSocket
- `/cbom` — Asset explorer, filter by algorithm/vulnerability/location
- `/findings` — Finding list, assign owner, track status
- `/certs` — Certificate inventory, expiry alerts
- `/reports` — Export CBOM (JSON/CSV/PDF), compliance packages
- `/admin` — User management, group management, RBAC assignment (admin only)
- `/qsri` — QSRI radar chart, dimension scores, improvement roadmap
- `/roadmap` — PQC migration roadmap, phased timeline

---

### 5.3 Backend API — FastAPI

**Image:** `custom/api`
**Role:** REST API for all frontend and CLI interactions. Handles authentication, authorization, and proxies task dispatch to the orchestrator.

**Auth flow:**
1. `POST /auth/login` — validates credentials against PostgreSQL, returns JWT (RS256, 1h expiry)
2. JWT decoded on every request via FastAPI dependency injection
3. RBAC checked against `user.roles` claim — endpoint-level permission decorators
4. Refresh tokens stored in Redis (7-day expiry, revocable)

**Key API groups:**

| Prefix | Description |
|--------|-------------|
| `/auth` | Login, logout, refresh, password change |
| `/api/scans` | Create, list, cancel, status of discovery scans |
| `/api/cbom` | CBOM CRUD, version comparison, export |
| `/api/findings` | Finding management, status workflow |
| `/api/certs` | Certificate inventory, expiry alerts |
| `/api/assets` | Crypto asset query, filter, annotate |
| `/api/qars` | QARS scores, Mosca breakdown, trend |
| `/api/qsri` | QSRI scores, dimension detail, roadmap |
| `/api/reports` | Generate and download compliance packages |
| `/api/admin` | User CRUD, group CRUD, RBAC assignment |
| `/api/traffic` | Start/stop/status traffic simulation scenarios |
| `/metrics` | Prometheus metrics endpoint |
| `/health` | Health check |

---

### 5.4 Admin UI (Embedded in React)

**Approach:** Protected `/admin` route in the React SPA, visible only to users with `admin` role.

**Features:**
- **User management:** Create, edit, deactivate users. Set password. Assign groups.
- **Group management:** Create groups (e.g. `security-team`, `auditors`). Define group RBAC role.
- **RBAC roles:** Five predefined roles — `admin`, `engineer`, `ciso`, `auditor`, `ceo`. Groups are assigned exactly one role.
- **Audit log viewer:** Last 100 admin actions with timestamp, actor, and change summary.
- **Session management:** View active sessions, revoke individual sessions.

**Pre-defined RBAC roles:**

| Role | Permissions |
|------|-------------|
| `admin` | Full access including user/group management |
| `engineer` | Scan execution, CBOM CRUD, findings workflow, export |
| `ciso` | Read-all, approve/defer findings, export compliance packages |
| `auditor` | Read-only on all resources, export only |
| `ceo` | Executive KPI dashboard only |

---

### 5.5 Discovery Orchestrator

**Image:** `custom/orchestrator`
**Role:** Receives scan requests from the API, decomposes them into individual scan jobs, and publishes tasks to RabbitMQ queues. Tracks scan state in PostgreSQL and Redis.

**Scan decomposition:**

```
ScanRequest
  ├── network_capture_job   → queue: zeek.capture
  ├── repo_crawl_job        → queue: scanner.ast
  ├── cert_probe_job        → queue: scanner.cert
  ├── db_probe_job          → queue: scanner.db
  └── binary_scan_job       → queue: scanner.binary
```

**State machine:** `queued` → `running` → `partial` → `complete` | `failed`

**Scan config parameters:**
- `target_repos`: list of git URLs or local paths
- `target_hosts`: list of IPs/hostnames for TLS probing
- `target_db_connections`: encrypted DB connection strings
- `network_interface`: interface for Zeek capture
- `max_file_depth`: default 5 (FR-D08)
- `enable_llm_fallback`: bool (default true)

---

### 5.6 Scanner Workers

All scanners are Celery workers consuming from dedicated RabbitMQ queues. Each worker type is a separate container for independent scaling.

#### AST Scanner (`worker-ast`)

**Queue:** `scanner.ast`
**Languages:** Python, Java, Go, JavaScript/TypeScript, C, C++
**Engine:** Tree-sitter v0.22 with language-specific grammars
**Pipeline per file:**
1. Magika classifies file type (via internal HTTP call to `worker-magika`)
2. If source code → parse AST → walk nodes for crypto API patterns
3. If unclassified (Magika score < 0.6) → send to Ollama SLM for semantic analysis
4. Emit `CryptoAssetFound` events to `cbom.ingest` queue

**Algorithm detection patterns:**

```python
CRYPTO_PATTERNS = {
    "python": [
        r'from cryptography\.hazmat\.primitives',
        r'algorithms\.(RSA|AES|ECDSA|DH|SHA)',
        r'hashes\.(SHA1|SHA256|MD5)',
    ],
    "java": [
        r'KeyPairGenerator\.getInstance\(["'](\w+)["']',
        r'Cipher\.getInstance\(["']([^"']+)["']',
    ],
    # ... (full pattern DB from conversation history)
}
```

#### Binary Scanner (`worker-binary`)

**Queue:** `scanner.binary`
**Targets:** ELF, PE, Mach-O, JVM .class, Python .pyc
**Tools:** `nm`, `objdump`, `readelf` (bundled in container)
**Method:** Symbol table extraction → match against crypto library symbol patterns → extract algorithm from symbol name

#### Certificate Scanner (`worker-cert`)

**Queue:** `scanner.cert`
**Formats:** PEM, DER, PKCS#12, JKS
**Live probing:** TLS handshake against target hosts, extract certificate chain
**Extracts:** Key algorithm, key size, signature algorithm, validity dates, SAN, fingerprints

#### Database Encryption Scanner (`worker-db`)

**Queue:** `scanner.db`
**Supported databases:** PostgreSQL, MySQL, MongoDB, SQL Server (read-only connection)
**Detection method:**
- Query `pg_settings` / `information_schema` for TDE settings
- Inspect SSL/TLS connection parameters
- Query for field-level encryption patterns (e.g. `pgcrypto` usage)
- Detect AES-256/3DES/RC4 in stored procedure definitions

---

### 5.7 CBOM Generator

**Image:** `custom/cbom`
**Queue consumed:** `cbom.ingest`
**Role:** Receives raw `CryptoAssetFound` events from all scanners, deduplicates by asset fingerprint (UUID v5 of algorithm + location + key_size), assembles CycloneDX 1.6 CBOM JSON, and writes to PostgreSQL + MinIO.

**Deduplication key:** `UUID5(SHA1(algorithm + normalized_location + key_size_str))`

**CycloneDX 1.6 output fields (per FR-C01):**

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "<uuid>",
  "name": "RSA-2048",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "pke",
      "parameterSetIdentifier": "2048",
      "curve": null,
      "executionEnvironment": "software-plain-ram",
      "implementationPlatform": "x86_64",
      "certificationLevel": ["none"],
      "mode": "ecb",
      "padding": "pkcs1v15",
      "cryptoFunctions": ["encapsulate", "decapsulate"]
    }
  }
}
```

**PQC classification logic (from conversation history):**

```python
QUANTUM_CLASSIFICATION = {
    # VULNERABLE — Shor's algorithm breaks these
    "RSA": {"class": "vulnerable", "pqc_replacement": "ML-KEM-768"},
    "ECDSA": {"class": "vulnerable", "pqc_replacement": "ML-DSA-65"},
    "ECDH": {"class": "vulnerable", "pqc_replacement": "ML-KEM-768"},
    "DH": {"class": "vulnerable", "pqc_replacement": "ML-KEM-768"},
    "DSA": {"class": "vulnerable", "pqc_replacement": "ML-DSA-44"},
    "ED25519": {"class": "vulnerable", "pqc_replacement": "ML-DSA-44"},
    # PARTIALLY SAFE — Grover's halves security level
    "AES-128": {"class": "partially_safe", "pqc_replacement": "AES-256"},
    "SHA-256": {"class": "partially_safe", "pqc_replacement": "SHA3-256"},
    "SHA-1": {"class": "partially_safe", "pqc_replacement": "SHA3-256"},
    # SAFE
    "AES-256": {"class": "safe", "pqc_replacement": None},
    "SHA3-256": {"class": "safe", "pqc_replacement": None},
    # PQC — NIST FIPS 203/204/205
    "ML-KEM": {"class": "pqc", "pqc_replacement": None},
    "ML-DSA": {"class": "pqc", "pqc_replacement": None},
    "SLH-DSA": {"class": "pqc", "pqc_replacement": None},
}
```

---

### 5.8 QARS Scoring Engine

**Image:** `custom/scoring`
**Role:** Computes the Quantum-Adjusted Risk Score (QARS) per crypto asset using the Mosca inequality framework.

**Formula (from conversation history):**

```
QARS = f(X, Y, Z, S, E)

Where:
  X = data shelf life in years (how long encrypted data must remain secret)
  Y = migration timeline in years (how long to migrate this asset)
  Z = quantum threat horizon in years from now (default: 2030, configurable)
  S = sensitivity weight (public=0.5, internal=1.0, confidential=1.5, restricted=2.0)
  E = exposure factor (internet-facing=1.5, internal=1.0, air-gapped=0.5)

Mosca urgency flag: triggered when X + Y >= Z

Base QARS = clamp((X + Y) / Z, 0.0, 1.0)
Weighted QARS = clamp(Base_QARS * S * E, 0.0, 1.0)
```

**Severity bands:**

| QARS Range | Severity | Action |
|-----------|----------|--------|
| 0.8 – 1.0 | Critical | Immediate migration required |
| 0.6 – 0.79 | High | Migration within 6 months |
| 0.4 – 0.59 | Medium | Migration within 18 months |
| 0.0 – 0.39 | Low | Monitor, plan migration |

**Sector profiles (FR-Q02):**

| Sector | Default X | Default Y | Default S |
|--------|----------|----------|----------|
| Financial (DORA) | 15 years | 3 years | 1.5 |
| Healthcare (NIS2) | 20 years | 3 years | 1.5 |
| Government (NSM-10) | 25 years | 2 years | 2.0 |
| Critical Infrastructure | 20 years | 3 years | 1.5 |
| General Enterprise | 10 years | 3 years | 1.0 |

**Output:** Per-asset QARS score, Mosca breakdown (X, Y, Z values), severity band, PQC replacement recommendation, compliance mapping (DORA/NIS2/NSM-10 control IDs).

---

### 5.9 QSRI Scoring Engine

**Image:** `custom/scoring` (same container as QARS)
**Role:** Computes the Quantum Security Readiness Index (QSRI) — organizational maturity score 0–100.

**8 dimensions and weights (from conversation history):**

| Dimension | Weight | Auto-populated from CBOM? |
|-----------|--------|--------------------------|
| Cryptographic Inventory & Discovery | 15% | Yes — from CBOM coverage % |
| Risk Assessment | 15% | Partial — QARS score feeds this |
| Crypto Agility | 15% | No — manual assessment |
| Migration Planning | 15% | No — manual assessment |
| Technical Implementation | 10% | No — manual assessment |
| Supply Chain Security | 10% | No — manual assessment |
| Governance & Compliance | 10% | No — manual assessment |
| Awareness & Training | 10% | No — manual assessment |

**Maturity levels (0–5):**

| Level | Description |
|-------|-------------|
| 0 | Non-existent — no awareness or process |
| 1 | Initial — ad-hoc, reactive |
| 2 | Developing — some documented processes |
| 3 | Defined — consistent, documented processes |
| 4 | Managed — measured and controlled |
| 5 | Optimised — continuous improvement |

**QSRI Score:** `sum(dimension_score * weight)` where `dimension_score = (maturity_level / 5) * 100`

---

### 5.10 Magika File Router

**Image:** `custom/magika`
**Role:** HTTP microservice wrapping Google's Magika library. Called by all scanner workers before routing a file to the correct scanner.

**API:**

```
POST /classify
Body: { "file_path": "/scan/target/file.bin" }
Response: { "content_type": "elf", "confidence": 0.97, "group": "binary" }
```

**Routing groups:**

| Magika Group | Scanner Routed To |
|-------------|------------------|
| `python`, `java`, `go`, `javascript`, `c`, `cpp` | `worker-ast` |
| `elf`, `pe`, `macho`, `jvm_class`, `pyc` | `worker-binary` |
| `pem`, `x509_der`, `pkcs12` | `worker-cert` |
| `zip`, `jar`, `tar`, `docker` | Unpack + recurse |
| `yaml`, `json`, `toml` | `worker-ast` (IaC patterns) |
| `unknown` (confidence < 0.6) | Ollama SLM fallback |

---

### 5.11 SLM Service — Ollama + Gemma 2 2B

**Image:** `ollama/ollama`
**Model:** `gemma2:2b` (Google Gemma 2 2B — 2.67 GB on disk, ~4 GB RAM at runtime)
**Role:** Local SLM serving the LLM fallback analysis tier. Only invoked for files that Magika cannot classify with confidence (< 5% of files in typical codebases).

**Why Gemma 2 2B:**
- 4 GB RAM fits on a host with 16 GB total (leaving headroom for other containers)
- CPU-only inference: ~2–5 seconds per analysis request (acceptable for fallback-only usage)
- GPU acceleration: if NVIDIA GPU present, Ollama auto-detects and reduces latency to <500ms
- Code understanding: Gemma 2 was trained on code datasets — competitive with Mistral 7B for structured code analysis tasks at half the size
- OpenAI-compatible API: trivial to swap to larger model for production

**Prompt template for crypto detection:**

```
You are a cryptographic security analyst. Analyze the following code/config for
cryptographic operations.

Return JSON only with this structure:
{
  "findings": [
    {
      "algorithm": "string",
      "quantum_vulnerable": true|false,
      "confidence": "high|medium|low",
      "reason": "one sentence",
      "line_number": int|null
    }
  ]
}

Code to analyze:
<code>
{file_content_truncated_to_2000_chars}
</code>
```

**Rate limiting:** Maximum 10 concurrent SLM requests (configurable). Queue excess requests via RabbitMQ `slm.fallback` queue with 60-second timeout.

---

### 5.12 Message Broker — RabbitMQ

**Image:** `rabbitmq:3.13-management`
**Role:** Durable message broker for all async task dispatch between the orchestrator and scanner workers.

**Queue topology:**

```
Exchange: cbom.direct (type: direct)
  ├── scanner.ast        (AST scan jobs)
  ├── scanner.binary     (Binary scan jobs)
  ├── scanner.cert       (Certificate scan jobs)
  ├── scanner.db         (Database scan jobs)
  ├── slm.fallback       (Ollama SLM analysis jobs)
  ├── cbom.ingest        (Raw crypto asset events)
  └── cbom.dlq           (Dead-letter queue — failed jobs)

Exchange: cbom.fanout (type: fanout)
  └── cbom.notify        (Scan completion notifications → WebSocket push)
```

**Key settings:**
- Message persistence: all queues durable, messages persistent (`delivery_mode=2`)
- Prefetch: workers set `prefetch_count=1` — one job at a time per worker
- DLQ: failed jobs (3 retries) routed to `cbom.dlq` with full message + error metadata
- Management UI: `:15672` (internal network only, not exposed via Traefik in MVP)

---

### 5.13 Primary Database — PostgreSQL 16

**Image:** `postgres:16-alpine`
**Role:** Primary persistent store for all platform data.

**Schema (high-level):**

```sql
-- Core entities
users          (id, email, password_hash, is_active, created_at)
groups         (id, name, rbac_role, created_at)
user_groups    (user_id, group_id)

-- Scan management
scans          (id, tenant_id, status, config_json, started_at, completed_at)
scan_targets   (scan_id, target_type, target_value)

-- CBOM data
cbom_versions  (id, scan_id, version_number, cyclonedx_json, created_at)
crypto_assets  (id, cbom_version_id, algorithm, key_size, crypto_type,
                quantum_class, pqc_replacement, location, line_number,
                confidence, source, created_at)

-- Risk scoring
qars_scores    (id, asset_id, scan_id, qars_value, severity, x_value,
                y_value, z_value, sensitivity, exposure, computed_at)
qsri_scores    (id, scan_id, total_score, dimension_scores_json, computed_at)

-- Findings workflow
findings       (id, asset_id, severity, type, description, status,
                owner_id, due_date, rationale, created_at, updated_at)

-- Certificates
certificates   (id, scan_id, subject, issuer, key_algorithm, key_size,
                sig_algorithm, valid_from, valid_until, sha256_fingerprint,
                location, created_at)

-- Audit log (append-only)
audit_log      (id, actor_id, action, resource_type, resource_id,
                old_value_json, new_value_json, ip_address, created_at)
```

**Indexes:** QARS score queries, asset algorithm filter, certificate expiry date, audit log actor/timestamp.

---

### 5.14 Object Storage — MinIO

**Image:** `minio/minio`
**Role:** S3-compatible object storage for all file artifacts.

**Bucket layout:**

| Bucket | Contents | Versioning |
|--------|---------|-----------|
| `cbom-exports` | CycloneDX JSON/XML exports, PDF reports | Enabled |
| `zeek-logs` | Raw Zeek JSON log files | Disabled (large, rotated) |
| `scan-artifacts` | Uploaded source archives, target files | Disabled |
| `compliance-packages` | DORA/NIS2/NSM-10 evidence packages | Enabled |

**Security:**
- Server-side encryption: AES-256 (MinIO SSE-S3)
- Access via MinIO service account (no public access)
- FastAPI uses `boto3` with internal MinIO endpoint

---

### 5.15 Cache & Session Store — Redis

**Image:** `redis:7-alpine`
**Role:** Fast in-memory store for sessions, scan status, and short-lived cache.

**Key namespaces:**

| Namespace | TTL | Purpose |
|-----------|-----|---------|
| `session:{token_jti}` | 7 days | Refresh token store (revocation list) |
| `scan:{scan_id}:status` | 24h | Real-time scan progress |
| `scan:{scan_id}:progress` | 24h | % complete, assets found count |
| `cbom:{cbom_id}:summary` | 1h | Cached CBOM summary for dashboard |
| `qars:{scan_id}` | 1h | Cached QARS scores |

---

### 5.16 Network Sensor — Zeek

**Image:** `zeek/zeek:6`
**Mode:** Host network (`network_mode: host`) with `NET_RAW` + `NET_ADMIN` capabilities
**Role:** Passive network capture of all TLS/SSL handshakes, SSH connections, and X.509 certificate exchanges on the host network interface.

**Output:** JSON logs written to shared Docker volume (`/shared/zeek-logs`) which are:
1. Picked up by the orchestrator's log watcher (watchdog)
2. Parsed and converted to `CryptoAssetFound` events
3. Published to `cbom.ingest` queue

**Zeek scripts enabled:**
- `protocols/ssl/ssl.zeek` — TLS cipher suite, version, certificate extraction
- `protocols/ssh/ssh.zeek` — SSH host key algorithm, key exchange
- `frameworks/files/hash.zeek` — SHA-1, SHA-256 file hashes
- Custom `crypto-detection.zeek` — maps cipher suite strings to algorithm DB

---

### 5.17 Traffic Generation & Simulation Module

**Image:** `custom/traffic-sim`
**Port:** `8080` (separate from main app, accessible directly)
**Role:** Dual-purpose module:
1. **Demo mode** — generates crypto-rich traffic against the bundled sample apps (HTTPS web app, SSH service, PostgreSQL TLS) so Zeek can discover assets in a demo environment
2. **Benchmark mode** — standalone tool clients deploy against their own infrastructure to validate scanner coverage and QARS scoring accuracy

**Technology:** Python + Locust v2 (distributed load testing framework)

**Why Locust:**
- Scriptable scenarios in Python — easy to add new protocol scenarios
- Web UI at `:8080` for controlling scenarios without CLI
- Distributed mode for higher load generation (add worker containers)
- Export metrics as JSON/CSV for benchmarking reports

**Scenarios:**

| Scenario ID | Description | Protocols Exercised |
|-------------|-------------|-------------------|
| `web-tls` | HTTPS requests to web app (RSA-2048 cert, AES-256-GCM) | TLS 1.2/1.3 |
| `ssh-keyx` | SSH connections with key exchange (ED25519, ECDSA, RSA) | SSH |
| `db-tls` | PostgreSQL TLS connections with SCRAM-SHA-256 auth | TLS + DB protocol |
| `weak-crypto` | Intentionally uses legacy ciphers (TLS 1.0, RC4, DES) | TLS |
| `cert-chain` | Presents multi-level cert chains (root CA → intermediate → leaf) | X.509 |
| `mixed-load` | All scenarios in parallel at configurable RPS | All |
| `pqc-demo` | Hybrid classical + ML-KEM key exchange (requires OQS-OpenSSL) | TLS 1.3 + PQC |
| `custom` | Client-defined scenario via YAML config file | Configurable |

**Benchmark output:**
- Discovery coverage report: % of planted crypto assets detected by Zeek + AST scanners
- QARS accuracy report: expected vs actual QARS scores for known-vulnerable assets
- Scan throughput report: files/second, assets/second, total scan time
- Export as JSON, CSV, and HTML report

**Sample apps bundled (for demo mode):**
- `sample-apps/web-app`: Flask + PyOpenSSL, self-signed RSA-2048 cert, port 8443
- `sample-apps/ssh-service`: OpenSSH with RSA/ECDSA/ED25519 host keys, port 2222
- `sample-apps/db-service`: PostgreSQL 16 with TLS, SCRAM-SHA-256, port 5433

---

### 5.18 Monitoring — Portainer

**Image:** `portainer/portainer-ce:latest`
**Port:** `9443` (HTTPS)
**Role:** Docker container management UI for operators.

**Capabilities:**
- Container start/stop/restart
- Real-time log streaming per container
- Resource usage (CPU, RAM, network) per container
- Image management
- Volume and network inspection
- Stack (Compose) management — redeploy with updated config

**Note:** FastAPI exposes `GET /metrics` (Prometheus format) from Day 1, pre-wired for v1.1 Grafana stack addition.

---

## 6. Data Flows

### 6.1 Scan Request Flow

```
User (Engineer)
  → POST /api/scans {config}                          [FastAPI :8000]
  → Scan record created in PostgreSQL
  → ScanQueued event published                        [RabbitMQ: orchestrator.requests]
  → Orchestrator decomposes scan into jobs
  → Jobs published to scanner queues                  [scanner.ast, scanner.binary, scanner.cert, scanner.db]
  → Scanner workers process files:
      → Magika classifies file type                   [worker-magika :8002]
      → If unknown → Ollama SLM analysis              [ollama :11434]
      → CryptoAssetFound event published              [cbom.ingest]
  → CBOM Generator assembles assets                   [cbom-generator :8003]
      → Deduplicates by UUID5
      → Classifies quantum vulnerability
      → Writes CBOM to PostgreSQL + MinIO
  → Scoring Engine computes QARS per asset            [scoring-engine :8004]
  → ScanComplete notification published               [cbom.fanout → cbom.notify]
  → Frontend receives real-time update via WebSocket
```

### 6.2 Zeek Network Discovery Flow

```
Network traffic on host interface
  → Zeek captures TLS/SSH/X.509                       [zeek: host network]
  → JSON logs written to shared volume                [/shared/zeek-logs/]
  → Orchestrator log watcher detects new log files
  → Parses ssl.log, x509.log, ssh.log
  → Emits CryptoAssetFound events                     [cbom.ingest]
  → CBOM Generator processes (same as above)
```

### 6.3 Export & Report Flow

```
User (CISO/Auditor)
  → POST /api/reports {format: "cyclonedx-json", scope: "scan_id"}
  → Report Generator assembles CBOM + findings + QARS
  → Renders PDF (WeasyPrint) or JSON/XML (direct)
  → Uploads to MinIO bucket: cbom-exports/
  → Returns pre-signed download URL (24h expiry)
  → User downloads via browser
```

---

## 7. Security Architecture

### 7.1 TLS Configuration

| Component | TLS Version | Cert Type | Notes |
|-----------|------------|-----------|-------|
| Traefik (external) | TLS 1.3 only | Self-signed wildcard (MVP) | Cipher: AES-256-GCM-SHA384, CHACHA20-POLY1305 |
| Inter-service | No TLS (Docker internal network) | N/A | Docker bridge network isolation |
| PostgreSQL | TLS 1.3 (internal) | Self-signed | Mandatory for DB scanner connections |
| MinIO | TLS 1.2+ | Self-signed | Internal endpoint, no external exposure |
| RabbitMQ | No TLS (internal network) | N/A | Docker bridge only |
| Ollama | No TLS (internal network) | N/A | Not externally reachable |

### 7.2 Authentication & RBAC

- **JWT RS256**: asymmetric signing — private key on API server, public key distributed to services that need to verify tokens
- **Access token**: 1-hour expiry, contains `user_id`, `email`, `roles`, `jti`
- **Refresh token**: 7-day expiry, stored in Redis (revocable on logout)
- **Password hashing**: bcrypt with cost factor 12
- **RBAC enforcement**: FastAPI `Depends()` decorator on every endpoint — role check before any business logic

### 7.3 Secrets Management (MVP)

- All secrets in `.env` file (not committed to git)
- `.env` encrypted at rest using host filesystem encryption (documented requirement)
- Docker Compose `secrets:` mechanism used for DB password and JWT private key
- Post-MVP: HashiCorp Vault integration documented

### 7.4 Audit Trail

- Every API mutating operation (`POST`, `PUT`, `PATCH`, `DELETE`) writes to `audit_log` table
- Includes: actor, action, resource, before/after JSON, IP address, timestamp
- Append-only: no `DELETE` or `UPDATE` permitted on `audit_log` (enforced by PostgreSQL row-level security)
- Retained for 7 years per NFR-S05

### 7.5 Network Isolation

```
Docker networks:
  cbom-frontend:   traefik ↔ frontend ↔ api
  cbom-backend:    api ↔ orchestrator ↔ workers ↔ rabbitmq ↔ postgres ↔ redis ↔ minio ↔ ollama
  host (zeek only): zeek sensor (no other containers)
```

No direct connectivity between the frontend network and the backend data network. API is the single bridge.

---

## 8. NFR Implementation Map

### 8.1 Security (NFR-S01 to NFR-S08)

| NFR | Implementation |
|-----|---------------|
| NFR-S01 TLS 1.3 in transit | Traefik enforces `minVersion: VersionTLS13`. All HTTP redirected to HTTPS. |
| NFR-S02 AES-256-GCM at rest | MinIO SSE-S3 (AES-256). PostgreSQL data directory on encrypted host volume. |
| NFR-S03 RBAC, 5 roles | FastAPI `Depends(require_role(...))` on every endpoint. 5 predefined roles. |
| NFR-S04 MFA / SSO | MVP: strong password + JWT. MFA (TOTP via `pyotp`) is v1.1. SAML SSO is v1.1. |
| NFR-S05 Audit log, 7-year retention | PostgreSQL `audit_log` table, append-only via RLS. Archival to MinIO after 90 days. |
| NFR-S06 Pentest | Documented requirement. OWASP ZAP scan in CI pipeline as MVP substitute. |
| NFR-S07 Data residency | All containers on-prem. No external API calls at runtime. Ollama air-gapped. |
| NFR-S08 Vuln disclosure | Tracked in GitHub Issues (internal repo). CVE monitoring via `pip-audit` in CI. |

### 8.2 Scalability & Performance (NFR-P01 to NFR-P08)

| NFR | Implementation |
|-----|---------------|
| NFR-P01 10,000 files in <4h | 4 parallel AST workers (Docker `scale`). Magika at 500 files/s. |
| NFR-P02 500 files/s Magika | Single Magika container handles this — 5ms/file × 200 parallel = 1000 files/s. |
| NFR-P03 50K assets QARS in <10min | Scoring engine processes assets in batches of 1000. PostgreSQL bulk insert. |
| NFR-P04 API p95 <500ms | Redis caches CBOM summaries and QARS scores. FastAPI async endpoints. |
| NFR-P05 Horizontal scaling | `docker compose scale worker-ast=4`. Each worker is stateless. |
| NFR-P06 100 tenant scans | MVP: single tenant. Multi-tenant isolation is v1.1 (schema-per-tenant). |
| NFR-P07 10M assets | PostgreSQL partitioned by `scan_date`. B-tree indexes on algorithm, severity. |
| NFR-P08 10 Gbps Zeek | Zeek host-network mode. Tested to 10 Gbps on commodity hardware. |

### 8.3 Availability & Reliability (NFR-A01 to NFR-A04)

| NFR | Implementation |
|-----|---------------|
| NFR-A01 99.9% uptime | Docker `restart: unless-stopped`. Health checks on all containers. |
| NFR-A02 RTO 4h, RPO 1h | PostgreSQL WAL archiving to MinIO every 15 minutes. Restore script provided. |
| NFR-A03 Zeek 24h buffer | Zeek writes to local shared volume. Orchestrator processes logs asynchronously. |
| NFR-A04 Daily CBOM backup | `cbom-backup` cron container: `pg_dump` + MinIO upload at 02:00 UTC. |

### 8.4 Compliance & Standards (NFR-C01 to NFR-C05)

| NFR | Implementation |
|-----|---------------|
| NFR-C01 CycloneDX 1.6 | CBOM Generator uses `cyclonedx-python-lib` 7.x. Schema validated on every export. |
| NFR-C02 NIST FIPS 203/204/205 | PQC replacement DB hardcoded to NIST-approved algorithms only. |
| NFR-C03 GDPR Article 32 | On-prem deployment. No data leaves client boundary. AES-256 at rest. |
| NFR-C04 SOC 2 Type II | Audit log + access controls lay groundwork. Formal audit engagement needed. |
| NFR-C05 ISO 27001 | ISMS documentation tracked in project wiki. Gap assessment in v1.1. |

### 8.5 Usability (NFR-U01 to NFR-U04)

| NFR | Implementation |
|-----|---------------|
| NFR-U01 30min onboarding | `make setup` script: cert gen + docker compose up + seed admin user. README <5 steps. |
| NFR-U02 CISO jargon-free dashboard | CISO view uses business language: "Critical assets requiring immediate action: 12" not algorithm names. |
| NFR-U03 WCAG 2.1 AA | shadcn/ui components are WCAG compliant by default. Lighthouse CI check in pipeline. |
| NFR-U04 English only (MVP) | i18n framework (`react-i18next`) wired but only English bundle populated. |

---

## 9. Docker Compose Service Map

```yaml
# Abbreviated docker-compose.yml structure
version: "3.9"

networks:
  cbom-frontend:
  cbom-backend:

volumes:
  postgres-data:
  redis-data:
  minio-data:
  zeek-logs:        # shared between zeek and orchestrator
  ollama-models:    # persists Gemma 2 2B weights across restarts

services:
  traefik:
    image: traefik:v3
    ports: ["443:443", "80:80"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./traefik/certs:/certs:ro
    networks: [cbom-frontend]
    restart: unless-stopped

  frontend:
    build: ./frontend
    networks: [cbom-frontend]
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.frontend.rule=PathPrefix(`/`)"
      - "traefik.http.routers.frontend.tls=true"
    restart: unless-stopped

  api:
    build: ./api
    environment:
      - DATABASE_URL=postgresql://cbom:${DB_PASS}@postgres:5432/cbom
      - REDIS_URL=redis://redis:6379
      - RABBITMQ_URL=amqp://cbom:${RABBIT_PASS}@rabbitmq:5672
      - MINIO_ENDPOINT=minio:9000
      - JWT_PRIVATE_KEY_FILE=/run/secrets/jwt_private_key
    secrets: [jwt_private_key, db_password]
    networks: [cbom-frontend, cbom-backend]
    labels:
      - "traefik.http.routers.api.rule=PathPrefix(`/api`) || PathPrefix(`/auth`) || PathPrefix(`/metrics`) || PathPrefix(`/health`)"
    depends_on: [postgres, redis, rabbitmq]
    restart: unless-stopped

  orchestrator:
    build: ./orchestrator
    networks: [cbom-backend]
    volumes:
      - zeek-logs:/shared/zeek-logs:ro
    depends_on: [rabbitmq, postgres]
    restart: unless-stopped

  worker-ast:
    build: ./scanners
    command: celery -A tasks worker -Q scanner.ast --concurrency=2
    networks: [cbom-backend]
    depends_on: [rabbitmq, worker-magika, ollama]
    restart: unless-stopped

  worker-binary:
    build: ./scanners
    command: celery -A tasks worker -Q scanner.binary --concurrency=2
    networks: [cbom-backend]
    restart: unless-stopped

  worker-cert:
    build: ./scanners
    command: celery -A tasks worker -Q scanner.cert --concurrency=4
    networks: [cbom-backend]
    restart: unless-stopped

  worker-db:
    build: ./scanners
    command: celery -A tasks worker -Q scanner.db --concurrency=2
    networks: [cbom-backend]
    restart: unless-stopped

  worker-magika:
    build: ./magika-service
    networks: [cbom-backend]
    restart: unless-stopped

  cbom-generator:
    build: ./cbom-generator
    networks: [cbom-backend]
    depends_on: [rabbitmq, postgres, minio]
    restart: unless-stopped

  scoring-engine:
    build: ./scoring-engine
    networks: [cbom-backend]
    depends_on: [postgres]
    restart: unless-stopped

  ollama:
    image: ollama/ollama
    volumes:
      - ollama-models:/root/.ollama
    networks: [cbom-backend]
    environment:
      - OLLAMA_NUM_PARALLEL=2
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]  # Optional: falls back to CPU if no GPU
    restart: unless-stopped

  rabbitmq:
    image: rabbitmq:3.13-management
    environment:
      - RABBITMQ_DEFAULT_USER=cbom
      - RABBITMQ_DEFAULT_PASS=${RABBIT_PASS}
    volumes:
      - ./rabbitmq/rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
    networks: [cbom-backend]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "ping"]
      interval: 30s

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=cbom
      - POSTGRES_USER=cbom
      - POSTGRES_PASSWORD=${DB_PASS}
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    networks: [cbom-backend]
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASS}
    volumes:
      - redis-data:/data
    networks: [cbom-backend]
    restart: unless-stopped

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=cbomadmin
      - MINIO_ROOT_PASSWORD=${MINIO_PASS}
    volumes:
      - minio-data:/data
    networks: [cbom-frontend, cbom-backend]
    labels:
      - "traefik.http.routers.minio.rule=PathPrefix(`/minio`)"
    restart: unless-stopped

  zeek:
    image: zeek/zeek:6
    network_mode: host
    cap_add: [NET_RAW, NET_ADMIN]
    volumes:
      - zeek-logs:/zeek/logs
      - ./zeek/scripts:/zeek/scripts:ro
    command: zeek -i eth0 -C local /zeek/scripts/crypto-detection.zeek
    restart: unless-stopped

  traffic-sim:
    build: ./traffic-sim
    ports: ["8080:8080"]
    networks: [cbom-backend]
    environment:
      - WEB_TARGET=https://traefik:443
      - SSH_TARGET=sample-ssh:22
      - DB_TARGET=sample-db:5432
    restart: unless-stopped

  portainer:
    image: portainer/portainer-ce:latest
    ports: ["9443:9443"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./portainer-data:/data
    networks: [cbom-frontend]
    restart: unless-stopped

secrets:
  jwt_private_key:
    file: ./secrets/jwt_private_key.pem
  db_password:
    file: ./secrets/db_password.txt
```

---

## 10. Directory Structure

```
cbom-platform/
├── docker-compose.yml
├── docker-compose.override.yml       # Dev overrides (hot reload)
├── .env.example                      # Template — copy to .env
├── Makefile                          # make setup, make up, make down, make backup
├── README.md
├── scripts/
│   ├── gen-certs.sh                  # Generate self-signed CA + wildcard cert
│   ├── seed-db.sh                    # Create admin user, default RBAC groups
│   ├── backup.sh                     # pg_dump + MinIO upload
│   └── model-pull.sh                 # ollama pull gemma2:2b
├── traefik/
│   ├── traefik.yml                   # Static Traefik config
│   ├── dynamic.yml                   # TLS options, middleware
│   └── certs/                        # Self-signed CA cert + wildcard cert
├── frontend/                         # React + Vite SPA
│   ├── Dockerfile
│   ├── src/
│   │   ├── pages/                    # dashboard, scans, cbom, findings, admin, qsri
│   │   ├── components/               # shared components
│   │   ├── admin/                    # Admin UI (users, groups, RBAC)
│   │   └── store/                    # Zustand state
│   └── nginx.conf
├── api/                              # FastAPI backend
│   ├── Dockerfile
│   ├── app/
│   │   ├── main.py
│   │   ├── auth/                     # JWT, RBAC, password hashing
│   │   ├── routers/                  # scans, cbom, findings, reports, admin, traffic
│   │   ├── models/                   # SQLAlchemy + Pydantic models
│   │   └── services/                 # Business logic
│   └── alembic/                      # Database migrations
├── orchestrator/                     # Discovery orchestrator
│   ├── Dockerfile
│   └── src/
│       ├── main.py
│       ├── decomposer.py             # Scan → jobs
│       └── log_watcher.py            # Zeek log monitor
├── scanners/                         # All scanner workers (shared Celery app)
│   ├── Dockerfile
│   └── src/
│       ├── tasks.py                  # Celery task definitions
│       ├── ast_scanner.py
│       ├── binary_scanner.py
│       ├── cert_scanner.py
│       └── db_scanner.py
├── magika-service/                   # Magika HTTP microservice
│   ├── Dockerfile
│   └── main.py
├── cbom-generator/                   # CycloneDX CBOM assembly
│   ├── Dockerfile
│   └── src/
│       ├── generator.py
│       ├── deduplicator.py
│       └── classifier.py             # Quantum vulnerability classification
├── scoring-engine/                   # QARS + QSRI
│   ├── Dockerfile
│   └── src/
│       ├── qars.py                   # Mosca inequality, per-asset scoring
│       ├── qsri.py                   # 8-dimension readiness scoring
│       └── sector_profiles.py        # DORA/NIS2/NSM-10 weights
├── traffic-sim/                      # Traffic generation + simulation
│   ├── Dockerfile
│   ├── locustfile.py                 # Locust scenario definitions
│   ├── scenarios/
│   │   ├── web_tls.py
│   │   ├── ssh_keyx.py
│   │   ├── db_tls.py
│   │   ├── weak_crypto.py
│   │   └── pqc_demo.py
│   ├── benchmark/
│   │   ├── coverage_report.py        # Detection coverage analysis
│   │   └── accuracy_report.py        # QARS accuracy analysis
│   └── sample-apps/                  # Bundled target apps for demo
│       ├── web-app/
│       ├── ssh-service/
│       └── db-service/
├── zeek/
│   ├── local.zeek
│   └── scripts/
│       └── crypto-detection.zeek
├── db/
│   └── init.sql                      # Schema + seed RBAC roles
└── rabbitmq/
    └── rabbitmq.conf                 # Queue definitions, DLQ policy
```

---

## 11. Hardware Requirements (MVP)

| Component | Minimum (CPU-only) | Recommended (GPU) |
|-----------|-------------------|--------------------|
| CPU | 8 cores | 16 cores |
| RAM | 16 GB | 32 GB |
| Disk (OS + containers) | 50 GB SSD | 100 GB NVMe SSD |
| Disk (data volumes) | 200 GB | 500 GB |
| GPU | None (CPU inference) | NVIDIA 8 GB VRAM (RTX 3070+) |
| Network | 1 Gbps NIC | 10 Gbps NIC (for Zeek at scale) |

**Memory breakdown (16 GB minimum):**

| Service | RAM Usage |
|---------|----------|
| Ollama + Gemma 2 2B | 4 GB |
| PostgreSQL 16 | 2 GB |
| Scanner workers (4×) | 2 GB |
| FastAPI + Uvicorn | 512 MB |
| RabbitMQ | 512 MB |
| Redis | 256 MB |
| MinIO | 512 MB |
| React Nginx | 128 MB |
| Traefik | 128 MB |
| Zeek | 1 GB |
| Remaining services | 1 GB |
| **Total** | **~12.5 GB** (3.5 GB headroom) |

---

## 12. MVP Scope Boundaries

### In Scope (v1.0 MVP)

- All `MUST` functional requirements from BRD v1.0
- Single-tenant deployment (one client per installation)
- English UI only
- Self-signed TLS cert (Traefik auto-generated)
- JWT auth with 5 RBAC roles (no MFA, no SSO for MVP)
- PostgreSQL plain (no TimescaleDB)
- Portainer monitoring (no Prometheus/Grafana)
- Traffic generation: demo + benchmark modes
- QARS + QSRI scoring with full Mosca formula
- CycloneDX 1.6 CBOM output
- PDF + JSON + CSV export
- DORA + NIS2 + NSM-10 compliance package generation

### Out of Scope (v1.1+)

| Feature | Target Version |
|---------|---------------|
| Multi-tenant (schema-per-tenant) | v1.1 |
| MFA (TOTP) | v1.1 |
| SAML 2.0 / OIDC SSO | v1.1 |
| TimescaleDB QARS time-series | v1.1 |
| Prometheus + Grafana | v1.1 |
| Kubernetes (Helm chart) | v1.2 |
| HSM PKCS#11 discovery | v1.2 |
| SBOM-to-CBOM bridge | v1.2 |
| Jira/ServiceNow integration | v1.2 |
| French + German localization | v1.2 |
| White-label branding | v2.0 |

---

## 13. Post-MVP Upgrade Path

### v1.0 → v1.1 (Single host → HA)

1. Replace `docker-compose.yml` with Compose with Swarm mode
2. Add TimescaleDB extension: `CREATE EXTENSION timescaledb;`
3. Add Prometheus scrape targets + Grafana dashboards
4. Add TOTP MFA: `pyotp` library in FastAPI auth router
5. Add SAML2 middleware: `python3-saml` or `pysaml2`

### v1.1 → v1.2 (Single node → Kubernetes)

1. Convert Compose services to Helm chart (already structured for this)
2. Replace MinIO single-node with MinIO distributed mode (4 nodes)
3. Replace PostgreSQL single with Patroni HA cluster
4. Replace Redis single with Redis Sentinel
5. Add Horizontal Pod Autoscaler for scanner workers

### Model Upgrade Path (Gemma 2 2B → larger model)

```bash
# Stop Ollama container
docker compose stop ollama

# Pull larger model (no code change required)
docker exec ollama ollama pull mistral:7b   # 8 GB RAM
docker exec ollama ollama pull codellama:13b  # 16 GB RAM

# Update .env
OLLAMA_MODEL=mistral:7b

# Restart
docker compose up -d ollama
```

---

*End of document — MVP Architecture v1.0 | Quantum-Safe CBOM Discovery Platform | Confidential*
