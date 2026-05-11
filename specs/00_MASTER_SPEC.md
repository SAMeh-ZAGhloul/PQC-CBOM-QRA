# Quantum-Safe CBOM Discovery Platform — Master Implementation Spec

> **For:** Claude Code agent
> **Version:** 1.1 | **Date:** June 2025
> **Status:** Implementation-ready

This is the entry point. Read this file first, then read each referenced spec in order before writing any code.

---

## Implementation Spec Index

| # | File | Covers | Read Before |
|---|------|--------|-------------|
| 00 | `00_MASTER_SPEC.md` | This file — project overview, conventions, read order | Everything |
| 01 | `01_PROJECT_STRUCTURE.md` | Directory layout, Makefile, .env, Docker networks | All |
| 02 | `02_DOCKER_COMPOSE.md` | Full docker-compose.yml, all 19 services, volumes, secrets | 01 |
| 03 | `03_DATABASE_SCHEMA.md` | PostgreSQL schema, all tables, indexes, RLS, seed data | 02 |
| 04 | `04_RABBITMQ.md` | Exchange/queue topology, DLQ policy, connection config | 02 |
| 05 | `05_API_BACKEND.md` | FastAPI app structure, auth, RBAC, all routers, models | 03, 04 |
| 06 | `06_SCANNER_WORKERS.md` | Celery workers: AST, binary, cert, DB scanners, Magika | 04, 05 |
| 07 | `07_CBOM_GENERATOR.md` | CycloneDX 1.6 assembly, dedup, quantum classifier | 04, 03 |
| 08 | `08_SCORING_ENGINE.md` | QARS formula, QSRI 8-dimension model, sector profiles | 07 |
| 09 | `09_ORCHESTRATOR.md` | Scan decomposer, Zeek log watcher, state machine | 04, 06 |
| 10 | `10_OLLAMA_SLM.md` | llama.cpp SLM service, model setup, prompt templates | 04 |
| 11 | `11_MINIO_STORAGE.md` | Bucket layout, SSE-S3, presigned URLs, backup cron | 02 |
| 12 | `12_TRAEFIK_TLS.md` | TLS 1.3 config, self-signed cert gen, routing rules | 02 |
| 13 | `13_FRONTEND_REACT.md` | React+Vite SPA, role views, pages, components, state | 05 |
| 14 | `14_ADMIN_UI.md` | Admin panel: user/group/RBAC CRUD, audit log viewer | 13, 05 |
| 15 | `15_ZEEK_SENSOR.md` | Zeek scripts, crypto-detection, log format, output | 09 |
| 16 | `16_TRAFFIC_SIM.md` | Locust scenarios, benchmark reports, sample apps | All |
| 17 | `17_SECURITY.md` | JWT RS256, bcrypt, Docker secrets, audit trail, RLS | 03, 05 |
| 18 | `18_SCRIPTS_AND_MAKEFILE.md` | gen-certs.sh, model-pull.sh, backup.sh, Makefile targets | All |
| 19 | `19_TESTING_STRATEGY.md` | Unit, integration, e2e tests per module | All |
| 20 | `20_NFR_CHECKLIST.md` | NFR acceptance criteria, how to verify each | All |

---

## Project Identity

```
Product:    Quantum-Safe CBOM Discovery Platform
Short name: cbom-platform
Version:    1.0.0-mvp
License:    Proprietary / Confidential
```

---

## Core Technology Versions (Pin These Exactly)

| Technology | Version | Notes |
|-----------|---------|-------|
| Python | 3.12 | All Python services |
| Node.js | 20 LTS | Frontend build only |
| React | 18.3 | |
| Vite | 5.x | |
| FastAPI | 0.111.x | |
| Pydantic | 2.x | |
| SQLAlchemy | 2.x | async ORM |
| Alembic | 1.13.x | migrations |
| Celery | 5.4.x | |
| Uvicorn | 0.29.x | |
| python-jose | 3.3.x | JWT RS256 |
| passlib[bcrypt] | 1.7.x | password hashing |
| cyclonedx-python-lib | 7.x | CycloneDX 1.6 |
| magika | 0.5.x | file classification |
| tree-sitter | 0.22.x | AST parsing |
| weasyprint | 62.x | PDF generation |
| locust | 2.x | traffic simulation |
| boto3 | 1.34.x | MinIO/S3 client |
| redis-py | 5.x | |
| aio-pika | 9.x | async RabbitMQ |
| watchdog | 4.x | file system events |
| PostgreSQL | 16-alpine | Docker image |
| Redis | 7-alpine | Docker image |
| RabbitMQ | 3.13-management | Docker image |
| MinIO | RELEASE.2024-xx | Docker image |
| Traefik | v3.0 | Docker image |
| Zeek | 6.x | Docker image |
| llama.cpp | server (ghcr.io/ggml-org/llama.cpp:server) | Docker image |
| Portainer CE | 2.x | Docker image |

---

## Global Conventions

### Python Code Style
- **Formatter:** `ruff format` (replaces black)
- **Linter:** `ruff check` + `mypy --strict`
- **Import order:** stdlib → third-party → local (ruff handles this)
- **Type hints:** Required on all function signatures
- **Docstrings:** Google style on all public functions/classes
- **Async:** Use `async`/`await` everywhere in FastAPI and I/O-heavy code
- **Exception handling:** Never bare `except:`; always catch specific exceptions

### Python Project Layout (per service)
```
service-name/
├── Dockerfile
├── pyproject.toml          # dependencies + ruff + mypy config
├── src/
│   └── service_name/
│       ├── __init__.py
│       ├── main.py         # entry point
│       ├── config.py       # pydantic-settings Settings class
│       └── ...
└── tests/
    ├── conftest.py
    └── test_*.py
```

### Environment Variables
- All config loaded via `pydantic-settings` `Settings` class
- Never hardcode secrets; always read from environment or Docker secrets
- `.env` file for development; Docker secrets for production values
- Every service has a `config.py` with a `get_settings()` cached function

### Logging
- Use Python `structlog` for structured JSON logging across all services
- Log level: `INFO` in production, `DEBUG` in development
- Every log entry includes: `service`, `trace_id`, `timestamp`, `level`, `message`
- FastAPI: use `structlog` middleware to attach `trace_id` to every request

### Error Responses (FastAPI)
```json
{
  "error": "string",
  "detail": "string",
  "trace_id": "uuid",
  "timestamp": "ISO8601"
}
```

### Frontend Code Style
- **TypeScript:** strict mode, no `any`
- **Formatter:** Prettier
- **Linter:** ESLint with react-hooks plugin
- **Component style:** Functional components only, hooks
- **State:** Zustand stores (no Redux)
- **API calls:** React Query (`@tanstack/react-query`) for all server state
- **Styling:** Tailwind CSS utility classes only (no custom CSS files except globals)

### Git Commit Convention
```
type(scope): subject

Types: feat, fix, docs, style, refactor, test, chore
Scope: api, frontend, scanner, cbom, scoring, zeek, infra, db
Example: feat(scanner): add AST detection for Go crypto/tls imports
```

---

## Docker Network Architecture

```
cbom-frontend  (bridge)
  Members: traefik, frontend, api, minio, portainer

cbom-backend  (bridge)
  Members: api, orchestrator, worker-ast, worker-binary,
           worker-cert, worker-db, worker-magika,
           cbom-generator, scoring-engine,
           rabbitmq, postgres, redis, minio, llama-cpp,
           traffic-sim

host  (zeek only)
  Members: zeek
```

**Rule:** No service on `cbom-frontend` can directly reach `cbom-backend` services except via `api`. The `api` service is on both networks.

---

## Secret Names (Docker Compose secrets)

| Secret Name | File | Used By |
|-------------|------|---------|
| `jwt_private_key` | `./secrets/jwt_private_key.pem` | api |
| `jwt_public_key` | `./secrets/jwt_public_key.pem` | api, orchestrator |
| `db_password` | `./secrets/db_password.txt` | api, orchestrator, scoring-engine, cbom-generator |
| `redis_password` | `./secrets/redis_password.txt` | api, orchestrator |
| `rabbitmq_password` | `./secrets/rabbitmq_password.txt` | api, orchestrator, workers, cbom-generator, scoring-engine |
| `minio_password` | `./secrets/minio_password.txt` | api, cbom-generator, backup-cron |

---

## Shared Volume Map

| Volume Name | Mounted By | Path | Purpose |
|-------------|-----------|------|---------|
| `postgres-data` | postgres | `/var/lib/postgresql/data` | DB files |
| `redis-data` | redis | `/data` | Redis AOF |
| `minio-data` | minio | `/data` | Object storage |
| `zeek-logs` | zeek (rw), orchestrator (ro) | `/zeek/logs`, `/app/zeek-logs` | Zeek JSON output |
| `llama-models` | llama-cpp | `/models` | GGUF model weights + HuggingFace cache |
| `portainer-data` | portainer | `/data` | Portainer config |

---

## Inter-Service Communication Map

| From | To | Protocol | Notes |
|------|----|----------|-------|
| traefik | frontend | HTTP | Docker label routing |
| traefik | api | HTTP | PathPrefix `/api`, `/auth`, `/health`, `/metrics` |
| traefik | minio | HTTP | PathPrefix `/minio` |
| frontend | api | HTTPS (via Traefik) | All API calls |
| api | postgres | TCP 5432 | SQLAlchemy async |
| api | redis | TCP 6379 | aioredis |
| api | rabbitmq | AMQP 5672 | aio-pika publish |
| api | minio | HTTP 9000 | boto3 |
| orchestrator | rabbitmq | AMQP 5672 | publish + consume |
| orchestrator | postgres | TCP 5432 | scan state updates |
| orchestrator | redis | TCP 6379 | scan progress cache |
| workers | rabbitmq | AMQP 5672 | Celery consume |
| workers | worker-magika | HTTP 8002 | file classification |
| workers | llama-cpp | HTTP 11434 | llama.cpp SLM fallback (OpenAI-compatible `/v1/chat/completions` + native `/completion`) |
| workers | rabbitmq | AMQP 5672 | publish CryptoAssetFound |
| cbom-generator | rabbitmq | AMQP 5672 | consume cbom.ingest |
| cbom-generator | postgres | TCP 5432 | write CBOM |
| cbom-generator | minio | HTTP 9000 | store CBOM exports |
| scoring-engine | postgres | TCP 5432 | read assets, write scores |
| zeek | (shared volume) | filesystem | write JSON logs |
| orchestrator | (shared volume) | filesystem | read Zeek logs |

---

## Port Reference

| Service | Internal Port | External Port | Access |
|---------|--------------|--------------|--------|
| traefik | 80, 443 | 80, 443 | Public (HTTP→HTTPS redirect) |
| frontend | 3000 | — (via Traefik) | Via Traefik |
| api | 8000 | — (via Traefik) | Via Traefik |
| rabbitmq mgmt | 15672 | — (internal only) | Internal only |
| rabbitmq amqp | 5672 | — | Internal only |
| postgres | 5432 | — | Internal only |
| redis | 6379 | — | Internal only |
| minio api | 9000 | — | Internal only |
| minio console | 9001 | — (via Traefik) | Via Traefik |
| llama-cpp | 11434 | — | Internal only |
| orchestrator | 8001 | — | Internal only |
| worker-magika | 8002 | — | Internal only |
| cbom-generator | 8003 | — | Internal only |
| scoring-engine | 8004 | — | Internal only |
| traffic-sim | 8080 | 8080 | Direct (not via Traefik) |
| portainer | 9443 | 9443 | Direct HTTPS |

---

## Implementation Order (Recommended for Claude Code)

```
Phase 1 — Infrastructure (no code, just config)
  1. 01_PROJECT_STRUCTURE.md  → scaffold directories, Makefile, .env.example
  2. 12_TRAEFIK_TLS.md        → traefik.yml, certs, routing
  3. 02_DOCKER_COMPOSE.md     → full docker-compose.yml
  4. 04_RABBITMQ.md           → rabbitmq.conf, queue definitions
  5. 18_SCRIPTS_AND_MAKEFILE.md → gen-certs.sh, model-pull.sh, backup.sh

Phase 2 — Data layer
  6. 03_DATABASE_SCHEMA.md    → init.sql, Alembic migrations
  7. 11_MINIO_STORAGE.md      → bucket init script

Phase 3 — Backend services
  8. 05_API_BACKEND.md        → FastAPI: auth, RBAC, all routers
  9. 10_OLLAMA_SLM.md         → llama.cpp setup, model pull, prompt service
  10. 06_SCANNER_WORKERS.md   → all 4 scanner workers + Magika service
  11. 07_CBOM_GENERATOR.md    → CycloneDX assembler
  12. 08_SCORING_ENGINE.md    → QARS + QSRI engines
  13. 09_ORCHESTRATOR.md      → scan decomposer + Zeek log watcher

Phase 4 — Network sensor
  14. 15_ZEEK_SENSOR.md       → Zeek scripts

Phase 5 — Frontend
  15. 13_FRONTEND_REACT.md    → React SPA, all pages
  16. 14_ADMIN_UI.md          → Admin panel

Phase 6 — Traffic simulation
  17. 16_TRAFFIC_SIM.md       → Locust scenarios, sample apps

Phase 7 — Quality
  18. 17_SECURITY.md          → security audit checklist
  19. 19_TESTING_STRATEGY.md  → test implementation
  20. 20_NFR_CHECKLIST.md     → NFR verification