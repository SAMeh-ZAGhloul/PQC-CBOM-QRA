# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
Quantum-Safe CBOM Discovery Platform. Identifies cryptographic assets and assesses quantum-readiness (QARS/QSRI) to generate CycloneDX 1.6 CBOMs.

## Architecture
Distributed microservices architecture orchestrated via Docker Compose (19 services).

### Core Components
- **API Backend**: FastAPI, async SQLAlchemy, Pydantic. Handles RBAC, auth (JWT RS256), and orchestration.
- **Orchestrator**: State machine for scan decomposition and Zeek log watching.
- **Scanner Workers**: Celery workers (AST, Binary, Cert, DB) + Magika (file classification).
- **CBOM Generator**: Assembles findings into CycloneDX 1.6 format with UUID5 deduplication.
- **Scoring Engine**: Calculates QARS (Mosca inequality) and QSRI (8-dimension maturity).
- **Network Sensor**: Zeek 6.x with custom crypto-detection scripts in host network mode.
- **Frontend**: React + Vite SPA using Zustand (state) and React Query (server state).
- **Infrastructure**: PostgreSQL 16 (RLS on audit), RabbitMQ (direct/fanout/dlx), Redis, MinIO (S3), Ollama (Gemma 2 2B SLM), Traefik (TLS 1.3).

### Communication Flow
`Frontend` $\to$ `Traefik` $\to$ `API` $\to$ `Postgres/Redis/RabbitMQ/MinIO`.
`API` $\to$ `RabbitMQ` $\to$ `Orchestrator` $\to$ `Workers` $\to$ `RabbitMQ` $\to$ `CBOM Generator` $\to$ `Scoring Engine`.

## Development Commands

### Setup & Lifecycle
- `make setup`: Full first-time setup (certs, infra, migrations, seed DB, MinIO).
- `make pull-model`: Pull Gemma 2 2B into Ollama.
- `make up`: Start all containers (builds images).
- `make down`: Stop containers.
- `make restart SERVICE=api`: Restart specific service.
- `make reset`: **DESTRUCTIVE** - Delete all volumes and data.

### Quality & Testing
- `make lint`: Run `ruff check` across all Python services.
- `make type-check`: Run `mypy` across Python services.
- `make test`: Run `pytest` for all Python services.
- `make test-svc SVC=api`: Run tests for a specific service.
- `make test-coverage`: Run API tests with coverage report.

### Database & Infra
- `make migrate`: Apply pending Alembic migrations.
- `make migrate-new MSG="..."`: Create new migration.
- `make shell-db`: Interactive psql shell.
- `make backup`: Manual DB backup to MinIO.
- `make trust-cert`: Add self-signed CA to system trust store.

### Observability
- `make logs`: Tail all container logs.
- `make logs-api`: Tail API logs.
- `make status`: Show container health table.

## Conventions
- **Python**: Python 3.12, `ruff` for formatting/linting, `mypy --strict` for types, Google-style docstrings, `structlog` for JSON logging.
- **Frontend**: React 18.3, TypeScript (strict), Tailwind CSS, Zustand, React Query.
- **Git**: `type(scope): subject` (e.g., `feat(scanner): add AST detection`).
- **Config**: `pydantic-settings` for all services. Secrets via Docker secrets (mounted at `/run/secrets/`).
- **Security**: TLS 1.3 minimum, bcrypt cost 12, JWT RS256, append-only audit log (DB RLS).
- **CBOM**: CycloneDX 1.6 specification.
