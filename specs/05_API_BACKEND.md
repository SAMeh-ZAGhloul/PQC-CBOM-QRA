# 05 — FastAPI Backend

> Read `00_MASTER_SPEC.md`, `03_DATABASE_SCHEMA.md`, `04_RABBITMQ.md` first.

---

## Directory Structure

```
api/
├── Dockerfile
├── pyproject.toml
├── alembic.ini
├── alembic/
│   ├── env.py
│   └── versions/
└── src/
    └── cbom_api/
        ├── __init__.py
        ├── main.py
        ├── config.py
        ├── dependencies.py        # Shared FastAPI Depends()
        ├── middleware.py          # Logging, audit, CORS
        ├── auth/
        │   ├── __init__.py
        │   ├── jwt.py             # JWT encode/decode RS256
        │   ├── rbac.py            # Role checking decorators
        │   └── password.py        # bcrypt helpers
        ├── models/
        │   ├── __init__.py
        │   ├── db.py              # SQLAlchemy models (see spec 03)
        │   └── schemas.py         # Pydantic request/response schemas
        ├── routers/
        │   ├── __init__.py
        │   ├── auth.py            # /auth/*
        │   ├── scans.py           # /api/scans/*
        │   ├── cbom.py            # /api/cbom/*
        │   ├── assets.py          # /api/assets/*
        │   ├── findings.py        # /api/findings/*
        │   ├── certificates.py    # /api/certs/*
        │   ├── qars.py            # /api/qars/*
        │   ├── qsri.py            # /api/qsri/*
        │   ├── reports.py         # /api/reports/*
        │   ├── admin.py           # /api/admin/*
        │   └── traffic.py         # /api/traffic/*
        ├── services/
        │   ├── __init__.py
        │   ├── scan_service.py
        │   ├── cbom_service.py
        │   ├── report_service.py
        │   ├── cert_alert_service.py
        │   └── websocket_service.py
        └── db/
            ├── __init__.py
            └── session.py         # Async session factory
```

---

## main.py

```python
"""FastAPI application factory."""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from .config import get_settings
from .db.session import init_db
from .middleware import AuditMiddleware, RequestLoggingMiddleware
from .routers import (
    admin, assets, auth, cbom, certificates,
    findings, qars, qsri, reports, scans, traffic,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    logger.info("starting_api", version=settings.app_version)
    await init_db()
    yield
    logger.info("shutting_down_api")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="CBOM Discovery Platform API",
        version=settings.app_version,
        docs_url="/api/docs" if settings.app_env == "development" else None,
        redoc_url="/api/redoc" if settings.app_env == "development" else None,
        lifespan=lifespan,
    )

    # CORS — only allow same-origin (frontend served via Traefik)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://localhost", f"https://{settings.domain}"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Trace-ID"],
    )

    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(AuditMiddleware)

    # Routers
    app.include_router(auth.router, prefix="/auth", tags=["auth"])
    app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
    app.include_router(cbom.router, prefix="/api/cbom", tags=["cbom"])
    app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
    app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
    app.include_router(certificates.router, prefix="/api/certs", tags=["certificates"])
    app.include_router(qars.router, prefix="/api/qars", tags=["qars"])
    app.include_router(qsri.router, prefix="/api/qsri", tags=["qsri"])
    app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
    app.include_router(admin.router, prefix="/api/admin", tags=["admin"])
    app.include_router(traffic.router, prefix="/api/traffic", tags=["traffic"])

    # Health + metrics
    @app.get("/health", tags=["system"])
    async def health() -> dict:
        return {"status": "ok", "version": settings.app_version}

    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

    return app


app = create_app()
```

---

## config.py

```python
"""Application settings loaded from environment variables and Docker secrets."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(path: str) -> str:
    p = Path(path)
    if p.exists():
        return p.read_text().strip()
    raise ValueError(f"Secret file not found: {path}")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_env: str = "production"
    app_version: str = "1.0.0-mvp"
    log_level: str = "INFO"
    domain: str = "localhost"

    # Database
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "cbom"
    postgres_user: str = "cbom"
    db_password_file: str = "/run/secrets/db_password"

    # Redis
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_password_file: str = "/run/secrets/redis_password"

    # RabbitMQ
    rabbitmq_host: str = "rabbitmq"
    rabbitmq_port: int = 5672
    rabbitmq_user: str = "cbom"
    rabbitmq_vhost: str = "/"
    rabbitmq_password_file: str = "/run/secrets/rabbitmq_password"

    # MinIO
    minio_endpoint: str = "minio:9000"
    minio_use_ssl: bool = False
    minio_user: str = "cbomadmin"
    minio_password_file: str = "/run/secrets/minio_password"
    minio_bucket_cbom_exports: str = "cbom-exports"
    minio_bucket_zeek_logs: str = "zeek-logs"
    minio_bucket_scan_artifacts: str = "scan-artifacts"
    minio_bucket_compliance: str = "compliance-packages"

    # JWT
    jwt_algorithm: str = "RS256"
    jwt_private_key_file: str = "/run/secrets/jwt_private_key"
    jwt_public_key_file: str = "/run/secrets/jwt_public_key"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 7

    # Ollama
    ollama_host: str = "ollama"
    ollama_port: int = 11434
    ollama_model: str = "gemma2:2b"

    # QARS
    qars_default_q_day_year: int = 2030
    qars_default_sector: str = "general_enterprise"

    @property
    def database_url(self) -> str:
        pwd = _read_secret_file(self.db_password_file)
        return f"postgresql+asyncpg://{self.postgres_user}:{pwd}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    @property
    def redis_url(self) -> str:
        pwd = _read_secret_file(self.redis_password_file)
        return f"redis://:{pwd}@{self.redis_host}:{self.redis_port}/0"

    @property
    def rabbitmq_url(self) -> str:
        pwd = _read_secret_file(self.rabbitmq_password_file)
        return f"amqp://{self.rabbitmq_user}:{pwd}@{self.rabbitmq_host}:{self.rabbitmq_port}/{self.rabbitmq_vhost}"

    @property
    def jwt_private_key(self) -> str:
        return _read_secret_file(self.jwt_private_key_file)

    @property
    def jwt_public_key(self) -> str:
        return _read_secret_file(self.jwt_public_key_file)

    @property
    def minio_password(self) -> str:
        return _read_secret_file(self.minio_password_file)


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

---

## auth/jwt.py

```python
"""JWT RS256 token creation and verification."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt

from ..config import get_settings

settings = get_settings()


def create_access_token(user_id: str, email: str, roles: list[str]) -> str:
    jti = str(uuid.uuid4())
    expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": user_id,
        "email": email,
        "roles": roles,
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_private_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str) -> tuple[str, str]:
    """Returns (token, jti)."""
    jti = str(uuid.uuid4())
    expire = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {
        "sub": user_id,
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "refresh",
    }
    token = jwt.encode(payload, settings.jwt_private_key, algorithm=settings.jwt_algorithm)
    return token, jti


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.jwt_public_key, algorithms=[settings.jwt_algorithm])
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}") from e
```

---

## auth/rbac.py

```python
"""RBAC role checking — FastAPI Depends() decorators."""
from __future__ import annotations

from typing import Callable
from fastapi import Depends, HTTPException, status
from .jwt import decode_token
from ..dependencies import get_current_token

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin":    {"*"},
    "engineer": {"scan:*", "cbom:*", "finding:*", "cert:read", "report:read", "report:export"},
    "ciso":     {"scan:read", "cbom:read", "finding:read", "finding:approve", "cert:read", "report:*", "qars:read", "qsri:*"},
    "auditor":  {"scan:read", "cbom:read", "finding:read", "cert:read", "report:export"},
    "ceo":      {"dashboard:executive"},
}


def require_role(*allowed_roles: str) -> Callable:
    """Dependency factory — raises 403 if user lacks required role."""
    def dependency(payload: dict = Depends(get_current_token)) -> dict:
        user_roles: list[str] = payload.get("roles", [])
        if not any(role in allowed_roles for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {allowed_roles}",
            )
        return payload
    return dependency


def require_any_authenticated() -> Callable:
    return require_role("admin", "engineer", "ciso", "auditor", "ceo")
```

---

## Router Specifications

### /auth/login (POST)
```
Request:  { email: str, password: str }
Response: { access_token: str, refresh_token: str, token_type: "bearer",
            user: { id, email, display_name, roles: str[] } }
Actions:
  1. Load user from DB by email
  2. Verify bcrypt password hash
  3. Update last_login_at
  4. Create access + refresh tokens
  5. Store refresh token JTI in Redis with 7-day TTL
  6. Write audit_log: action=LOGIN
  7. Return tokens
```

### /api/scans (POST) — requires role: engineer, admin
```
Request:  ScanCreateRequest (see schemas below)
Response: { scan_id: uuid, status: "queued" }
Actions:
  1. Validate config (target_repos / target_hosts / target_db_connections)
  2. Create scan record in DB (status=queued)
  3. Publish ScanRequest to orchestrator.requests queue
  4. Write audit_log: action=CREATE_SCAN
  5. Return scan_id
```

### /api/scans/{scan_id} (GET) — requires any authenticated
```
Response: ScanDetailResponse (scan + progress + asset count + findings count)
  - Read scan from DB
  - Read progress from Redis: scan:{scan_id}:progress
  - Return combined response
```

### /api/scans/{scan_id}/status (GET + WebSocket)
```
WebSocket /api/scans/{scan_id}/ws
  - Subscribe to cbom.notify fanout exchange
  - Stream ScanComplete events to connected clients
  - Fallback: poll Redis scan:{scan_id}:status every 5 seconds
```

### /api/cbom/{scan_id} (GET) — requires any authenticated
```
Response: Full CycloneDX 1.6 JSON or filtered asset list
Query params: format=json|xml|summary
```

### /api/findings (GET) — requires any authenticated
```
Query params: scan_id, status, severity, owner_id, page, limit
Response: paginated FindingListResponse
```

### /api/findings/{id} (PATCH) — requires engineer, ciso, admin
```
Request:  { status?, owner_id?, due_date?, rationale? }
Response: UpdatedFinding
Actions:
  1. Load finding, verify exists
  2. Update fields
  3. Write audit_log: action=UPDATE_FINDING, old_value, new_value
```

### /api/reports (POST) — requires any authenticated
```
Request:  { scan_id, format: "cyclonedx-json"|"cyclonedx-xml"|"csv"|"pdf"|"compliance-dora"|"compliance-nis2"|"compliance-nsm10" }
Response: { download_url: str, expires_at: ISO8601 }
Actions:
  1. Assemble report data from DB
  2. Render to requested format
  3. Upload to MinIO cbom-exports/
  4. Return pre-signed URL (24h expiry)
  5. Write audit_log: action=EXPORT_REPORT
```

### /api/admin/users (GET, POST) — requires admin
```
GET:  Paginated user list with groups
POST: { email, password, display_name, group_ids[] }
      → Hash password (bcrypt cost 12)
      → Create user
      → Assign groups
      → Write audit_log: action=CREATE_USER
```

### /api/traffic/{scenario} (POST) — requires engineer, admin
```
Scenarios: web-tls, ssh-keyx, db-tls, weak-crypto, mixed-load, all
Actions:
  1. HTTP POST to traffic-sim:8080/api/scenarios/{scenario}/start
  2. Return { job_id, status: "running" }
```

---

## Pydantic Schemas (models/schemas.py) — Key ones

```python
from __future__ import annotations
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class ScanCreateRequest(BaseModel):
    name: Optional[str] = None
    target_repos: list[str] = Field(default_factory=list)
    target_hosts: list[str] = Field(default_factory=list)
    target_db_connections: list[str] = Field(default_factory=list)
    network_interface: str = "eth0"
    max_file_depth: int = Field(default=5, ge=1, le=10)
    enable_llm_fallback: bool = True
    sector: str = "general_enterprise"
    q_day_year: int = Field(default=2030, ge=2025, le=2040)


class CryptoAssetResponse(BaseModel):
    id: uuid.UUID
    algorithm: str
    key_size: Optional[int]
    crypto_type: str
    quantum_class: str
    pqc_replacement: Optional[str]
    location: str
    line_number: Optional[int]
    source: str
    confidence: str
    qars_score: Optional[Decimal]
    severity: Optional[str]
    first_seen_at: datetime
    last_seen_at: datetime

    class Config:
        from_attributes = True


class QarsScoreResponse(BaseModel):
    asset_id: uuid.UUID
    algorithm: str
    location: str
    x_value: Decimal
    y_value: Decimal
    z_value: Decimal
    mosca_urgent: bool
    base_qars: Decimal
    weighted_qars: Decimal
    severity: str
    pqc_replacement: Optional[str]
    compliance_gaps: list[dict]


class QsriScoreResponse(BaseModel):
    scan_id: uuid.UUID
    total_score: Decimal
    dimensions: dict[str, int]   # dimension_name -> maturity_level
    recommendations: list[dict]
    computed_at: datetime


class FindingResponse(BaseModel):
    id: uuid.UUID
    severity: str
    finding_type: str
    title: str
    description: str
    recommendation: str
    status: str
    owner_id: Optional[uuid.UUID]
    due_date: Optional[str]
    framework: Optional[str]
    control_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    display_name: Optional[str] = None
    group_ids: list[uuid.UUID] = Field(default_factory=list)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
```

---

## db/session.py

```python
"""Async SQLAlchemy session factory."""
from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    echo=settings.app_env == "development",
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    async with engine.begin() as conn:
        pass  # Tables created by init.sql; Alembic handles migrations


DBSession = Annotated[AsyncSession, Depends(get_db)]
```

---

## Dockerfile

```dockerfile
FROM python:3.12-slim

RUN groupadd -r cbom && useradd -r -g cbom cbom

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"

COPY src/ ./src/
COPY alembic.ini .
COPY alembic/ ./alembic/

USER cbom

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "cbom_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
```

---

## pyproject.toml (api)

```toml
[project]
name = "cbom-api"
version = "1.0.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi==0.111.*",
    "uvicorn[standard]==0.29.*",
    "pydantic==2.*",
    "pydantic-settings==2.*",
    "sqlalchemy[asyncio]==2.*",
    "asyncpg==0.29.*",
    "alembic==1.13.*",
    "python-jose[cryptography]==3.3.*",
    "passlib[bcrypt]==1.7.*",
    "aio-pika==9.*",
    "redis[hiredis]==5.*",
    "boto3==1.34.*",
    "structlog==24.*",
    "prometheus-fastapi-instrumentator==7.*",
    "weasyprint==62.*",
    "cyclonedx-python-lib==7.*",
    "python-multipart==0.0.*",
]

[project.optional-dependencies]
dev = ["pytest==8.*", "pytest-asyncio==0.23.*", "httpx==0.27.*", "ruff", "mypy"]
```
