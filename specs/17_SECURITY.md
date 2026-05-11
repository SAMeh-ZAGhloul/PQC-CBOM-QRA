# 17 -- Security Architecture

> Read `00_MASTER_SPEC.md`, `05_API_BACKEND.md`, `03_DATABASE_SCHEMA.md` first.

---

## Overview

This spec covers the complete security implementation for the MVP:
JWT RS256 auth, bcrypt password hashing, Docker secrets management,
audit trail enforcement, network isolation, and the security checklist
Claude Code must verify before declaring the MVP complete.

---

## 1. Password Hashing (api/auth/password.py)

```python
"""bcrypt password hashing with cost factor 12."""
from __future__ import annotations
from passlib.context import CryptContext

_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt (cost=12)."""
    if len(plain) < 12:
        raise ValueError("Password must be at least 12 characters")
    return _ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return _ctx.verify(plain, hashed)
```

---

## 2. JWT RS256 Full Implementation (api/auth/jwt.py)

```python
"""JWT RS256 token lifecycle: create, verify, refresh, revoke."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import redis.asyncio as aioredis
from jose import JWTError, jwt

from ..config import get_settings

settings = get_settings()

TOKEN_TYPE_ACCESS  = "access"
TOKEN_TYPE_REFRESH = "refresh"


def create_access_token(user_id: str, email: str, roles: list[str]) -> tuple[str, str]:
    """Returns (token, jti)."""
    jti = str(uuid.uuid4())
    expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub":   user_id,
        "email": email,
        "roles": roles,
        "jti":   jti,
        "exp":   expire,
        "iat":   datetime.now(UTC),
        "type":  TOKEN_TYPE_ACCESS,
    }
    token = jwt.encode(payload, settings.jwt_private_key, algorithm=settings.jwt_algorithm)
    return token, jti


def create_refresh_token(user_id: str) -> tuple[str, str]:
    """Returns (token, jti)."""
    jti = str(uuid.uuid4())
    expire = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {
        "sub":  user_id,
        "jti":  jti,
        "exp":  expire,
        "iat":  datetime.now(UTC),
        "type": TOKEN_TYPE_REFRESH,
    }
    token = jwt.encode(payload, settings.jwt_private_key, algorithm=settings.jwt_algorithm)
    return token, jti


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT. Raises ValueError on failure."""
    try:
        return jwt.decode(
            token,
            settings.jwt_public_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}") from e


async def store_refresh_token(
    redis: aioredis.Redis,
    jti: str,
    user_id: str,
    expire_days: int,
) -> None:
    """Store refresh token JTI in Redis for revocation checking."""
    await redis.setex(
        f"session:{jti}",
        expire_days * 86400,
        user_id,
    )


async def revoke_refresh_token(redis: aioredis.Redis, jti: str) -> None:
    """Revoke a refresh token by deleting it from Redis."""
    await redis.delete(f"session:{jti}")


async def is_refresh_token_valid(redis: aioredis.Redis, jti: str) -> bool:
    """Return True if the refresh token JTI exists in Redis (not revoked)."""
    return bool(await redis.exists(f"session:{jti}"))
```

---

## 3. FastAPI Dependencies (api/dependencies.py)

```python
"""Shared FastAPI Depends() functions for auth and RBAC."""
from __future__ import annotations

from typing import Annotated, Any

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .auth.jwt import decode_token, is_refresh_token_valid
from .config import get_settings

settings = get_settings()
_bearer = HTTPBearer(auto_error=True)


async def get_redis() -> aioredis.Redis:
    """Dependency: Redis client."""
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


async def get_current_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
) -> dict[str, Any]:
    """Decode and validate JWT access token from Authorization header."""
    try:
        payload = decode_token(credentials.credentials)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Token type must be 'access'")
    return payload


async def get_current_token_ws(websocket: WebSocket) -> dict[str, Any]:
    """Extract and validate JWT from WebSocket query param ?token=..."""
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        raise HTTPException(status_code=401, detail="No token provided")
    try:
        return decode_token(token)
    except ValueError:
        await websocket.close(code=1008)
        raise HTTPException(status_code=401, detail="Invalid token")


CurrentUser = Annotated[dict[str, Any], Depends(get_current_token)]
RedisClient = Annotated[aioredis.Redis, Depends(get_redis)]
```

---

## 4. Audit Middleware (api/middleware.py)

```python
"""Request logging and audit trail middleware."""
from __future__ import annotations

import time
import uuid
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger()

# HTTP methods that trigger audit log entries
AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths excluded from audit logging
AUDIT_EXCLUDE_PATHS = {"/health", "/metrics", "/api/scans/ws"}


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Attach trace_id and log every request."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        trace_id = str(uuid.uuid4())
        request.state.trace_id = trace_id
        start = time.perf_counter()

        log = logger.bind(
            trace_id=trace_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else "unknown",
        )

        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 1)

        log.info(
            "request_complete",
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        response.headers["X-Trace-ID"] = trace_id
        return response


class AuditMiddleware(BaseHTTPMiddleware):
    """Write audit log entries for all mutating API requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Only audit mutating methods on API paths
        if (
            request.method not in AUDIT_METHODS
            or request.url.path in AUDIT_EXCLUDE_PATHS
            or not request.url.path.startswith("/api/")
        ):
            return response

        # Only audit successful mutations
        if response.status_code >= 400:
            return response

        # Extract actor from JWT (if available -- don't fail if missing)
        actor_id = None
        actor_email = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from .auth.jwt import decode_token
                payload = decode_token(auth_header.split(" ", 1)[1])
                actor_id = payload.get("sub")
                actor_email = payload.get("email")
            except Exception:
                pass

        # Determine action from method + path
        action = _infer_action(request.method, request.url.path)

        # Write audit log asynchronously (best-effort, don't fail request)
        try:
            from .db.session import SessionLocal
            from .models.db import AuditLog
            async with SessionLocal() as db:
                db.add(AuditLog(
                    actor_id=actor_id,
                    actor_email=actor_email,
                    action=action,
                    resource_type=_infer_resource(request.url.path),
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("User-Agent"),
                    trace_id=getattr(request.state, "trace_id", None),
                ))
                await db.commit()
        except Exception as e:
            logger.warning("audit_log_write_failed", error=str(e))

        return response


def _infer_action(method: str, path: str) -> str:
    """Infer audit action name from HTTP method and path."""
    resource = _infer_resource(path)
    return {
        "POST":   f"CREATE_{resource.upper()}",
        "PUT":    f"UPDATE_{resource.upper()}",
        "PATCH":  f"UPDATE_{resource.upper()}",
        "DELETE": f"DELETE_{resource.upper()}",
    }.get(method, f"{method}_{resource.upper()}")


def _infer_resource(path: str) -> str:
    """Extract resource type from path."""
    parts = [p for p in path.strip("/").split("/") if p]
    if len(parts) >= 2:
        return parts[1]   # /api/scans -> scans
    return "unknown"
```

---

## 5. Docker Secrets Pattern

All secrets are injected as files, never environment variables.

```python
# Pattern used in every service config.py:
from pathlib import Path

def _read_secret(env_var: str, fallback_env: str | None = None) -> str:
    """Read secret from Docker secret file or fall back to env var."""
    file_path = os.environ.get(f"{env_var}_FILE")
    if file_path:
        p = Path(file_path)
        if p.exists():
            return p.read_text().strip()
    if fallback_env:
        return os.environ.get(fallback_env, "")
    return os.environ.get(env_var, "")
```

```yaml
# In docker-compose.yml -- correct pattern:
secrets:
  db_password:
    file: ./secrets/db_password.txt

services:
  api:
    secrets: [db_password]
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
    # NEVER: - DB_PASSWORD=plaintext_value
```

---

## 6. Network Isolation Rules

```
Rule 1: Frontend network contains ONLY:
  traefik, frontend, api, minio (console), portainer
  --> NO direct access to postgres, redis, rabbitmq, llama-cpp, workers

Rule 2: Backend network contains:
  api, orchestrator, all workers, rabbitmq, postgres, redis,
  minio (api endpoint), llama-cpp, cbom-generator, scoring-engine
  --> NOT exposed externally

Rule 3: Host network contains ONLY:
  zeek (for packet capture)
  --> zeek writes to shared volume ONLY; no network calls to backend

Rule 4: The API service is the ONLY bridge:
  api is on BOTH cbom-frontend AND cbom-backend
  --> React never calls postgres/rabbitmq/redis directly
```

---

## 7. Security Checklist (Claude Code Must Verify)

### Authentication & Authorization
- [ ] All `/api/*` endpoints require valid JWT (except `/health` and `/metrics`)
- [ ] JWT uses RS256 algorithm (asymmetric -- not HS256)
- [ ] Access token TTL is 60 minutes maximum
- [ ] Refresh token stored in Redis, revocable on logout
- [ ] Password hashing uses bcrypt with cost factor >= 12
- [ ] Password minimum length enforced at 12 characters
- [ ] RBAC `require_role()` decorator applied on every router endpoint
- [ ] Admin-only endpoints return 403 for non-admin roles (not 404)
- [ ] WebSocket auth uses query param token (no cookies)

### Transport Security
- [ ] Traefik enforces `minVersion: VersionTLS13`
- [ ] HTTP port 80 redirects to HTTPS with 301
- [ ] `Strict-Transport-Security` header present on all responses
- [ ] `X-Content-Type-Options: nosniff` header present
- [ ] `X-Frame-Options: DENY` header present
- [ ] Self-signed cert covers `localhost` and `127.0.0.1` in SAN
- [ ] TLS 1.2 connections are rejected (test with `openssl s_client -tls1_2`)

### Data Protection
- [ ] PostgreSQL data directory is on an encrypted host volume
- [ ] MinIO server-side encryption (SSE-S3 AES-256) enabled on all buckets
- [ ] No secrets appear in environment variables (only `*_FILE` pointers)
- [ ] `.env` file excluded from git via `.gitignore`
- [ ] `secrets/` directory excluded from git (only `.gitkeep` committed)
- [ ] Redis requires password auth (`requirepass` set)
- [ ] RabbitMQ default guest account is disabled

### Audit Trail
- [ ] `audit_log` table has PostgreSQL RLS enabled
- [ ] `DELETE` and `UPDATE` on `audit_log` blocked for all roles
- [ ] Every `POST/PUT/PATCH/DELETE` to `/api/*` writes an audit entry
- [ ] Audit entries include: actor_id, actor_email, action, resource_type, resource_id, ip_address, trace_id
- [ ] Audit log is tested: direct SQL delete attempt returns permission denied

### Input Validation
- [ ] All request bodies use Pydantic v2 models with type validation
- [ ] String fields have `max_length` constraints
- [ ] UUID path parameters validated by FastAPI (invalid UUID returns 422)
- [ ] File upload size limits enforced (no unbounded file reads)
- [ ] SQL injection impossible (SQLAlchemy ORM with parameterized queries only)
- [ ] No `text()` raw SQL with user-controlled input

### Dependency Security
- [ ] `pip-audit` integrated in CI -- fails on critical/high CVEs
- [ ] All Docker base images pinned to specific versions (not `latest`)
- [ ] PostgreSQL, Redis, RabbitMQ, MinIO run as non-root inside containers
- [ ] FastAPI, uvicorn, cryptography packages at latest patch versions

### OWASP Top 10 Coverage
- [ ] **A01 Broken Access Control** -- RBAC on all endpoints, no IDOR
- [ ] **A02 Cryptographic Failures** -- TLS 1.3, AES-256, bcrypt, RS256
- [ ] **A03 Injection** -- Pydantic validation, SQLAlchemy ORM
- [ ] **A04 Insecure Design** -- audit log, secrets management, network isolation
- [ ] **A05 Security Misconfiguration** -- no default passwords, no debug in prod
- [ ] **A06 Vulnerable Components** -- pip-audit in CI
- [ ] **A07 Auth Failures** -- JWT with refresh revocation, bcrypt
- [ ] **A08 Software Integrity** -- Docker image pinning
- [ ] **A09 Logging Failures** -- structlog JSON on all services, audit trail
- [ ] **A10 SSRF** -- no user-controlled URL fetching in API

---

## 8. Security Test Cases

```python
# tests/security/test_auth.py

import pytest
from httpx import AsyncClient

async def test_no_token_returns_401(client: AsyncClient):
    resp = await client.get("/api/scans")
    assert resp.status_code == 401

async def test_wrong_role_returns_403(client: AsyncClient, engineer_token: str):
    resp = await client.get("/api/admin/users",
                            headers={"Authorization": f"Bearer {engineer_token}"})
    assert resp.status_code == 403

async def test_expired_token_returns_401(client: AsyncClient, expired_token: str):
    resp = await client.get("/api/scans",
                            headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401

async def test_weak_password_rejected(client: AsyncClient, admin_token: str):
    resp = await client.post("/api/admin/users",
                             json={"email": "x@x.com", "password": "short"},
                             headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 422

async def test_audit_log_delete_blocked(db_session):
    """Verify PostgreSQL RLS blocks direct DELETE on audit_log."""
    from sqlalchemy import text
    with pytest.raises(Exception, match="permission denied"):
        await db_session.execute(text("DELETE FROM audit_log WHERE id = 1"))

async def test_sql_injection_safe(client: AsyncClient, auth_token: str):
    """Verify SQL injection in query params returns 422 or empty results."""
    resp = await client.get("/api/assets",
                            params={"algorithm": "'; DROP TABLE crypto_assets; --"},
                            headers={"Authorization": f"Bearer {auth_token}"})
    assert resp.status_code in (200, 422)
    if resp.status_code == 200:
        assert resp.json()["items"] == []

async def test_tls_12_rejected():
    """Verify TLS 1.2 is rejected by Traefik."""
    import ssl, socket
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with pytest.raises((ssl.SSLError, ConnectionResetError, OSError)):
        with socket.create_connection(("localhost", 443)) as sock:
            with ctx.wrap_socket(sock):
                pass
```

---

## 9. Structlog Configuration (shared across all services)

```python
# shared/logging_config.py
import logging
import structlog


def configure_logging(log_level: str = "INFO") -> None:
    """Configure structlog for JSON output across all services."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(log_level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )
    logging.basicConfig(
        format="%(message)s",
        level=logging.getLevelName(log_level.upper()),
    )
```
