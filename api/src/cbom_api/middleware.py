"""Request logging and audit trail middleware."""
from __future__ import annotations

import time
import uuid
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger()

AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
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

        log.info("request_complete", status_code=response.status_code, duration_ms=duration_ms)
        response.headers["X-Trace-ID"] = trace_id
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response


class AuditMiddleware(BaseHTTPMiddleware):
    """Write audit log entries for all mutating API requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        if (
            request.method not in AUDIT_METHODS
            or request.url.path in AUDIT_EXCLUDE_PATHS
            or not request.url.path.startswith("/api/")
        ):
            return response

        if response.status_code >= 400:
            return response

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

        action = _infer_action(request.method, request.url.path)

        try:
            from .db.session import SessionLocal
            from .models.db import AuditLog

            async with SessionLocal() as db:
                db.add(
                    AuditLog(
                        actor_id=actor_id,
                        actor_email=actor_email,
                        action=action,
                        resource_type=_infer_resource(request.url.path),
                        ip_address=request.client.host if request.client else None,
                        user_agent=request.headers.get("User-Agent"),
                        trace_id=getattr(request.state, "trace_id", None),
                    )
                )
                await db.commit()
        except Exception as e:
            logger.warning("audit_log_write_failed", error=str(e))

        return response


def _infer_action(method: str, path: str) -> str:
    resource = _infer_resource(path)
    return {
        "POST": f"CREATE_{resource.upper()}",
        "PUT": f"UPDATE_{resource.upper()}",
        "PATCH": f"UPDATE_{resource.upper()}",
        "DELETE": f"DELETE_{resource.upper()}",
    }.get(method, f"{method}_{resource.upper()}")


def _infer_resource(path: str) -> str:
    parts = [p for p in path.strip("/").split("/") if p]
    if len(parts) >= 2:
        return parts[1]
    return "unknown"
