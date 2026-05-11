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
from .routers import admin, assets, auth, cbom, certificates, findings, qars, qsri, reports, scans, traffic

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

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://localhost", f"https://{settings.domain}"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Trace-ID"],
    )

    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(AuditMiddleware)

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

    @app.get("/health", tags=["system"])
    async def health() -> dict:
        return {"status": "ok", "version": settings.app_version}

    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

    return app


app = create_app()
