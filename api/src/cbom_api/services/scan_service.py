"""Scan service helpers."""
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.db import AuditLog, Finding, Scan
from ..models.schemas import ScanCreateRequest


async def create_scan_record(db: AsyncSession, payload: dict, body: ScanCreateRequest) -> Scan:
    config = body.model_dump(exclude={"name"})
    scan = Scan(
        name=body.name,
        status="queued",
        config=config,
        created_by=uuid.UUID(payload["sub"]),
    )
    db.add(scan)
    await db.flush()
    db.add(
        AuditLog(
            actor_id=uuid.UUID(payload["sub"]),
            actor_email=payload.get("email"),
            action="CREATE_SCAN",
            resource_type="scan",
            resource_id=scan.id,
            new_value=config,
        )
    )
    return scan


async def get_scan_detail(db: AsyncSession, scan_id: uuid.UUID) -> tuple[Scan | None, int]:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        return None, 0
    finding_count = await db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan_id))
    return scan, int(finding_count or 0)
