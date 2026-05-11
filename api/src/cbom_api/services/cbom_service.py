"""CBOM read helpers."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.db import CbomVersion, CryptoAsset


async def get_latest_cbom(db: AsyncSession, scan_id: uuid.UUID) -> CbomVersion | None:
    result = await db.execute(
        select(CbomVersion)
        .where(CbomVersion.scan_id == scan_id)
        .order_by(CbomVersion.version_number.desc())
    )
    return result.scalars().first()


async def list_assets_for_scan(db: AsyncSession, scan_id: uuid.UUID) -> list[CryptoAsset]:
    result = await db.execute(select(CryptoAsset).where(CryptoAsset.scan_id == scan_id))
    return list(result.scalars().all())
