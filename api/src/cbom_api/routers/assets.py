from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from ..auth.rbac import require_role
from ..db.session import DBSession
from ..models.db import CryptoAsset
from ..models.schemas import AssetAnnotateRequest, CryptoAssetResponse, PaginatedResponse

router = APIRouter()
RequireRead = Annotated[dict, Depends(require_role("admin", "engineer", "ciso", "auditor", "ceo"))]
RequireWrite = Annotated[dict, Depends(require_role("admin", "engineer"))]


@router.get("", response_model=PaginatedResponse[CryptoAssetResponse])
async def list_assets(
    payload: RequireRead,
    db: DBSession,
    algorithm: str | None = None,
    scan_id: uuid.UUID | None = None,
    page: int = 1,
    limit: int = 50,
) -> PaginatedResponse[CryptoAssetResponse]:
    query = select(CryptoAsset).order_by(CryptoAsset.created_at.desc())
    if algorithm:
        query = query.where(CryptoAsset.algorithm_normalized == algorithm.upper())
    if scan_id:
        query = query.where(CryptoAsset.scan_id == scan_id)
    result = await db.execute(query.offset((page - 1) * limit).limit(limit))
    items = [CryptoAssetResponse.model_validate(asset) for asset in result.scalars().all()]
    return PaginatedResponse(items=items, page=page, limit=limit, total=len(items))


@router.patch("/{asset_id}", response_model=CryptoAssetResponse)
async def annotate_asset(asset_id: uuid.UUID, payload: RequireWrite, body: AssetAnnotateRequest, db: DBSession) -> CryptoAssetResponse:
    result = await db.execute(select(CryptoAsset).where(CryptoAsset.id == asset_id))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(asset, field, value)
    await db.flush()
    return CryptoAssetResponse.model_validate(asset)
