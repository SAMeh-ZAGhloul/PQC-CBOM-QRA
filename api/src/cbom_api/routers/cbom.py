from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth.rbac import require_role
from ..db.session import DBSession
from ..models.schemas import CryptoAssetResponse
from ..services.cbom_service import get_latest_cbom, list_assets_for_scan

router = APIRouter()
RequireRead = Annotated[dict, Depends(require_role("admin", "engineer", "ciso", "auditor", "ceo"))]


@router.get("/{scan_id}")
async def get_cbom(scan_id: uuid.UUID, payload: RequireRead, db: DBSession, format: str = Query(default="json")):
    cbom_version = await get_latest_cbom(db, scan_id)
    if format == "summary":
        assets = await list_assets_for_scan(db, scan_id)
        return [CryptoAssetResponse.model_validate(asset) for asset in assets]
    if cbom_version is None:
        raise HTTPException(status_code=404, detail="CBOM not found")
    return cbom_version.cyclonedx_json or {}
