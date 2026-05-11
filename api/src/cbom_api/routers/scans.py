from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from ..auth.rbac import require_role
from ..db.session import DBSession
from ..dependencies import RedisClient, get_current_token_ws
from ..models.db import Scan
from ..models.schemas import PaginatedResponse, ScanCreateRequest, ScanDetailResponse, ScanResponse
from ..services.scan_service import create_scan_record, get_scan_detail
from ..services.websocket_service import manager

router = APIRouter()

RequireCreate = Annotated[dict, Depends(require_role("engineer", "admin"))]
RequireRead = Annotated[dict, Depends(require_role("admin", "engineer", "ciso", "auditor", "ceo"))]


@router.get("", response_model=PaginatedResponse[ScanDetailResponse])
async def list_scans(payload: RequireRead, db: DBSession, page: int = 1, limit: int = 50) -> PaginatedResponse[ScanDetailResponse]:
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).offset((page - 1) * limit).limit(limit)
    )
    items = [
        ScanDetailResponse(
            id=scan.id,
            name=scan.name,
            status=scan.status,
            config=scan.config,
            assets_found=scan.assets_found,
            files_scanned=scan.files_scanned,
            progress=0,
            findings_count=0,
            created_at=scan.created_at,
            updated_at=scan.updated_at,
        )
        for scan in result.scalars().all()
    ]
    return PaginatedResponse(items=items, page=page, limit=limit, total=len(items))


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: RequireCreate, body: ScanCreateRequest, db: DBSession) -> ScanResponse:
    if not (body.target_repos or body.target_hosts or body.target_db_connections):
        raise HTTPException(status_code=422, detail="At least one target must be provided")
    scan = await create_scan_record(db, payload, body)
    return ScanResponse(scan_id=scan.id, status=scan.status)


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: uuid.UUID, payload: RequireRead, db: DBSession, redis: RedisClient) -> ScanDetailResponse:
    scan, findings_count = await get_scan_detail(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    progress = await redis.get(f"scan:{scan_id}:progress") or 0
    return ScanDetailResponse(
        id=scan.id,
        name=scan.name,
        status=scan.status,
        config=scan.config,
        assets_found=scan.assets_found,
        files_scanned=scan.files_scanned,
        progress=int(progress),
        findings_count=findings_count,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
    )


@router.websocket("/{scan_id}/ws")
async def scan_status_ws(websocket: WebSocket, scan_id: uuid.UUID) -> None:
    await get_current_token_ws(websocket)
    channel = f"scan:{scan_id}"
    await manager.connect(channel, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(channel, websocket)
