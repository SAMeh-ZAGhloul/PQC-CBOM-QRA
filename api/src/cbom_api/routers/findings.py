from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from ..auth.rbac import require_role
from ..db.session import DBSession
from ..models.db import Finding
from ..models.schemas import FindingResponse, FindingUpdateRequest, PaginatedResponse

router = APIRouter()
RequireRead = Annotated[dict, Depends(require_role("admin", "engineer", "ciso", "auditor", "ceo"))]
RequireWrite = Annotated[dict, Depends(require_role("engineer", "ciso", "admin"))]


@router.get("", response_model=PaginatedResponse[FindingResponse])
async def list_findings(
    payload: RequireRead,
    db: DBSession,
    scan_id: uuid.UUID | None = None,
    status: str | None = None,
    severity: str | None = None,
    owner_id: uuid.UUID | None = None,
    page: int = 1,
    limit: int = 50,
) -> PaginatedResponse[FindingResponse]:
    query = select(Finding).order_by(Finding.created_at.desc())
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if status:
        query = query.where(Finding.status == status)
    if severity:
        query = query.where(Finding.severity == severity)
    if owner_id:
        query = query.where(Finding.owner_id == owner_id)
    result = await db.execute(query.offset((page - 1) * limit).limit(limit))
    items = [FindingResponse.model_validate(item) for item in result.scalars().all()]
    return PaginatedResponse(items=items, page=page, limit=limit, total=len(items))


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    payload: RequireWrite,
    body: FindingUpdateRequest,
    db: DBSession,
) -> FindingResponse:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(finding, field, value)
    await db.flush()
    return FindingResponse.model_validate(finding)
