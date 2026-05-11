from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select

from ..auth.rbac import require_role
from ..db.session import DBSession
from ..models.db import Certificate
from ..models.schemas import CertificateResponse, PaginatedResponse

router = APIRouter()
RequireRead = Annotated[dict, Depends(require_role("admin", "engineer", "ciso", "auditor"))]


@router.get("", response_model=PaginatedResponse[CertificateResponse])
async def list_certificates(payload: RequireRead, db: DBSession, page: int = 1, limit: int = 50) -> PaginatedResponse[CertificateResponse]:
    result = await db.execute(
        select(Certificate).order_by(Certificate.created_at.desc()).offset((page - 1) * limit).limit(limit)
    )
    items = [CertificateResponse.model_validate(item) for item in result.scalars().all()]
    return PaginatedResponse(items=items, page=page, limit=limit, total=len(items))
