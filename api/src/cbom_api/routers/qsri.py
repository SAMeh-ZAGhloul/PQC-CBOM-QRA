from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from ..auth.rbac import require_role
from ..db.session import DBSession
from ..models.db import AuditLog, QsriScore
from ..models.schemas import QsriInputRequest, QsriScoreResponse

router = APIRouter()
RequireRead = Annotated[dict, Depends(require_role("admin", "engineer", "ciso"))]


@router.get("/{scan_id}", response_model=QsriScoreResponse)
async def get_qsri(scan_id: uuid.UUID, payload: RequireRead, db: DBSession) -> QsriScoreResponse:
    result = await db.execute(select(QsriScore).where(QsriScore.scan_id == scan_id).order_by(QsriScore.computed_at.desc()))
    score = result.scalars().first()
    if score is None:
        raise HTTPException(status_code=404, detail="QSRI score not found")
    return QsriScoreResponse(
        scan_id=score.scan_id,
        total_score=score.total_score,
        dimensions={
            "inventory": score.dim_inventory_level,
            "risk_assessment": score.dim_risk_assessment_level,
            "crypto_agility": score.dim_crypto_agility_level,
            "migration": score.dim_migration_level,
            "tech_impl": score.dim_tech_impl_level,
            "supply_chain": score.dim_supply_chain_level,
            "governance": score.dim_governance_level,
            "awareness": score.dim_awareness_level,
        },
        recommendations=score.recommendations,
        computed_at=score.computed_at,
    )


@router.post("/{scan_id}", response_model=QsriScoreResponse)
async def upsert_qsri(scan_id: uuid.UUID, payload: RequireRead, body: QsriInputRequest, db: DBSession) -> QsriScoreResponse:
    dims = body.dimensions
    score = QsriScore(
        scan_id=scan_id,
        total_score=Decimal("0.00"),
        dim_inventory_level=dims.get("inventory", 0),
        dim_risk_assessment_level=dims.get("risk_assessment", 0),
        dim_crypto_agility_level=dims.get("crypto_agility", 0),
        dim_migration_level=dims.get("migration", 0),
        dim_tech_impl_level=dims.get("tech_impl", 0),
        dim_supply_chain_level=dims.get("supply_chain", 0),
        dim_governance_level=dims.get("governance", 0),
        dim_awareness_level=dims.get("awareness", 0),
        recommendations=[],
        assessment_input=body.model_dump(),
    )
    db.add(score)
    db.add(
        AuditLog(
            actor_id=uuid.UUID(payload["sub"]),
            actor_email=payload.get("email"),
            action="UPSERT_QSRI",
            resource_type="qsri",
            resource_id=score.id,
            new_value=body.model_dump(),
        )
    )
    await db.flush()
    return await get_qsri(scan_id, payload, db)
