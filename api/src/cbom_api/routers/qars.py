from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select

from ..auth.rbac import require_role
from ..db.session import DBSession
from ..models.db import CryptoAsset, QarsScore
from ..models.schemas import QarsScoreResponse

router = APIRouter()
RequireRead = Annotated[dict, Depends(require_role("admin", "engineer", "ciso"))]


@router.get("", response_model=list[QarsScoreResponse])
async def list_qars(payload: RequireRead, db: DBSession) -> list[QarsScoreResponse]:
    result = await db.execute(select(QarsScore, CryptoAsset).join(CryptoAsset, CryptoAsset.id == QarsScore.asset_id))
    items: list[QarsScoreResponse] = []
    for score, asset in result.all():
        items.append(
            QarsScoreResponse(
                asset_id=score.asset_id,
                algorithm=asset.algorithm,
                location=asset.location,
                x_value=score.x_value,
                y_value=score.y_value,
                z_value=score.z_value,
                mosca_urgent=score.mosca_urgent,
                base_qars=score.base_qars,
                weighted_qars=score.weighted_qars,
                severity=score.severity,
                pqc_replacement=asset.pqc_replacement,
                compliance_gaps=score.compliance_gaps,
            )
        )
    return items
