from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from ..auth.rbac import require_role
from ..db.session import DBSession
from ..models.db import CryptoAsset, Finding, QarsScore, Scan
from ..models.schemas import ReportRequest, ReportResponse
from ..services.cbom_service import get_latest_cbom
from ..services.report_service import generate_report

router = APIRouter()
RequireRead = Annotated[dict, Depends(require_role("admin", "engineer", "ciso", "auditor", "ceo"))]


@router.post("", response_model=ReportResponse)
async def create_report(payload: RequireRead, body: ReportRequest, db: DBSession) -> ReportResponse:
    scan = await db.get(Scan, body.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    cbom_version = await get_latest_cbom(db, body.scan_id)
    assets = list((await db.execute(select(CryptoAsset).where(CryptoAsset.scan_id == body.scan_id))).scalars().all())
    findings = list((await db.execute(select(Finding).where(Finding.scan_id == body.scan_id))).scalars().all())
    qars_scores = list((await db.execute(select(QarsScore).where(QarsScore.scan_id == body.scan_id))).scalars().all())
    url = await generate_report(
        scan_id=str(body.scan_id),
        format=body.format,
        cbom_json=(cbom_version.cyclonedx_json if cbom_version else {}),
        assets=assets,
        findings=findings,
        qars_scores=qars_scores,
    )
    return ReportResponse(download_url=url, expires_at=datetime.now(UTC) + timedelta(hours=24))
