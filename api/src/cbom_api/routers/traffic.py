from __future__ import annotations

from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException

from ..auth.rbac import require_role
from ..config import get_settings

router = APIRouter()
settings = get_settings()
RequireRun = Annotated[dict, Depends(require_role("engineer", "admin"))]


@router.post("/{scenario}")
async def run_scenario(scenario: str, payload: RequireRun) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            response = await client.post(f"{settings.traffic_sim_url}/api/scenarios/{scenario}/start")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"traffic-sim request failed: {exc}") from exc
    return response.json() if response.content else {"job_id": scenario, "status": "running"}
