import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_scan(client: AsyncClient, engineer_token: str):
    resp = await client.post(
        "/api/scans",
        json={"name": "Test scan", "target_hosts": ["localhost:443"], "sector": "general_enterprise", "q_day_year": 2030},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "scan_id" in data
    assert data["status"] == "queued"


@pytest.mark.asyncio
async def test_get_scan(client: AsyncClient, engineer_token: str):
    create_resp = await client.post(
        "/api/scans",
        json={"name": "Test", "target_hosts": ["localhost:443"]},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    scan_id = create_resp.json()["scan_id"]

    resp = await client.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {engineer_token}"})
    assert resp.status_code == 200
    assert resp.json()["id"] == scan_id


@pytest.mark.asyncio
async def test_auditor_cannot_create_scan(client: AsyncClient, auditor_token: str):
    resp = await client.post("/api/scans", json={"name": "Should fail"}, headers={"Authorization": f"Bearer {auditor_token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_report_export_returns_url(client: AsyncClient, engineer_token: str):
    resp = await client.post(
        "/api/reports",
        json={"scan_id": "00000000-0000-0000-0000-000000000001", "format": "cyclonedx-json"},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert resp.status_code in (200, 404)
    if resp.status_code == 200:
        assert "download_url" in resp.json()
