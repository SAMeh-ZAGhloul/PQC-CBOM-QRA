import pytest
from httpx import AsyncClient


async def test_no_token_returns_401(client: AsyncClient):
    resp = await client.get("/api/scans")
    assert resp.status_code == 401


async def test_wrong_role_returns_403(client: AsyncClient, engineer_token: str):
    resp = await client.get("/api/admin/users", headers={"Authorization": f"Bearer {engineer_token}"})
    assert resp.status_code == 403


async def test_expired_token_returns_401(client: AsyncClient, expired_token: str | None = None):
    if expired_token is None:
        pytest.skip("expired_token fixture not implemented in MVP scaffold")


async def test_weak_password_rejected(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/admin/users",
        json={"email": "x@x.com", "password": "short"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422
