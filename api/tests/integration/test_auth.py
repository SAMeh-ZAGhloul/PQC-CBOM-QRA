import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, db_session):
    from cbom_api.auth.password import hash_password
    from cbom_api.models.db import Group, User, UserGroup

    group = Group(name="test-engineers", rbac_role="engineer")
    db_session.add(group)
    user = User(email="test@cbom.local", password_hash=hash_password("ValidPass123!"))
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserGroup(user_id=user.id, group_id=group.id))
    await db_session.commit()

    resp = await client.post("/auth/login", json={"email": "test@cbom.local", "password": "ValidPass123!"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    resp = await client.post("/auth/login", json={"email": "test@cbom.local", "password": "WrongPassword!"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_no_token(client: AsyncClient):
    resp = await client.get("/api/scans")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_valid_token(client: AsyncClient, engineer_token: str):
    resp = await client.get("/api/scans", headers={"Authorization": f"Bearer {engineer_token}"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_endpoint_rejects_engineer(client: AsyncClient, engineer_token: str):
    resp = await client.get("/api/admin/users", headers={"Authorization": f"Bearer {engineer_token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_endpoint_accepts_admin(client: AsyncClient, admin_token: str):
    resp = await client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
