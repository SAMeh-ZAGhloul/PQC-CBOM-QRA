"""Shared test fixtures for API tests."""
from __future__ import annotations

import asyncio
import uuid
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cbom_api.auth.jwt import create_access_token
from cbom_api.main import create_app
from cbom_api.models.db import Base

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def setex(self, key: str, _ttl: int, value: str) -> None:
        self.store[key] = value

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)

    async def exists(self, key: str) -> int:
        return int(key in self.store)

    async def get(self, key: str):
        return self.store.get(key)

    async def aclose(self) -> None:
        return None


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with SessionLocal() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    fake_redis = FakeRedis()

    from cbom_api.db.session import get_db
    from cbom_api.dependencies import get_redis

    async def override_get_db():
        yield db_session

    async def override_get_redis():
        yield fake_redis

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()


def make_token(role: str = "engineer") -> str:
    user_id = str(uuid.uuid4())
    token, _ = create_access_token(user_id, f"{role}@test.com", [role])
    return token


@pytest.fixture
def admin_token() -> str:
    return make_token("admin")


@pytest.fixture
def engineer_token() -> str:
    return make_token("engineer")


@pytest.fixture
def ciso_token() -> str:
    return make_token("ciso")


@pytest.fixture
def auditor_token() -> str:
    return make_token("auditor")
