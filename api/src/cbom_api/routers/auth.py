from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    is_refresh_token_valid,
    revoke_refresh_token,
    store_refresh_token,
)
from ..auth.password import verify_password
from ..db.session import DBSession
from ..dependencies import RedisClient
from ..models.db import AuditLog, User, UserSession
from ..models.schemas import LoginRequest, LoginResponse, RefreshRequest, TokenResponse

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, db: DBSession, redis: RedisClient) -> LoginResponse:
    result = await db.execute(select(User).options(selectinload(User.groups)).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is inactive")

    user.last_login_at = datetime.now(UTC)
    access_token, _ = create_access_token(str(user.id), user.email, user.rbac_roles)
    refresh_token, refresh_jti = create_refresh_token(str(user.id))
    await store_refresh_token(redis, refresh_jti, str(user.id), 7)

    db.add(
        UserSession(
            jti=uuid.UUID(refresh_jti),
            user_id=user.id,
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
    )
    db.add(
        AuditLog(
            actor_id=user.id,
            actor_email=user.email,
            action="LOGIN",
            resource_type="user",
            resource_id=user.id,
        )
    )

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user={
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "roles": user.rbac_roles,
        },
    )


@router.post("/logout", response_model=dict[str, str])
async def logout(body: RefreshRequest, db: DBSession, redis: RedisClient) -> dict[str, str]:
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Token type must be 'refresh'")

    await revoke_refresh_token(redis, payload["jti"])
    result = await db.execute(select(UserSession).where(UserSession.jti == uuid.UUID(payload["jti"])))
    session = result.scalar_one_or_none()
    if session is not None:
        session.revoked_at = datetime.now(UTC)
        db.add(
            AuditLog(
                actor_id=session.user_id,
                action="LOGOUT",
                resource_type="session",
                resource_id=session.jti,
            )
        )
    return {"status": "logged_out"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: DBSession, redis: RedisClient) -> TokenResponse:
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Token type must be 'refresh'")
    if not await is_refresh_token_valid(redis, payload["jti"]):
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired")

    result = await db.execute(select(User).options(selectinload(User.groups)).where(User.id == uuid.UUID(payload["sub"])))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    access_token, _ = create_access_token(str(user.id), user.email, user.rbac_roles)
    refresh_token, refresh_jti = create_refresh_token(str(user.id))
    await revoke_refresh_token(redis, payload["jti"])
    await store_refresh_token(redis, refresh_jti, str(user.id), 7)
    db.add(
        AuditLog(
            actor_id=user.id,
            actor_email=user.email,
            action="REFRESH_TOKEN",
            resource_type="session",
            resource_id=uuid.UUID(refresh_jti),
        )
    )
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)
