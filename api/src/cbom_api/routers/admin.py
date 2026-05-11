from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.password import hash_password
from ..auth.rbac import require_role
from ..db.session import get_db
from ..models.db import AuditLog, Group, User, UserGroup, UserSession
from ..models.schemas import GroupCreateRequest, GroupResponse, PaginatedResponse, UserCreateRequest, UserResponse, UserUpdateRequest

router = APIRouter()
logger = structlog.get_logger()

RequireAdmin = Annotated[dict, Depends(require_role("admin"))]
DBSession = Annotated[AsyncSession, Depends(get_db)]


@router.get("/users", response_model=PaginatedResponse[UserResponse])
async def list_users(payload: RequireAdmin, db: DBSession, page: int = 1, limit: int = 50) -> PaginatedResponse[UserResponse]:
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).offset((page - 1) * limit).limit(limit)
    )
    users = result.scalars().all()
    return PaginatedResponse(items=[UserResponse.model_validate(user) for user in users], page=page, limit=limit, total=len(users))


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(payload: RequireAdmin, body: UserCreateRequest, db: DBSession) -> UserResponse:
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        display_name=body.display_name,
        is_active=True,
    )
    db.add(user)
    await db.flush()

    for group_id in body.group_ids:
        db.add(UserGroup(user_id=user.id, group_id=group_id))

    db.add(
        AuditLog(
            actor_id=uuid.UUID(payload["sub"]),
            actor_email=payload["email"],
            action="CREATE_USER",
            resource_type="user",
            resource_id=user.id,
            new_value={"email": body.email, "group_ids": [str(g) for g in body.group_ids]},
        )
    )

    logger.info("user_created", user_id=str(user.id), email=body.email)
    return UserResponse.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: uuid.UUID, payload: RequireAdmin, body: UserUpdateRequest, db: DBSession) -> UserResponse:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_values = {"is_active": user.is_active, "display_name": user.display_name}
    if body.display_name is not None:
        user.display_name = body.display_name
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password is not None:
        user.password_hash = hash_password(body.password)
    if body.group_ids is not None:
        await db.execute(delete(UserGroup).where(UserGroup.user_id == user_id))
        for group_id in body.group_ids:
            db.add(UserGroup(user_id=user_id, group_id=group_id))

    db.add(
        AuditLog(
            actor_id=uuid.UUID(payload["sub"]),
            actor_email=payload["email"],
            action="UPDATE_USER",
            resource_type="user",
            resource_id=user_id,
            old_value=old_values,
            new_value=body.model_dump(exclude_none=True),
        )
    )
    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", status_code=status.HTTP_200_OK, response_class=Response)
async def deactivate_user(user_id: uuid.UUID, payload: RequireAdmin, db: DBSession) -> None:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if str(user_id) == payload["sub"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    user.is_active = False
    db.add(
        AuditLog(
            actor_id=uuid.UUID(payload["sub"]),
            actor_email=payload["email"],
            action="DEACTIVATE_USER",
            resource_type="user",
            resource_id=user_id,
        )
    )


@router.get("/groups", response_model=list[GroupResponse])
async def list_groups(payload: RequireAdmin, db: DBSession) -> list[GroupResponse]:
    result = await db.execute(select(Group).order_by(Group.name))
    return [GroupResponse.model_validate(group) for group in result.scalars().all()]


@router.post("/groups", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(payload: RequireAdmin, body: GroupCreateRequest, db: DBSession) -> GroupResponse:
    group = Group(name=body.name, rbac_role=body.rbac_role, description=body.description)
    db.add(group)
    await db.flush()
    db.add(
        AuditLog(
            actor_id=uuid.UUID(payload["sub"]),
            actor_email=payload["email"],
            action="CREATE_GROUP",
            resource_type="group",
            resource_id=group.id,
            new_value={"name": body.name, "rbac_role": body.rbac_role},
        )
    )
    return GroupResponse.model_validate(group)


@router.delete("/groups/{group_id}", status_code=status.HTTP_200_OK, response_class=Response)
async def delete_group(group_id: uuid.UUID, payload: RequireAdmin, db: DBSession) -> None:
    default_group_names = {"administrators", "security-team", "cisos", "auditors", "executives"}
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group.name in default_group_names:
        raise HTTPException(status_code=400, detail="Cannot delete default groups")
    await db.execute(delete(Group).where(Group.id == group_id))
    db.add(
        AuditLog(
            actor_id=uuid.UUID(payload["sub"]),
            actor_email=payload["email"],
            action="DELETE_GROUP",
            resource_type="group",
            resource_id=group_id,
        )
    )


@router.get("/audit")
async def get_audit_log(payload: RequireAdmin, db: DBSession, page: int = 1, limit: int = 100, resource_type: str | None = None):
    query = select(AuditLog).order_by(AuditLog.created_at.desc())
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    query = query.offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/sessions")
async def list_sessions(payload: RequireAdmin, db: DBSession):
    result = await db.execute(
        select(UserSession)
        .where(UserSession.expires_at > datetime.now(UTC), UserSession.revoked_at.is_(None))
        .order_by(UserSession.created_at.desc())
        .limit(200)
    )
    return result.scalars().all()


@router.delete("/sessions/{jti}", status_code=status.HTTP_200_OK, response_class=Response)
async def revoke_session(jti: uuid.UUID, payload: RequireAdmin, db: DBSession) -> None:
    result = await db.execute(select(UserSession).where(UserSession.jti == jti))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session.revoked_at = datetime.now(UTC)
    db.add(
        AuditLog(
            actor_id=uuid.UUID(payload["sub"]),
            actor_email=payload["email"],
            action="REVOKE_SESSION",
            resource_type="session",
            resource_id=jti,
        )
    )
