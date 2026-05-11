"""JWT RS256 token lifecycle: create, verify, refresh, revoke."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import redis.asyncio as aioredis
from jose import JWTError, jwt

from ..config import get_settings

settings = get_settings()

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"


def create_access_token(user_id: str, email: str, roles: list[str]) -> tuple[str, str]:
    """Returns (token, jti)."""
    jti = str(uuid.uuid4())
    expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": user_id,
        "email": email,
        "roles": roles,
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": TOKEN_TYPE_ACCESS,
    }
    token = jwt.encode(payload, settings.jwt_private_key, algorithm=settings.jwt_algorithm)
    return token, jti


def create_refresh_token(user_id: str) -> tuple[str, str]:
    """Returns (token, jti)."""
    jti = str(uuid.uuid4())
    expire = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {
        "sub": user_id,
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": TOKEN_TYPE_REFRESH,
    }
    token = jwt.encode(payload, settings.jwt_private_key, algorithm=settings.jwt_algorithm)
    return token, jti


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT. Raises ValueError on failure."""
    try:
        return jwt.decode(
            token,
            settings.jwt_public_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}") from e


async def store_refresh_token(
    redis: aioredis.Redis,
    jti: str,
    user_id: str,
    expire_days: int,
) -> None:
    """Store refresh token JTI in Redis for revocation checking."""
    await redis.setex(f"session:{jti}", expire_days * 86400, user_id)


async def revoke_refresh_token(redis: aioredis.Redis, jti: str) -> None:
    """Revoke a refresh token by deleting it from Redis."""
    await redis.delete(f"session:{jti}")


async def is_refresh_token_valid(redis: aioredis.Redis, jti: str) -> bool:
    """Return True if the refresh token JTI exists in Redis (not revoked)."""
    return bool(await redis.exists(f"session:{jti}"))
