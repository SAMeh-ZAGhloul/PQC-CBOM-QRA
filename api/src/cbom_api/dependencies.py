"""Shared FastAPI Depends() functions for auth and RBAC."""
from __future__ import annotations

from typing import Annotated, Any

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .auth.jwt import decode_token
from .config import get_settings

settings = get_settings()
_bearer = HTTPBearer(auto_error=True)


async def get_redis():
    """Dependency: Redis client."""
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


async def get_current_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
) -> dict[str, Any]:
    """Decode and validate JWT access token from Authorization header."""
    try:
        payload = decode_token(credentials.credentials)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Token type must be 'access'")
    return payload


async def get_current_token_ws(websocket: WebSocket) -> dict[str, Any]:
    """Extract and validate JWT from WebSocket query param ?token=..."""
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        raise HTTPException(status_code=401, detail="No token provided")
    try:
        return decode_token(token)
    except ValueError:
        await websocket.close(code=1008)
        raise HTTPException(status_code=401, detail="Invalid token")


CurrentUser = Annotated[dict[str, Any], Depends(get_current_token)]
RedisClient = Annotated[aioredis.Redis, Depends(get_redis)]
