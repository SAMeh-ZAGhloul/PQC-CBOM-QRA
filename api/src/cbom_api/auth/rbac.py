"""RBAC role checking - FastAPI Depends() decorators."""
from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, status

from ..dependencies import get_current_token

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"*"},
    "engineer": {"scan:*", "cbom:*", "finding:*", "cert:read", "report:read", "report:export"},
    "ciso": {"scan:read", "cbom:read", "finding:read", "finding:approve", "cert:read", "report:*", "qars:read", "qsri:*"},
    "auditor": {"scan:read", "cbom:read", "finding:read", "cert:read", "report:export"},
    "ceo": {"dashboard:executive"},
}


def require_role(*allowed_roles: str) -> Callable:
    """Dependency factory - raises 403 if user lacks required role."""

    def dependency(payload: dict = Depends(get_current_token)) -> dict:
        user_roles: list[str] = payload.get("roles", [])
        if not any(role in allowed_roles for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {allowed_roles}",
            )
        return payload

    return dependency


def require_any_authenticated() -> Callable:
    return require_role("admin", "engineer", "ciso", "auditor", "ceo")
