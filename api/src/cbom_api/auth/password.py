"""bcrypt password hashing with cost factor 12."""
from __future__ import annotations

from passlib.context import CryptContext

_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt (cost=12)."""
    if len(plain) < 12:
        raise ValueError("Password must be at least 12 characters")
    return _ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return _ctx.verify(plain, hashed)
