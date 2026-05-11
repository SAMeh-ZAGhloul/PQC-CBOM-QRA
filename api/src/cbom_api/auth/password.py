"""bcrypt password hashing with cost factor 12."""
from __future__ import annotations

import bcrypt


def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt (cost=12)."""
    if len(plain) < 12:
        raise ValueError("Password must be at least 12 characters")
    hashed = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
