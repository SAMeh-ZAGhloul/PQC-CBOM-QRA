# 14 -- Admin UI (Embedded in React)

> Read `00_MASTER_SPEC.md`, `13_FRONTEND_REACT.md`, `05_API_BACKEND.md` first.

---

## Overview

The Admin UI is a protected `/admin` route within the React SPA, visible
only to users with the `admin` role. It shares the AppLayout (sidebar + topbar)
and uses the same API client as the rest of the frontend.

No separate service or port -- everything is served from the same
Nginx container on port 3000.

---

## RBAC Model

### Five Pre-defined Roles (immutable in MVP)

| Role | Label | Permissions Summary |
|------|-------|-------------------|
| `admin` | Administrator | Full access including user/group management |
| `engineer` | Security Engineer | Scan execution, CBOM, findings, export |
| `ciso` | CISO | Read-all, approve/defer findings, compliance export |
| `auditor` | Auditor | Read-only, compliance export only |
| `ceo` | Executive | Executive KPI dashboard only |

### Groups
- Each group is assigned **exactly one** role
- Users can belong to **multiple** groups (roles are unioned)
- Default groups seeded at startup: administrators, security-team, cisos, auditors, executives

---

## API Endpoints (api/routers/admin.py)

```python
from __future__ import annotations
import uuid
from typing import Annotated
import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth.rbac import require_role
from ..auth.password import hash_password
from ..db.session import get_db
from ..models.db import User, Group, UserGroup, AuditLog
from ..models.schemas import (
    UserCreateRequest, UserUpdateRequest, UserResponse,
    GroupCreateRequest, GroupResponse, PaginatedResponse,
)

router = APIRouter()
logger = structlog.get_logger()

RequireAdmin = Annotated[dict, Depends(require_role("admin"))]
DBSession = Annotated[AsyncSession, Depends(get_db)]


# ── Users ─────────────────────────────────────────────────────────────────

@router.get("/users", response_model=PaginatedResponse[UserResponse])
async def list_users(
    payload: RequireAdmin,
    db: DBSession,
    page: int = 1,
    limit: int = 50,
) -> PaginatedResponse[UserResponse]:
    result = await db.execute(
        select(User).order_by(User.created_at.desc())
        .offset((page - 1) * limit).limit(limit)
    )
    users = result.scalars().all()
    return PaginatedResponse(items=users, page=page, limit=limit, total=len(users))


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: RequireAdmin,
    body: UserCreateRequest,
    db: DBSession,
) -> UserResponse:
    # Check email uniqueness
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

    # Assign groups
    for group_id in body.group_ids:
        db.add(UserGroup(user_id=user.id, group_id=group_id))

    # Audit log
    db.add(AuditLog(
        actor_id=uuid.UUID(payload["sub"]),
        actor_email=payload["email"],
        action="CREATE_USER",
        resource_type="user",
        resource_id=user.id,
        new_value={"email": body.email, "group_ids": [str(g) for g in body.group_ids]},
    ))

    await db.commit()
    logger.info("user_created", user_id=str(user.id), email=body.email)
    return user


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    payload: RequireAdmin,
    body: UserUpdateRequest,
    db: DBSession,
) -> UserResponse:
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

    db.add(AuditLog(
        actor_id=uuid.UUID(payload["sub"]),
        actor_email=payload["email"],
        action="UPDATE_USER",
        resource_type="user",
        resource_id=user_id,
        old_value=old_values,
        new_value=body.model_dump(exclude_none=True),
    ))

    await db.commit()
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: uuid.UUID,
    payload: RequireAdmin,
    db: DBSession,
) -> None:
    """Deactivate (soft-delete) a user. Does not delete audit log records."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if str(user_id) == payload["sub"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    user.is_active = False
    db.add(AuditLog(
        actor_id=uuid.UUID(payload["sub"]),
        actor_email=payload["email"],
        action="DEACTIVATE_USER",
        resource_type="user",
        resource_id=user_id,
    ))
    await db.commit()


# ── Groups ────────────────────────────────────────────────────────────────

@router.get("/groups", response_model=list[GroupResponse])
async def list_groups(payload: RequireAdmin, db: DBSession) -> list[GroupResponse]:
    result = await db.execute(select(Group).order_by(Group.name))
    return result.scalars().all()


@router.post("/groups", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: RequireAdmin,
    body: GroupCreateRequest,
    db: DBSession,
) -> GroupResponse:
    group = Group(name=body.name, rbac_role=body.rbac_role, description=body.description)
    db.add(group)
    await db.flush()
    db.add(AuditLog(
        actor_id=uuid.UUID(payload["sub"]),
        actor_email=payload["email"],
        action="CREATE_GROUP",
        resource_type="group",
        resource_id=group.id,
        new_value={"name": body.name, "rbac_role": body.rbac_role},
    ))
    await db.commit()
    return group


@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: uuid.UUID,
    payload: RequireAdmin,
    db: DBSession,
) -> None:
    DEFAULT_GROUP_NAMES = {"administrators","security-team","cisos","auditors","executives"}
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group.name in DEFAULT_GROUP_NAMES:
        raise HTTPException(status_code=400, detail="Cannot delete default groups")
    await db.execute(delete(Group).where(Group.id == group_id))
    db.add(AuditLog(
        actor_id=uuid.UUID(payload["sub"]),
        actor_email=payload["email"],
        action="DELETE_GROUP",
        resource_type="group",
        resource_id=group_id,
    ))
    await db.commit()


# ── Audit Log ─────────────────────────────────────────────────────────────

@router.get("/audit")
async def get_audit_log(
    payload: RequireAdmin,
    db: DBSession,
    page: int = 1,
    limit: int = 100,
    resource_type: str | None = None,
):
    query = select(AuditLog).order_by(AuditLog.created_at.desc())
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    query = query.offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


# ── Sessions ──────────────────────────────────────────────────────────────

@router.get("/sessions")
async def list_sessions(payload: RequireAdmin, db: DBSession):
    from ..models.db import UserSession
    from sqlalchemy import and_
    from datetime import UTC, datetime
    result = await db.execute(
        select(UserSession)
        .where(and_(
            UserSession.expires_at > datetime.now(UTC),
            UserSession.revoked_at.is_(None),
        ))
        .order_by(UserSession.created_at.desc())
        .limit(200)
    )
    return result.scalars().all()


@router.delete("/sessions/{jti}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    jti: uuid.UUID,
    payload: RequireAdmin,
    db: DBSession,
) -> None:
    from ..models.db import UserSession
    from datetime import UTC, datetime
    result = await db.execute(select(UserSession).where(UserSession.jti == jti))
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session.revoked_at = datetime.now(UTC)
    db.add(AuditLog(
        actor_id=uuid.UUID(payload["sub"]),
        actor_email=payload["email"],
        action="REVOKE_SESSION",
        resource_type="session",
        resource_id=jti,
    ))
    await db.commit()
```

---

## Frontend: pages/admin/Users.tsx

```typescript
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import apiClient from '../../api/client'
import { UserPlus, Edit, UserX } from 'lucide-react'
import toast from 'react-hot-toast'

interface User {
  id: string
  email: string
  displayName: string | null
  isActive: boolean
  groups: Array<{ id: string; name: string; rbacRole: string }>
  createdAt: string
}

export default function Users() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['admin', 'users'],
    queryFn: () => apiClient.get('/api/admin/users').then(r => r.data),
  })

  const deactivate = useMutation({
    mutationFn: (userId: string) => apiClient.delete(`/api/admin/users/${userId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      toast.success('User deactivated')
    },
    onError: () => toast.error('Failed to deactivate user'),
  })

  if (isLoading) return <div className="p-6">Loading...</div>

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold text-navy-900">User Management</h1>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-teal-700 text-white rounded-md text-sm font-medium hover:bg-teal-800"
        >
          <UserPlus size={16} /> Add User
        </button>
      </div>

      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="bg-navy-900 text-white">
            <th className="px-4 py-3 text-left">Email</th>
            <th className="px-4 py-3 text-left">Display Name</th>
            <th className="px-4 py-3 text-left">Groups / Roles</th>
            <th className="px-4 py-3 text-left">Status</th>
            <th className="px-4 py-3 text-left">Created</th>
            <th className="px-4 py-3 text-left">Actions</th>
          </tr>
        </thead>
        <tbody>
          {data?.items?.map((user: User, i: number) => (
            <tr key={user.id} className={i % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
              <td className="px-4 py-3 font-mono text-sm">{user.email}</td>
              <td className="px-4 py-3">{user.displayName || '--'}</td>
              <td className="px-4 py-3">
                <div className="flex flex-wrap gap-1">
                  {user.groups?.map((g) => (
                    <span key={g.id}
                      className="px-2 py-0.5 rounded text-xs font-medium bg-teal-100 text-teal-800">
                      {g.name} ({g.rbacRole})
                    </span>
                  ))}
                </div>
              </td>
              <td className="px-4 py-3">
                <span className={`px-2 py-0.5 rounded text-xs font-bold
                  ${user.isActive ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                  {user.isActive ? 'Active' : 'Inactive'}
                </span>
              </td>
              <td className="px-4 py-3 text-gray-500 text-xs">
                {new Date(user.createdAt).toLocaleDateString()}
              </td>
              <td className="px-4 py-3">
                <div className="flex gap-2">
                  <button className="p-1 text-gray-500 hover:text-teal-700">
                    <Edit size={14} />
                  </button>
                  {user.isActive && (
                    <button
                      onClick={() => {
                        if (confirm(`Deactivate ${user.email}?`)) {
                          deactivate.mutate(user.id)
                        }
                      }}
                      className="p-1 text-gray-500 hover:text-red-600"
                    >
                      <UserX size={14} />
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} />}
    </div>
  )
}


function CreateUserModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    email: '', password: '', displayName: '', groupIds: [] as string[],
  })

  const { data: groups } = useQuery({
    queryKey: ['admin', 'groups'],
    queryFn: () => apiClient.get('/api/admin/groups').then(r => r.data),
  })

  const create = useMutation({
    mutationFn: () => apiClient.post('/api/admin/users', {
      email: form.email,
      password: form.password,
      display_name: form.displayName || null,
      group_ids: form.groupIds,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      toast.success('User created')
      onClose()
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to create user'),
  })

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md shadow-xl">
        <h2 className="text-lg font-bold mb-4 text-navy-900">Create User</h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Email *</label>
            <input type="email" value={form.email}
              onChange={e => setForm(p => ({ ...p, email: e.target.value }))}
              className="w-full border rounded px-3 py-2 text-sm"
              placeholder="user@example.com" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Password * (min 12 chars)</label>
            <input type="password" value={form.password}
              onChange={e => setForm(p => ({ ...p, password: e.target.value }))}
              className="w-full border rounded px-3 py-2 text-sm" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Display Name</label>
            <input type="text" value={form.displayName}
              onChange={e => setForm(p => ({ ...p, displayName: e.target.value }))}
              className="w-full border rounded px-3 py-2 text-sm" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Groups</label>
            <div className="space-y-1 max-h-40 overflow-y-auto border rounded p-2">
              {groups?.map((g: any) => (
                <label key={g.id} className="flex items-center gap-2 text-sm">
                  <input type="checkbox"
                    checked={form.groupIds.includes(g.id)}
                    onChange={e => {
                      setForm(p => ({
                        ...p,
                        groupIds: e.target.checked
                          ? [...p.groupIds, g.id]
                          : p.groupIds.filter(id => id !== g.id),
                      }))
                    }} />
                  <span>{g.name}</span>
                  <span className="text-xs text-gray-500">({g.rbacRole})</span>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose}
            className="px-4 py-2 text-sm border rounded hover:bg-gray-50">
            Cancel
          </button>
          <button
            onClick={() => create.mutate()}
            disabled={!form.email || form.password.length < 12 || create.isPending}
            className="px-4 py-2 text-sm bg-teal-700 text-white rounded hover:bg-teal-800 disabled:opacity-50"
          >
            {create.isPending ? 'Creating...' : 'Create User'}
          </button>
        </div>
      </div>
    </div>
  )
}
```

---

## Frontend: pages/admin/AuditLog.tsx

```typescript
import { useQuery } from '@tanstack/react-query'
import apiClient from '../../api/client'
import { format } from 'date-fns'

const ACTION_COLORS: Record<string, string> = {
  CREATE_USER:    'bg-green-100 text-green-800',
  UPDATE_USER:    'bg-blue-100 text-blue-800',
  DEACTIVATE_USER:'bg-red-100 text-red-800',
  CREATE_GROUP:   'bg-green-100 text-green-800',
  DELETE_GROUP:   'bg-red-100 text-red-800',
  LOGIN:          'bg-gray-100 text-gray-700',
  LOGOUT:         'bg-gray-100 text-gray-700',
  REVOKE_SESSION: 'bg-orange-100 text-orange-800',
  EXPORT_REPORT:  'bg-purple-100 text-purple-800',
  CREATE_SCAN:    'bg-teal-100 text-teal-800',
  UPDATE_FINDING: 'bg-blue-100 text-blue-800',
}

export default function AuditLog() {
  const { data, isLoading } = useQuery({
    queryKey: ['admin', 'audit'],
    queryFn: () => apiClient.get('/api/admin/audit?limit=100').then(r => r.data),
    refetchInterval: 30000,
  })

  if (isLoading) return <div className="p-6">Loading audit log...</div>

  return (
    <div className="p-6">
      <h1 className="text-xl font-bold mb-6 text-navy-900">Audit Log</h1>
      <p className="text-sm text-gray-500 mb-4">
        Showing last 100 entries. Append-only -- no records can be modified or deleted.
      </p>

      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="bg-navy-900 text-white">
              <th className="px-4 py-3 text-left">Timestamp</th>
              <th className="px-4 py-3 text-left">Actor</th>
              <th className="px-4 py-3 text-left">Action</th>
              <th className="px-4 py-3 text-left">Resource</th>
              <th className="px-4 py-3 text-left">IP Address</th>
            </tr>
          </thead>
          <tbody>
            {data?.map((entry: any, i: number) => (
              <tr key={entry.id} className={i % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                <td className="px-4 py-2 text-xs text-gray-500 whitespace-nowrap">
                  {format(new Date(entry.created_at), 'yyyy-MM-dd HH:mm:ss')}
                </td>
                <td className="px-4 py-2 text-xs font-mono">
                  {entry.actor_email || 'system'}
                </td>
                <td className="px-4 py-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium
                    ${ACTION_COLORS[entry.action] || 'bg-gray-100 text-gray-700'}`}>
                    {entry.action}
                  </span>
                </td>
                <td className="px-4 py-2 text-xs text-gray-600">
                  {entry.resource_type && (
                    <span>{entry.resource_type}:{entry.resource_id?.slice(0,8)}...</span>
                  )}
                </td>
                <td className="px-4 py-2 text-xs font-mono text-gray-500">
                  {entry.ip_address || '--'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
```

---

## scripts/seed-db.sh

```bash
#!/usr/bin/env bash
# Create admin user and verify default groups were seeded by init.sql.
# Run once during `make setup`.

set -euo pipefail

DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_NAME="${POSTGRES_DB:-cbom}"
DB_USER="${POSTGRES_USER:-cbom}"
DB_PASS=$(cat ./secrets/db_password.txt)

echo "==> Waiting for PostgreSQL to be ready..."
until PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c '\q' 2>/dev/null; do
  sleep 2
done

echo "==> Verifying default groups..."
PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << 'SQL'
SELECT name, rbac_role FROM groups ORDER BY name;
SQL

echo ""
echo "==> Creating admin user..."
echo "Enter admin email (default: admin@cbom.local):"
read -r ADMIN_EMAIL
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@cbom.local}"

echo "Enter admin password (min 12 chars):"
read -rs ADMIN_PASS
echo ""

if [[ ${#ADMIN_PASS} -lt 12 ]]; then
  echo "ERROR: Password must be at least 12 characters."
  exit 1
fi

# Hash password using Python bcrypt (available in the api container)
HASH=$(docker exec cbom-api python3 -c "
from passlib.context import CryptContext
ctx = CryptContext(schemes=['bcrypt'], deprecated='auto')
print(ctx.hash('${ADMIN_PASS}'))
")

ADMIN_GROUP_ID=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
  "SELECT id FROM groups WHERE name = 'administrators' LIMIT 1;")

PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << SQL
INSERT INTO users (email, password_hash, display_name, is_active, is_admin)
VALUES ('${ADMIN_EMAIL}', '${HASH}', 'Platform Administrator', true, true)
ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash;

INSERT INTO user_groups (user_id, group_id)
SELECT id, '${ADMIN_GROUP_ID}' FROM users WHERE email = '${ADMIN_EMAIL}'
ON CONFLICT DO NOTHING;
SQL

echo "==> Admin user created: ${ADMIN_EMAIL}"
echo "==> Login at: https://localhost"
```
