from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Generic, Optional, TypeVar

from pydantic import BaseModel, EmailStr, Field

T = TypeVar("T")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)


class RefreshRequest(BaseModel):
    refresh_token: str


class ScanCreateRequest(BaseModel):
    name: Optional[str] = None
    target_repos: list[str] = Field(default_factory=list)
    target_hosts: list[str] = Field(default_factory=list)
    target_db_connections: list[str] = Field(default_factory=list)
    network_interface: str = "eth0"
    max_file_depth: int = Field(default=5, ge=1, le=10)
    enable_llm_fallback: bool = True
    sector: str = "general_enterprise"
    q_day_year: int = Field(default=2030, ge=2025, le=2040)


class ScanResponse(BaseModel):
    scan_id: uuid.UUID
    status: str


class ScanDetailResponse(BaseModel):
    id: uuid.UUID
    name: Optional[str]
    status: str
    config: dict
    assets_found: int
    files_scanned: int
    progress: int = 0
    findings_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CryptoAssetResponse(BaseModel):
    id: uuid.UUID
    algorithm: str
    key_size: Optional[int]
    crypto_type: str
    quantum_class: str
    pqc_replacement: Optional[str]
    location: str
    line_number: Optional[int]
    source: str
    confidence: str
    qars_score: Optional[Decimal] = None
    severity: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime

    class Config:
        from_attributes = True


class AssetAnnotateRequest(BaseModel):
    owner: Optional[str] = Field(default=None, max_length=200)
    system_name: Optional[str] = Field(default=None, max_length=200)
    data_classification: Optional[str] = Field(default=None, max_length=50)
    migration_status: Optional[str] = Field(default=None, max_length=50)


class QarsScoreResponse(BaseModel):
    asset_id: uuid.UUID
    algorithm: str
    location: str
    x_value: Decimal
    y_value: Decimal
    z_value: Decimal
    mosca_urgent: bool
    base_qars: Decimal
    weighted_qars: Decimal
    severity: str
    pqc_replacement: Optional[str]
    compliance_gaps: list[dict]


class QsriInputRequest(BaseModel):
    dimensions: dict[str, int] = Field(default_factory=dict)


class QsriScoreResponse(BaseModel):
    scan_id: uuid.UUID
    total_score: Decimal
    dimensions: dict[str, int]
    recommendations: list[dict]
    computed_at: datetime


class FindingUpdateRequest(BaseModel):
    status: Optional[str] = None
    owner_id: Optional[uuid.UUID] = None
    due_date: Optional[date] = None
    rationale: Optional[str] = None


class FindingResponse(BaseModel):
    id: uuid.UUID
    severity: str
    finding_type: str
    title: str
    description: str
    recommendation: str
    status: str
    owner_id: Optional[uuid.UUID]
    due_date: Optional[date]
    framework: Optional[str]
    control_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CertificateResponse(BaseModel):
    id: uuid.UUID
    subject: str
    issuer: str
    key_algorithm: str
    key_size: Optional[int]
    signature_algorithm: str
    quantum_class: str
    valid_until: Optional[datetime]
    days_until_expiry: Optional[int]
    location: str

    class Config:
        from_attributes = True


class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)
    display_name: Optional[str] = None
    group_ids: list[uuid.UUID] = Field(default_factory=list)


class UserUpdateRequest(BaseModel):
    password: Optional[str] = Field(default=None, min_length=12)
    display_name: Optional[str] = None
    is_active: Optional[bool] = None
    group_ids: Optional[list[uuid.UUID]] = None


class GroupCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    rbac_role: str
    description: Optional[str] = None


class GroupResponse(BaseModel):
    id: uuid.UUID
    name: str
    rbac_role: str
    description: Optional[str]

    class Config:
        from_attributes = True


class UserResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    display_name: Optional[str]
    is_active: bool
    groups: list[GroupResponse] = Field(default_factory=list)
    created_at: datetime

    class Config:
        from_attributes = True


class ReportRequest(BaseModel):
    scan_id: uuid.UUID
    format: str


class ReportResponse(BaseModel):
    download_url: str
    expires_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class AuthenticatedUserResponse(BaseModel):
    id: str
    email: EmailStr
    display_name: Optional[str]
    roles: list[str]


class LoginResponse(TokenResponse):
    user: AuthenticatedUserResponse


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    page: int
    limit: int
    total: int
