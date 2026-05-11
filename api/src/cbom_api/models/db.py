"""SQLAlchemy 2.x async ORM models - mirrors init.sql exactly."""
from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import BigInteger, Boolean, Date, DateTime, Enum, ForeignKey, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    rbac_role: Mapped[str] = mapped_column(Enum("admin", "engineer", "ciso", "auditor", "ceo", name="rbac_role"))
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users: Mapped[list["User"]] = relationship("User", secondary="user_groups", back_populates="groups")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    groups: Mapped[list[Group]] = relationship("Group", secondary="user_groups", back_populates="users")
    sessions: Mapped[list["UserSession"]] = relationship("UserSession", back_populates="user")

    @property
    def rbac_roles(self) -> list[str]:
        return [g.rbac_role for g in self.groups]


class UserGroup(Base):
    __tablename__ = "user_groups"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class UserSession(Base):
    __tablename__ = "user_sessions"

    jti: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    ip_address: Mapped[Optional[str]] = mapped_column(INET)

    user: Mapped[User] = relationship("User", back_populates="sessions")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[Optional[str]] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(
        Enum("queued", "running", "partial", "complete", "failed", "cancelled", name="scan_status"),
        default="queued",
    )
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    assets_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    assets: Mapped[list["CryptoAsset"]] = relationship("CryptoAsset", back_populates="scan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan")
    qars_scores: Mapped[list["QarsScore"]] = relationship("QarsScore", back_populates="scan")
    qsri_scores: Mapped[list["QsriScore"]] = relationship("QsriScore", back_populates="scan")
    cbom_versions: Mapped[list["CbomVersion"]] = relationship("CbomVersion", back_populates="scan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    job_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        Enum("queued", "running", "partial", "complete", "failed", "cancelled", name="scan_status"),
        default="queued",
    )
    queue_name: Mapped[Optional[str]] = mapped_column(String(100))
    target: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CbomVersion(Base):
    __tablename__ = "cbom_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    cyclonedx_json: Mapped[Optional[dict]] = mapped_column(JSONB)
    minio_key: Mapped[Optional[str]] = mapped_column(String(500))
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship("Scan", back_populates="cbom_versions")


class CryptoAsset(Base):
    __tablename__ = "crypto_assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dedup_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    cbom_version_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cbom_versions.id", ondelete="SET NULL"))
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(100), nullable=False)
    algorithm_normalized: Mapped[str] = mapped_column(String(100), nullable=False)
    key_size: Mapped[Optional[int]] = mapped_column(Integer)
    crypto_type: Mapped[str] = mapped_column(
        Enum(
            "asymmetric_encryption",
            "digital_signature",
            "key_exchange",
            "symmetric_encryption",
            "hash",
            "mac",
            "kdf",
            "pqc_kem",
            "pqc_signature",
            "unknown",
            name="crypto_type",
        ),
        default="unknown",
    )
    quantum_class: Mapped[str] = mapped_column(
        Enum("vulnerable", "partially_safe", "safe", "pqc", "unknown", name="quantum_class"),
        default="unknown",
    )
    pqc_replacement: Mapped[Optional[str]] = mapped_column(String(100))
    location: Mapped[str] = mapped_column(Text, nullable=False)
    line_number: Mapped[Optional[int]] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(
        Enum("zeek_network", "ast_scanner", "binary_scanner", "cert_scanner", "db_scanner", "slm_fallback", "manual", name="discovery_source"),
        nullable=False,
    )
    library: Mapped[Optional[str]] = mapped_column(String(200))
    usage_context: Mapped[Optional[str]] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    owner: Mapped[Optional[str]] = mapped_column(String(200))
    system_name: Mapped[Optional[str]] = mapped_column(String(200))
    data_classification: Mapped[Optional[str]] = mapped_column(String(50))
    migration_status: Mapped[Optional[str]] = mapped_column(String(50))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    remediation_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship("Scan", back_populates="assets")
    qars_score: Mapped[Optional["QarsScore"]] = relationship("QarsScore", back_populates="asset", uselist=False)
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="asset")


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    issuer: Mapped[str] = mapped_column(Text, nullable=False)
    serial_number: Mapped[Optional[str]] = mapped_column(Text)
    is_ca: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    key_algorithm: Mapped[str] = mapped_column(String(100), nullable=False)
    key_size: Mapped[Optional[int]] = mapped_column(Integer)
    signature_algorithm: Mapped[str] = mapped_column(String(100), nullable=False)
    quantum_class: Mapped[str] = mapped_column(
        Enum("vulnerable", "partially_safe", "safe", "pqc", "unknown", name="quantum_class"),
        default="unknown",
    )
    valid_from: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_expired: Mapped[Optional[bool]] = mapped_column(Boolean)
    days_until_expiry: Mapped[Optional[int]] = mapped_column(Integer)
    sha1_fingerprint: Mapped[Optional[str]] = mapped_column(String(60))
    sha256_fingerprint: Mapped[Optional[str]] = mapped_column(String(95))
    location: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(
        Enum("zeek_network", "ast_scanner", "binary_scanner", "cert_scanner", "db_scanner", "slm_fallback", "manual", name="discovery_source"),
        nullable=False,
    )
    sans: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class QarsScore(Base):
    __tablename__ = "qars_scores"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("crypto_assets.id", ondelete="CASCADE"))
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"))
    x_value: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    y_value: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    z_value: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    mosca_urgent: Mapped[bool] = mapped_column(Boolean, nullable=False)
    sensitivity_weight: Mapped[Decimal] = mapped_column(Numeric(3, 2), nullable=False)
    exposure_factor: Mapped[Decimal] = mapped_column(Numeric(3, 2), nullable=False)
    base_qars: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    weighted_qars: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    severity: Mapped[str] = mapped_column(Enum("critical", "high", "medium", "low", "info", name="severity"), nullable=False)
    sector: Mapped[str] = mapped_column(String(50), nullable=False)
    compliance_gaps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped[CryptoAsset] = relationship("CryptoAsset", back_populates="qars_score")
    scan: Mapped[Scan] = relationship("Scan", back_populates="qars_scores")


class QsriScore(Base):
    __tablename__ = "qsri_scores"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"))
    total_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    dim_inventory_level: Mapped[int] = mapped_column(Integer, nullable=False)
    dim_risk_assessment_level: Mapped[int] = mapped_column(Integer, nullable=False)
    dim_crypto_agility_level: Mapped[int] = mapped_column(Integer, nullable=False)
    dim_migration_level: Mapped[int] = mapped_column(Integer, nullable=False)
    dim_tech_impl_level: Mapped[int] = mapped_column(Integer, nullable=False)
    dim_supply_chain_level: Mapped[int] = mapped_column(Integer, nullable=False)
    dim_governance_level: Mapped[int] = mapped_column(Integer, nullable=False)
    dim_awareness_level: Mapped[int] = mapped_column(Integer, nullable=False)
    recommendations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    cbom_coverage_pct: Mapped[Optional[Decimal]] = mapped_column(Numeric(5, 2))
    assessment_input: Mapped[Optional[dict]] = mapped_column(JSONB)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship("Scan", back_populates="qsri_scores")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("crypto_assets.id", ondelete="SET NULL"))
    cert_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("certificates.id", ondelete="SET NULL"))
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    severity: Mapped[str] = mapped_column(Enum("critical", "high", "medium", "low", "info", name="severity"), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        Enum("open", "in_progress", "resolved", "accepted_risk", name="finding_status"),
        default="open",
    )
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    due_date: Mapped[Optional[date]] = mapped_column(Date)
    rationale: Mapped[Optional[str]] = mapped_column(Text)
    framework: Mapped[Optional[str]] = mapped_column(String(50))
    control_id: Mapped[Optional[str]] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped[Optional[CryptoAsset]] = relationship("CryptoAsset", back_populates="findings")
    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    actor_email: Mapped[Optional[str]] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100))
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    old_value: Mapped[Optional[dict]] = mapped_column(JSONB)
    new_value: Mapped[Optional[dict]] = mapped_column(JSONB)
    ip_address: Mapped[Optional[str]] = mapped_column(INET)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    trace_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
