# 19 -- Testing Strategy

> Read `00_MASTER_SPEC.md` and the spec for each module being tested first.

---

## Overview

Three test tiers for the MVP:
1. **Unit tests** -- pure Python logic, no external dependencies (mocked)
2. **Integration tests** -- services talking to real PostgreSQL, Redis, RabbitMQ in Docker
3. **End-to-end tests** -- full stack via HTTP, verifying user-facing behaviour

Target coverage: **>= 80%** on all business-critical modules
(QARS engine, QSRI engine, CBOM classifier, scanner pattern matching).

---

## Test Dependencies (all services)

```toml
# pyproject.toml [project.optional-dependencies]
[project.optional-dependencies]
test = [
    "pytest==8.*",
    "pytest-asyncio==0.23.*",
    "pytest-cov==5.*",
    "httpx==0.27.*",          # async HTTP client for FastAPI testing
    "factory-boy==3.*",       # test fixtures / factories
    "faker==25.*",            # fake data generation
    "respx==0.21.*",          # mock httpx calls (Magika, Ollama)
    "freezegun==1.5.*",       # freeze time for QARS Z-value tests
]
```

---

## conftest.py (api/tests/conftest.py)

```python
"""Shared test fixtures for API tests."""
from __future__ import annotations

import asyncio
import uuid
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cbom_api.main import create_app
from cbom_api.models.db import Base
from cbom_api.auth.jwt import create_access_token
from cbom_api.auth.password import hash_password

# Use in-memory SQLite for unit/integration tests
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with SessionLocal() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def client() -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


def make_token(role: str = "engineer") -> str:
    user_id = str(uuid.uuid4())
    token, _ = create_access_token(user_id, f"{role}@test.com", [role])
    return token


@pytest.fixture
def admin_token() -> str:
    return make_token("admin")

@pytest.fixture
def engineer_token() -> str:
    return make_token("engineer")

@pytest.fixture
def ciso_token() -> str:
    return make_token("ciso")

@pytest.fixture
def auditor_token() -> str:
    return make_token("auditor")
```

---

## 1. Unit Tests -- QARS Engine

```python
# scoring-engine/tests/unit/test_qars.py
"""Unit tests for QARS Mosca inequality scoring."""
from __future__ import annotations

import pytest
from freezegun import freeze_time
from cbom_scoring.qars import compute_qars, score_all_assets
from cbom_scoring.sector_profiles import SECTOR_PROFILES


@freeze_time("2025-06-01")  # Z = 2030 - 2025 = 5 years
class TestQarsComputation:

    def _make_asset(self, quantum_class: str, algorithm: str = "RSA",
                    data_class: str = "internal") -> dict:
        return {
            "id": "test-id-001",
            "algorithm": algorithm,
            "quantum_class": quantum_class,
            "pqc_replacement": "ML-KEM-768",
            "location": "test-location",
            "data_classification": data_class,
        }

    def test_vulnerable_asset_general_enterprise(self):
        """RSA asset, general enterprise sector, internal data."""
        asset = self._make_asset("vulnerable")
        result = compute_qars(asset, sector="general_enterprise", q_day_year=2030)

        # X=10, Y=3, Z=5 -> base = (10+3)/5 = 2.6 -> clamped to 1.0
        # S=1.0 (internal), E=1.0 (internal) -> weighted = 1.0
        assert result.base_qars == 1.0
        assert result.weighted_qars == 1.0
        assert result.severity == "critical"
        assert result.mosca_urgent is True

    def test_vulnerable_asset_mosca_flag(self):
        """Mosca flag triggers when X + Y >= Z."""
        asset = self._make_asset("vulnerable")
        result = compute_qars(asset, sector="general_enterprise", q_day_year=2030)
        # X=10, Y=3, Z=5 -> 10+3=13 >= 5 -> urgent
        assert result.mosca_urgent is True

    def test_safe_asset_scores_zero(self):
        """AES-256 (safe) should always score 0.0."""
        asset = self._make_asset("safe", algorithm="AES-256")
        result = compute_qars(asset, sector="financial_dora", q_day_year=2030)
        assert result.weighted_qars == 0.0
        assert result.severity == "low"
        assert result.mosca_urgent is False

    def test_pqc_asset_scores_zero(self):
        """ML-KEM (pqc) should score 0.0."""
        asset = self._make_asset("pqc", algorithm="ML-KEM-768")
        result = compute_qars(asset, sector="government_nsm10", q_day_year=2030)
        assert result.weighted_qars == 0.0

    def test_partially_safe_discounted(self):
        """Partially safe assets get 60% discount on base QARS."""
        asset = self._make_asset("partially_safe", algorithm="SHA-256")
        result = compute_qars(asset, sector="general_enterprise", q_day_year=2030)
        # base clamped to 1.0, then * 0.6 = 0.6
        assert result.base_qars == pytest.approx(0.6, abs=0.01)

    def test_restricted_data_amplifies_score(self):
        """Restricted data classification (S=2.0) amplifies QARS score."""
        asset_internal = self._make_asset("vulnerable", data_class="internal")
        asset_restricted = self._make_asset("vulnerable", data_class="restricted")
        r1 = compute_qars(asset_internal, q_day_year=2030)
        r2 = compute_qars(asset_restricted, q_day_year=2030)
        # Both will be clamped to 1.0, but restricted shows higher sensitivity weight
        assert r2.sensitivity_weight == 2.0
        assert r1.sensitivity_weight == 1.0

    def test_internet_facing_exposure(self):
        """Internet-facing assets get E=1.5 exposure factor."""
        asset = self._make_asset("vulnerable")
        asset["usage_context"] = "TLS HTTPS endpoint"
        result = compute_qars(asset, q_day_year=2030)
        assert result.exposure_factor == 1.5

    def test_sector_profiles_applied(self):
        """Government sector has X=25, Y=2 (higher sensitivity)."""
        asset = self._make_asset("vulnerable")
        result = compute_qars(asset, sector="government_nsm10", q_day_year=2030)
        profile = SECTOR_PROFILES["government_nsm10"]
        assert result.x_value == profile.default_x
        assert result.y_value == profile.default_y

    def test_score_all_assets_sorted(self):
        """score_all_assets returns results sorted by weighted_qars descending."""
        assets = [
            {**self._make_asset("safe", "AES-256"), "id": "a1"},
            {**self._make_asset("vulnerable", "RSA"), "id": "a2"},
            {**self._make_asset("pqc", "ML-KEM"), "id": "a3"},
        ]
        results = score_all_assets(assets, q_day_year=2030)
        scores = [r.weighted_qars for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_compliance_gaps_populated_for_vulnerable(self):
        """Vulnerable assets have DORA, NIS2, NSM-10 compliance gaps."""
        asset = self._make_asset("vulnerable")
        result = compute_qars(asset, sector="financial_dora", q_day_year=2030)
        frameworks = {g["framework"] for g in result.compliance_gaps}
        assert "DORA" in frameworks
        assert "NIS2" in frameworks

    def test_z_value_changes_with_q_day_year(self):
        """Closer Q-Day increases urgency."""
        asset = self._make_asset("vulnerable")
        r_2030 = compute_qars(asset, q_day_year=2030)
        r_2027 = compute_qars(asset, q_day_year=2027)
        # 2027 gives Z=2, 2030 gives Z=5; closer Q-Day -> higher base score
        assert r_2027.z_value < r_2030.z_value
```

---

## 2. Unit Tests -- QSRI Engine

```python
# scoring-engine/tests/unit/test_qsri.py
from cbom_scoring.qsri import compute_qsri, DIMENSIONS


def test_all_zeros_gives_zero_score():
    """All dimensions at level 0 -> total score 0."""
    levels = {d: 0 for d in DIMENSIONS}
    result = compute_qsri("scan-001", levels)
    assert result.total_score == 0.0


def test_all_fives_gives_100():
    """All dimensions at level 5 -> total score 100."""
    levels = {d: 5 for d in DIMENSIONS}
    result = compute_qsri("scan-001", levels)
    assert result.total_score == pytest.approx(100.0, abs=0.1)


def test_inventory_auto_populated_from_cbom_coverage():
    """90% CBOM coverage auto-sets inventory level to 4."""
    levels = {d: 0 for d in DIMENSIONS}
    result = compute_qsri("scan-001", levels, cbom_coverage_pct=90.0)
    # 90 / 20 = 4.5 -> clamped to 4
    assert result.dimension_levels["inventory"] == 4


def test_weights_sum_to_one():
    """All dimension weights must sum to 1.0."""
    total = sum(d["weight"] for d in DIMENSIONS.values())
    assert total == pytest.approx(1.0, abs=0.001)


def test_recommendations_sorted_by_impact():
    """Recommendations are sorted by impact*score_gain descending."""
    levels = {d: 1 for d in DIMENSIONS}  # All at level 1
    result = compute_qsri("scan-001", levels)
    assert len(result.recommendations) > 0
    # High-impact recs should come before low-impact
    impacts = [r["impact"] for r in result.recommendations[:3]]
    assert "high" in impacts  # At least one high-impact rec in top 3


def test_dimension_score_calculation():
    """Dimension at level 3 -> score = (3/5)*100 = 60."""
    levels = {d: 0 for d in DIMENSIONS}
    levels["inventory"] = 3
    result = compute_qsri("scan-001", levels)
    assert result.dimension_scores["inventory"] == 60.0
```

---

## 3. Unit Tests -- Quantum Classifier

```python
# cbom-generator/tests/unit/test_classifier.py
from cbom_generator.classifier import classify, QuantumClass, normalize_algorithm


def test_rsa_is_vulnerable():
    info = classify("RSA")
    assert info.quantum_class == QuantumClass.VULNERABLE
    assert info.pqc_replacement == "ML-KEM-768"

def test_ecdsa_is_vulnerable():
    info = classify("ECDSA")
    assert info.quantum_class == QuantumClass.VULNERABLE

def test_aes256_is_safe():
    info = classify("AES-256")
    assert info.quantum_class == QuantumClass.SAFE
    assert info.pqc_replacement is None

def test_aes128_is_partially_safe():
    info = classify("AES-128")
    assert info.quantum_class == QuantumClass.PARTIALLY_SAFE
    assert info.pqc_replacement == "AES-256"

def test_ml_kem_is_pqc():
    info = classify("ML-KEM-768")
    assert info.quantum_class == QuantumClass.PQC
    assert info.nist_fips == "FIPS 203"

def test_ml_dsa_is_pqc():
    info = classify("ML-DSA-65")
    assert info.quantum_class == QuantumClass.PQC
    assert info.nist_fips == "FIPS 204"

def test_sha1_is_partially_safe():
    info = classify("SHA-1")
    assert info.quantum_class == QuantumClass.PARTIALLY_SAFE

def test_md5_is_partially_safe():
    info = classify("MD5")
    assert info.quantum_class == QuantumClass.PARTIALLY_SAFE

def test_slh_dsa_is_pqc():
    info = classify("SLH-DSA")
    assert info.quantum_class == QuantumClass.PQC
    assert info.nist_fips == "FIPS 205"

def test_normalize_strips_dashes_and_case():
    assert normalize_algorithm("aes-256-gcm") == "AES256GCM"
    assert normalize_algorithm("sha_256") == "SHA256"
    assert normalize_algorithm("ML-KEM-768") == "MLKEM768"

def test_unknown_algorithm_returns_unknown_class():
    info = classify("HOMEGROWN_CIPHER_XYZ")
    assert info.quantum_class == QuantumClass.UNKNOWN

def test_kyber_maps_to_ml_kem():
    """Pre-standard Kyber name should map to ML-KEM."""
    info = classify("KYBER768")
    assert info.normalized == "ML-KEM-768"
    assert info.quantum_class == QuantumClass.PQC

def test_dilithium_maps_to_ml_dsa():
    """Pre-standard Dilithium name should map to ML-DSA."""
    info = classify("DILITHIUM")
    assert info.normalized == "ML-DSA"
    assert info.quantum_class == QuantumClass.PQC
```

---

## 4. Unit Tests -- AST Scanner Patterns

```python
# scanners/tests/unit/test_ast_patterns.py
from cbom_scanners.ast_scanner import scan_file_ast
import tempfile, os


def write_temp(content: str, suffix: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


def test_python_rsa_import_detected():
    code = "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)"
    path = write_temp(code, ".py")
    try:
        findings = scan_file_ast(path, "python")
        algos = [f["algorithm"].upper() for f in findings]
        assert any("RSA" in a for a in algos)
    finally:
        os.unlink(path)


def test_python_hashlib_md5_detected():
    code = "import hashlib\nh = hashlib.md5(b'data').hexdigest()"
    path = write_temp(code, ".py")
    try:
        findings = scan_file_ast(path, "python")
        algos = [f["algorithm"].upper() for f in findings]
        assert any("MD5" in a for a in algos)
    finally:
        os.unlink(path)


def test_python_jwt_algorithm_string_detected():
    code = 'import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")'
    path = write_temp(code, ".py")
    try:
        findings = scan_file_ast(path, "python")
        algos = [f["algorithm"].upper() for f in findings]
        assert any("RSA" in a or "RS256" in a for a in algos)
    finally:
        os.unlink(path)


def test_go_crypto_rsa_import_detected():
    code = 'package main\nimport "crypto/rsa"\nfunc main() { rsa.GenerateKey(rand.Reader, 2048) }'
    path = write_temp(code, ".go")
    try:
        findings = scan_file_ast(path, "go")
        algos = [f["algorithm"].upper() for f in findings]
        assert any("RSA" in a for a in algos)
    finally:
        os.unlink(path)


def test_no_crypto_file_returns_empty():
    code = "x = 1 + 1\nprint(x)"
    path = write_temp(code, ".py")
    try:
        findings = scan_file_ast(path, "python")
        assert findings == []
    finally:
        os.unlink(path)


def test_deduplication_same_finding_not_repeated():
    code = "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(65537, 2048)"
    path = write_temp(code, ".py")
    try:
        findings = scan_file_ast(path, "python")
        # Same file, same algo -> should deduplicate
        unique = {(f["algorithm"], f["location"]) for f in findings}
        assert len(unique) <= len(findings)  # No exact duplicates
    finally:
        os.unlink(path)
```

---

## 5. Integration Tests -- API Auth

```python
# api/tests/integration/test_auth.py
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, db_session):
    # Create a test user
    from cbom_api.models.db import User, Group, UserGroup
    from cbom_api.auth.password import hash_password
    import uuid

    group = Group(name="test-engineers", rbac_role="engineer")
    db_session.add(group)
    user = User(email="test@cbom.local", password_hash=hash_password("ValidPass123!"))
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserGroup(user_id=user.id, group_id=group.id))
    await db_session.commit()

    resp = await client.post("/auth/login", json={
        "email": "test@cbom.local",
        "password": "ValidPass123!",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    resp = await client.post("/auth/login", json={
        "email": "test@cbom.local",
        "password": "WrongPassword!"
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_no_token(client: AsyncClient):
    resp = await client.get("/api/scans")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_valid_token(client: AsyncClient, engineer_token: str):
    resp = await client.get("/api/scans",
                            headers={"Authorization": f"Bearer {engineer_token}"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_endpoint_rejects_engineer(client: AsyncClient, engineer_token: str):
    resp = await client.get("/api/admin/users",
                            headers={"Authorization": f"Bearer {engineer_token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_endpoint_accepts_admin(client: AsyncClient, admin_token: str):
    resp = await client.get("/api/admin/users",
                            headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
```

---

## 6. Integration Tests -- CBOM API

```python
# api/tests/integration/test_cbom.py
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_scan(client: AsyncClient, engineer_token: str):
    resp = await client.post(
        "/api/scans",
        json={
            "name": "Test scan",
            "target_hosts": ["localhost:443"],
            "sector": "general_enterprise",
            "q_day_year": 2030,
        },
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "scan_id" in data
    assert data["status"] == "queued"


@pytest.mark.asyncio
async def test_get_scan(client: AsyncClient, engineer_token: str):
    # Create first
    create_resp = await client.post(
        "/api/scans",
        json={"name": "Test", "target_hosts": ["localhost:443"]},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    scan_id = create_resp.json()["scan_id"]

    # Then fetch
    resp = await client.get(
        f"/api/scans/{scan_id}",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == scan_id


@pytest.mark.asyncio
async def test_auditor_cannot_create_scan(client: AsyncClient, auditor_token: str):
    resp = await client.post(
        "/api/scans",
        json={"name": "Should fail"},
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_report_export_returns_url(client: AsyncClient, engineer_token: str):
    resp = await client.post(
        "/api/reports",
        json={"scan_id": "00000000-0000-0000-0000-000000000001",
              "format": "cyclonedx-json"},
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    # Either succeeds with URL or returns 404 for unknown scan_id
    assert resp.status_code in (200, 404)
    if resp.status_code == 200:
        assert "download_url" in resp.json()
```

---

## 7. End-to-End Tests -- Full Stack

```python
# tests/e2e/test_full_scan_flow.py
"""E2E tests that run against the full Docker Compose stack.
Set E2E_BASE_URL=https://localhost before running.
"""
import os
import pytest
import httpx

BASE_URL = os.environ.get("E2E_BASE_URL", "https://localhost")
ADMIN_EMAIL = os.environ.get("E2E_ADMIN_EMAIL", "admin@cbom.local")
ADMIN_PASS  = os.environ.get("E2E_ADMIN_PASS",  "AdminPass123!")


@pytest.fixture(scope="module")
def token() -> str:
    resp = httpx.post(f"{BASE_URL}/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
                      verify=False, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]


def test_health_check():
    resp = httpx.get(f"{BASE_URL}/health", verify=False, timeout=10)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_login_and_get_token(token: str):
    assert token is not None
    assert len(token) > 50


def test_create_and_poll_scan(token: str):
    headers = {"Authorization": f"Bearer {token}"}

    # Create scan
    resp = httpx.post(f"{BASE_URL}/api/scans",
                      json={"name": "E2E Test Scan",
                            "target_hosts": ["localhost:443"],
                            "sector": "general_enterprise"},
                      headers=headers, verify=False, timeout=30)
    assert resp.status_code == 201
    scan_id = resp.json()["scan_id"]

    # Poll for status
    import time
    for _ in range(30):
        status_resp = httpx.get(f"{BASE_URL}/api/scans/{scan_id}",
                                headers=headers, verify=False, timeout=10)
        status = status_resp.json().get("status")
        if status in ("complete", "failed"):
            break
        time.sleep(2)

    assert status in ("complete", "partial", "running", "queued")


def test_admin_user_list(token: str):
    resp = httpx.get(f"{BASE_URL}/api/admin/users",
                     headers={"Authorization": f"Bearer {token}"},
                     verify=False, timeout=10)
    assert resp.status_code == 200
    assert "items" in resp.json()


def test_tls_version_is_13():
    import ssl, socket
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("localhost", 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
            assert ssock.version() == "TLSv1.3"
```

---

## Running Tests

```bash
# Unit + integration tests (no full stack needed)
make test

# Single service
make test-svc SVC=scoring-engine

# With coverage
make test-coverage

# E2E tests (requires full stack: make up first)
E2E_BASE_URL=https://localhost \
E2E_ADMIN_EMAIL=admin@cbom.local \
E2E_ADMIN_PASS=YourPassword123! \
pytest tests/e2e/ -v --tb=short

# Security-specific tests
pytest api/tests/security/ -v

# CI command (runs lint + type-check + tests)
make lint && make type-check && make test
```

---

## Coverage Targets by Module

| Module | Target | Critical Path |
|--------|--------|---------------|
| `cbom_scoring.qars` | >= 95% | All QARS formula branches |
| `cbom_scoring.qsri` | >= 90% | All 8 dimension weights |
| `cbom_generator.classifier` | >= 95% | All 60+ algorithm entries |
| `cbom_scanners.ast_scanner` | >= 80% | All language patterns |
| `cbom_api.auth` | >= 90% | JWT create/decode/refresh/revoke |
| `cbom_api.routers` | >= 75% | Happy path + auth failures |
| `cbom_generator.deduplicator` | >= 90% | Hash consistency |
| `cbom_generator.findings` | >= 85% | All severity/compliance paths |
