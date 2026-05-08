# 08 -- QARS & QSRI Scoring Engine

> Read `00_MASTER_SPEC.md`, `07_CBOM_GENERATOR.md` first.

---

## Directory Structure

```
scoring-engine/
├── Dockerfile
├── pyproject.toml
└── src/
    └── cbom_scoring/
        ├── __init__.py
        ├── main.py              # Queue consumer
        ├── config.py
        ├── qars.py              # QARS Mosca inequality engine
        ├── qsri.py              # QSRI 8-dimension maturity engine
        ├── sector_profiles.py   # Per-sector default values
        ├── compliance.py        # DORA/NIS2/NSM-10 control mapping
        └── publisher.py         # Write scores to PostgreSQL
```

---

## sector_profiles.py

```python
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class SectorProfile:
    name: str
    default_x: float       # Data shelf life (years)
    default_y: float       # Migration time (years)
    default_sensitivity: float
    q_day_year: int
    description: str


SECTOR_PROFILES: dict[str, SectorProfile] = {
    "financial_dora": SectorProfile(
        "Financial Services (DORA)", 15.0, 3.0, 1.5, 2030,
        "Banks, payment processors -- DORA regulated"),
    "healthcare_nis2": SectorProfile(
        "Healthcare (NIS2)", 20.0, 3.0, 1.5, 2030,
        "Hospitals, medical devices -- NIS2 regulated"),
    "government_nsm10": SectorProfile(
        "Government (NSM-10)", 25.0, 2.0, 2.0, 2030,
        "Federal agencies, defence -- NSM-10 mandated"),
    "critical_infrastructure": SectorProfile(
        "Critical Infrastructure", 20.0, 3.0, 1.5, 2030,
        "Energy, water, transport -- NIS2 essential entities"),
    "general_enterprise": SectorProfile(
        "General Enterprise", 10.0, 3.0, 1.0, 2030,
        "General commercial organizations"),
    "telecom": SectorProfile(
        "Telecommunications", 15.0, 4.0, 1.5, 2030,
        "Telecom operators -- NIS2 important entities"),
}

SENSITIVITY_WEIGHTS = {
    "public": 0.5, "internal": 1.0, "confidential": 1.5, "restricted": 2.0,
}

EXPOSURE_FACTORS = {
    "internet_facing": 1.5, "internal": 1.0, "air_gapped": 0.5,
}
```

---

## qars.py

```python
"""
QARS -- Quantum-Adjusted Risk Score

Formula:
    Base QARS     = clamp((X + Y) / Z, 0.0, 1.0)
    Weighted QARS = clamp(Base_QARS x S x E, 0.0, 1.0)

    X = data shelf life (years)
    Y = migration timeline (years)
    Z = years to Q-Day from today
    S = sensitivity weight  (0.5 / 1.0 / 1.5 / 2.0)
    E = exposure factor     (0.5 / 1.0 / 1.5)

Mosca urgency flag: X + Y >= Z
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import date
from typing import Any
from .sector_profiles import SECTOR_PROFILES, SENSITIVITY_WEIGHTS, EXPOSURE_FACTORS, SectorProfile
from .compliance import get_compliance_gaps


@dataclass
class QarsResult:
    asset_id: str
    x_value: float
    y_value: float
    z_value: float
    mosca_urgent: bool
    sensitivity_weight: float
    exposure_factor: float
    base_qars: float
    weighted_qars: float
    severity: str
    sector: str
    compliance_gaps: list[dict[str, Any]]
    pqc_replacement: str | None


SEVERITY_BANDS = [(0.80, "critical"), (0.60, "high"), (0.40, "medium"), (0.00, "low")]


def compute_qars(
    asset: dict[str, Any],
    sector: str = "general_enterprise",
    q_day_year: int = 2030,
    sensitivity_override: str | None = None,
    exposure_override: str | None = None,
) -> QarsResult:
    profile: SectorProfile = SECTOR_PROFILES.get(sector, SECTOR_PROFILES["general_enterprise"])
    quantum_class = asset.get("quantum_class", "unknown")

    # Safe / PQC assets score 0.0
    if quantum_class in ("pqc", "safe"):
        return QarsResult(
            asset_id=str(asset.get("id", "")),
            x_value=profile.default_x, y_value=profile.default_y,
            z_value=float(q_day_year - date.today().year),
            mosca_urgent=False, sensitivity_weight=1.0, exposure_factor=1.0,
            base_qars=0.0, weighted_qars=0.0, severity="low",
            sector=sector, compliance_gaps=[], pqc_replacement=asset.get("pqc_replacement"),
        )

    z = float(max(1, q_day_year - date.today().year))
    x = profile.default_x
    y = profile.default_y

    data_class = sensitivity_override or asset.get("data_classification") or "internal"
    s = SENSITIVITY_WEIGHTS.get(data_class, 1.0)

    exposure = exposure_override or _infer_exposure(asset)
    e = EXPOSURE_FACTORS.get(exposure, 1.0)

    mosca_urgent = (x + y) >= z
    base_qars = min(1.0, max(0.0, (x + y) / z))

    if quantum_class == "partially_safe":
        base_qars *= 0.6

    weighted_qars = min(1.0, max(0.0, base_qars * s * e))

    severity = "low"
    for threshold, band in SEVERITY_BANDS:
        if weighted_qars >= threshold:
            severity = band
            break

    compliance_gaps = get_compliance_gaps(quantum_class, sector, asset.get("algorithm", ""))

    return QarsResult(
        asset_id=str(asset.get("id", "")),
        x_value=x, y_value=y, z_value=z,
        mosca_urgent=mosca_urgent,
        sensitivity_weight=s, exposure_factor=e,
        base_qars=round(base_qars, 3), weighted_qars=round(weighted_qars, 3),
        severity=severity, sector=sector,
        compliance_gaps=compliance_gaps, pqc_replacement=asset.get("pqc_replacement"),
    )


def score_all_assets(
    assets: list[dict[str, Any]],
    sector: str = "general_enterprise",
    q_day_year: int = 2030,
) -> list[QarsResult]:
    results = [compute_qars(a, sector, q_day_year) for a in assets]
    return sorted(results, key=lambda r: r.weighted_qars, reverse=True)


def _infer_exposure(asset: dict[str, Any]) -> str:
    loc = asset.get("location", "").lower()
    usage = asset.get("usage_context", "").lower()
    if any(k in loc or k in usage for k in ("https","tls","ssl","api","web","public")):
        return "internet_facing"
    if "air" in loc or "offline" in usage:
        return "air_gapped"
    return "internal"
```

---

## qsri.py

```python
"""
QSRI -- Quantum Security Readiness Index

Score = sum(dimension_score x weight)
  where dimension_score = (maturity_level / 5) x 100

8 dimensions, total weight = 100%.
Maturity levels: 0 (non-existent) -> 5 (optimised).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any


DIMENSIONS = {
    "inventory":       {"weight": 0.15, "label": "Cryptographic Inventory & Discovery"},
    "risk_assessment": {"weight": 0.15, "label": "Risk Assessment"},
    "crypto_agility":  {"weight": 0.15, "label": "Crypto Agility"},
    "migration":       {"weight": 0.15, "label": "Migration Planning"},
    "tech_impl":       {"weight": 0.10, "label": "Technical Implementation"},
    "supply_chain":    {"weight": 0.10, "label": "Supply Chain Security"},
    "governance":      {"weight": 0.10, "label": "Governance & Compliance"},
    "awareness":       {"weight": 0.10, "label": "Awareness & Training"},
}

MATURITY_LEVELS = {
    0: "Non-existent -- no awareness or process",
    1: "Initial -- ad-hoc, reactive",
    2: "Developing -- some documented processes",
    3: "Defined -- consistent, documented processes",
    4: "Managed -- measured and controlled",
    5: "Optimised -- continuous improvement",
}

# (recommendation_text, effort, impact) per dimension per current level
RECOMMENDATIONS: dict[str, dict[int, tuple[str, str, str]]] = {
    "inventory": {
        0: ("Deploy CBOM discovery tooling across all codebases and network segments", "high", "high"),
        1: ("Expand scanner coverage to include binary analysis and database encryption", "medium", "high"),
        2: ("Automate CBOM generation in CI/CD pipeline", "medium", "high"),
        3: ("Achieve 90%+ asset coverage; integrate Zeek network sensor", "low", "medium"),
        4: ("Maintain continuous discovery with real-time CBOM updates", "low", "medium"),
    },
    "risk_assessment": {
        0: ("Implement QARS scoring for all discovered assets", "high", "high"),
        1: ("Apply sector-specific Mosca inequality parameters", "medium", "high"),
        2: ("Integrate QARS into executive risk reporting", "medium", "medium"),
        3: ("Automate QARS trend tracking and alerting", "low", "medium"),
        4: ("Benchmark QARS against sector peers", "low", "low"),
    },
    "crypto_agility": {
        0: ("Audit codebase for hardcoded algorithm names and key sizes", "high", "high"),
        1: ("Refactor to use crypto-agile abstraction layer", "high", "high"),
        2: ("Implement algorithm negotiation in all protocols", "medium", "high"),
        3: ("Deploy hybrid classical+PQC in non-critical systems", "medium", "high"),
        4: ("Full hybrid deployment with PQC primary", "low", "high"),
    },
    "migration": {
        0: ("Create PQC migration roadmap with timeline and resource plan", "high", "high"),
        1: ("Prioritize assets by QARS score; assign owners", "medium", "high"),
        2: ("Begin PoC for ML-KEM and ML-DSA in test environment", "medium", "high"),
        3: ("Deploy PQC in production for internet-facing systems", "medium", "high"),
        4: ("Complete migration of all critical assets", "low", "high"),
    },
    "tech_impl": {
        0: ("Evaluate PQC libraries: liboqs, OQS-OpenSSL, BouncyCastle PQC", "high", "high"),
        1: ("Test ML-KEM-768 for key exchange in staging", "medium", "high"),
        2: ("Deploy hybrid TLS (classical + ML-KEM) on internet endpoints", "medium", "high"),
        3: ("Replace RSA signatures with ML-DSA-65", "medium", "high"),
        4: ("Complete PQC deployment for all cryptographic operations", "low", "high"),
    },
    "supply_chain": {
        0: ("Inventory third-party crypto dependencies", "high", "medium"),
        1: ("Request CBOM from critical vendors", "medium", "medium"),
        2: ("Include PQC readiness in vendor assessment criteria", "medium", "medium"),
        3: ("Mandate PQC timelines in vendor contracts", "low", "medium"),
        4: ("Continuous supply chain crypto monitoring", "low", "low"),
    },
    "governance": {
        0: ("Assign PQC migration ownership at CISO level", "high", "medium"),
        1: ("Establish PQC steering committee with executive sponsorship", "medium", "medium"),
        2: ("Integrate PQC milestones into board risk reporting", "medium", "medium"),
        3: ("Achieve DORA/NIS2 compliance with documented evidence", "low", "medium"),
        4: ("Continuous compliance monitoring and regulatory engagement", "low", "low"),
    },
    "awareness": {
        0: ("Deliver PQC awareness training to security team", "high", "medium"),
        1: ("Train development teams on PQC-safe coding practices", "medium", "medium"),
        2: ("Include PQC in onboarding for engineering roles", "medium", "low"),
        3: ("Executive briefings on quantum risk and timeline", "low", "low"),
        4: ("Organization-wide PQC fluency programme", "low", "low"),
    },
}


@dataclass
class QsriResult:
    scan_id: str
    total_score: float
    dimension_levels: dict[str, int]
    dimension_scores: dict[str, float]
    recommendations: list[dict[str, Any]]
    cbom_coverage_pct: float | None = None


def compute_qsri(
    scan_id: str,
    dimension_levels: dict[str, int],
    cbom_coverage_pct: float | None = None,
) -> QsriResult:
    # Auto-populate inventory from CBOM coverage
    if cbom_coverage_pct is not None:
        auto_level = min(5, int(cbom_coverage_pct / 20))
        dimension_levels["inventory"] = max(dimension_levels.get("inventory", 0), auto_level)

    dimension_scores: dict[str, float] = {}
    total_score = 0.0

    for dim_key, meta in DIMENSIONS.items():
        level = max(0, min(5, dimension_levels.get(dim_key, 0)))
        dim_score = (level / 5) * 100
        dimension_scores[dim_key] = dim_score
        total_score += dim_score * meta["weight"]

    recommendations = []
    impact_order = {"high": 3, "medium": 2, "low": 1}
    for dim_key, meta in DIMENSIONS.items():
        level = dimension_levels.get(dim_key, 0)
        if level < 5:
            rec_data = RECOMMENDATIONS.get(dim_key, {}).get(level)
            if rec_data:
                text, effort, impact = rec_data
                recommendations.append({
                    "dimension": dim_key,
                    "dimension_label": meta["label"],
                    "current_level": level,
                    "target_level": level + 1,
                    "recommendation": text,
                    "effort": effort,
                    "impact": impact,
                    "score_gain": round(meta["weight"] * (1 / 5) * 100, 2),
                })

    recommendations.sort(key=lambda r: impact_order[r["impact"]] * r["score_gain"], reverse=True)

    return QsriResult(
        scan_id=scan_id,
        total_score=round(total_score, 2),
        dimension_levels=dimension_levels,
        dimension_scores=dimension_scores,
        recommendations=recommendations,
        cbom_coverage_pct=cbom_coverage_pct,
    )
```

---

## compliance.py

```python
from __future__ import annotations
from typing import Any

COMPLIANCE_CONTROLS: dict[str, dict[str, list[dict]]] = {
    "vulnerable": {
        "DORA": [
            {"control_id":"ICT-2.1","description":"Quantum-vulnerable cryptography in critical ICT assets"},
            {"control_id":"ICT-6.1","description":"Inadequate encryption for data-in-transit protection"},
            {"control_id":"TLPT-1.2","description":"Cryptographic weakness in threat-led testing scope"},
        ],
        "NIS2": [
            {"control_id":"ART-21-2e","description":"Use of cryptographic controls -- inadequate algorithm strength"},
            {"control_id":"ART-21-2h","description":"Supply chain security -- cryptographic dependencies"},
        ],
        "NSM-10": [
            {"control_id":"NSM10-4.1","description":"Quantum-vulnerable algorithm -- immediate migration required"},
            {"control_id":"NSM10-4.2","description":"CBOM inventory -- asset not migrated to PQC"},
            {"control_id":"NSM10-M1.3","description":"High-value asset protection -- cryptographic risk"},
        ],
    },
    "partially_safe": {
        "DORA":   [{"control_id":"ICT-2.1","description":"Algorithm with reduced post-quantum security margin"}],
        "NIS2":   [{"control_id":"ART-21-2e","description":"Cryptographic controls -- recommend upgrade to quantum-safe"}],
        "NSM-10": [{"control_id":"NSM10-4.2","description":"Algorithm requires planned migration -- monitor timeline"}],
    },
}

LEGACY_CRITICAL = {"MD5","SHA1","SHA-1","RC4","DES","3DES","RC2"}

LEGACY_CONTROLS = {
    "DORA":   [{"control_id":"ICT-6.2","description":"Deprecated/broken algorithm -- immediate remediation required"}],
    "NIS2":   [{"control_id":"ART-21-2e","description":"Prohibited cryptographic algorithm in use"}],
    "NSM-10": [{"control_id":"NSM10-4.1","description":"Broken algorithm -- retire immediately"}],
}


def get_compliance_gaps(quantum_class: str, sector: str, algorithm: str) -> list[dict[str, Any]]:
    gaps = []
    normalized = algorithm.upper().replace("-","").replace("_","")
    is_legacy = any(c.upper().replace("-","").replace("_","") == normalized for c in LEGACY_CRITICAL)
    if is_legacy:
        for framework, controls in LEGACY_CONTROLS.items():
            for ctrl in controls:
                gaps.append({"framework": framework, **ctrl, "priority": "immediate"})
        return gaps
    for framework, controls in COMPLIANCE_CONTROLS.get(quantum_class, {}).items():
        for ctrl in controls:
            gaps.append({"framework": framework, **ctrl, "priority": "planned"})
    return gaps
```
