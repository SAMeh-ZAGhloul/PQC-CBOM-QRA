# 07 -- CBOM Generator

> Read `00_MASTER_SPEC.md`, `03_DATABASE_SCHEMA.md`, `04_RABBITMQ.md` first.

---

## Directory Structure

```
cbom-generator/
├── Dockerfile
├── pyproject.toml
└── src/
    └── cbom_generator/
        ├── __init__.py
        ├── main.py            # Entry point: consume cbom.ingest queue
        ├── config.py
        ├── generator.py       # CycloneDX 1.6 CBOM assembler
        ├── deduplicator.py    # UUID5-based asset deduplication
        ├── classifier.py      # Quantum vulnerability DB
        ├── publisher.py       # Write to PostgreSQL + MinIO
        └── findings.py        # Auto-generate findings from assets
```

---

## classifier.py

```python
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class QuantumClass(str, Enum):
    VULNERABLE     = "vulnerable"
    PARTIALLY_SAFE = "partially_safe"
    SAFE           = "safe"
    PQC            = "pqc"
    UNKNOWN        = "unknown"


@dataclass(frozen=True)
class AlgorithmInfo:
    normalized: str
    quantum_class: QuantumClass
    crypto_type: str
    pqc_replacement: str | None
    nist_fips: str | None
    reason: str


ALGORITHM_DB: dict[str, AlgorithmInfo] = {
    # VULNERABLE: broken by Shor's algorithm
    "RSA":       AlgorithmInfo("RSA",     QuantumClass.VULNERABLE,    "asymmetric_encryption", "ML-KEM-768", "FIPS 203", "Shor's algorithm factors RSA modulus in polynomial time"),
    "RSAPSS":    AlgorithmInfo("RSA",     QuantumClass.VULNERABLE,    "digital_signature",     "ML-DSA-65",  "FIPS 204", "RSA-PSS signature broken by Shor's"),
    "DSA":       AlgorithmInfo("DSA",     QuantumClass.VULNERABLE,    "digital_signature",     "ML-DSA-44",  "FIPS 204", "Discrete log solved by Shor's"),
    "ECDSA":     AlgorithmInfo("ECDSA",   QuantumClass.VULNERABLE,    "digital_signature",     "ML-DSA-65",  "FIPS 204", "Elliptic curve discrete log solved by Shor's"),
    "ECDH":      AlgorithmInfo("ECDH",    QuantumClass.VULNERABLE,    "key_exchange",          "ML-KEM-768", "FIPS 203", "EC Diffie-Hellman broken by Shor's"),
    "ECDHE":     AlgorithmInfo("ECDH",    QuantumClass.VULNERABLE,    "key_exchange",          "ML-KEM-768", "FIPS 203", "Ephemeral ECDH broken by Shor's"),
    "DH":        AlgorithmInfo("DH",      QuantumClass.VULNERABLE,    "key_exchange",          "ML-KEM-768", "FIPS 203", "Diffie-Hellman discrete log solved by Shor's"),
    "DHE":       AlgorithmInfo("DH",      QuantumClass.VULNERABLE,    "key_exchange",          "ML-KEM-768", "FIPS 203", "Ephemeral DH broken by Shor's"),
    "ED25519":   AlgorithmInfo("ED25519", QuantumClass.VULNERABLE,    "digital_signature",     "ML-DSA-44",  "FIPS 204", "Edwards curve vulnerable to Shor's"),
    "ED448":     AlgorithmInfo("ED448",   QuantumClass.VULNERABLE,    "digital_signature",     "ML-DSA-65",  "FIPS 204", "Edwards curve 448 vulnerable to Shor's"),
    "X25519":    AlgorithmInfo("X25519",  QuantumClass.VULNERABLE,    "key_exchange",          "ML-KEM-512", "FIPS 203", "Curve25519 key exchange broken by Shor's"),
    "X448":      AlgorithmInfo("X448",    QuantumClass.VULNERABLE,    "key_exchange",          "ML-KEM-768", "FIPS 203", "Curve448 key exchange broken by Shor's"),
    "ELGAMAL":   AlgorithmInfo("ElGamal",QuantumClass.VULNERABLE,    "asymmetric_encryption", "ML-KEM-768", "FIPS 203", "Discrete log broken by Shor's"),

    # PARTIALLY SAFE: Grover's algorithm halves effective security level
    "AES128":    AlgorithmInfo("AES-128", QuantumClass.PARTIALLY_SAFE,"symmetric_encryption",  "AES-256",    None,       "Grover's reduces 128-bit to 64-bit effective security"),
    "AES-128":   AlgorithmInfo("AES-128", QuantumClass.PARTIALLY_SAFE,"symmetric_encryption",  "AES-256",    None,       "Grover's reduces 128-bit to 64-bit effective security"),
    "3DES":      AlgorithmInfo("3DES",    QuantumClass.PARTIALLY_SAFE,"symmetric_encryption",  "AES-256",    None,       "168-bit key; Grover's reduces to 84-bit; deprecated by NIST 2023"),
    "TRIPLEDES": AlgorithmInfo("3DES",    QuantumClass.PARTIALLY_SAFE,"symmetric_encryption",  "AES-256",    None,       "Triple DES deprecated by NIST 2023"),
    "DES":       AlgorithmInfo("DES",     QuantumClass.PARTIALLY_SAFE,"symmetric_encryption",  "AES-256",    None,       "56-bit key; classically broken; retire immediately"),
    "RC4":       AlgorithmInfo("RC4",     QuantumClass.PARTIALLY_SAFE,"symmetric_encryption",  "AES-256-GCM",None,       "Broken classically; prohibited in TLS 1.3"),
    "RC2":       AlgorithmInfo("RC2",     QuantumClass.PARTIALLY_SAFE,"symmetric_encryption",  "AES-256",    None,       "Deprecated; retire immediately"),
    "BLOWFISH":  AlgorithmInfo("Blowfish",QuantumClass.PARTIALLY_SAFE,"symmetric_encryption",  "AES-256",    None,       "64-bit block size; retire"),
    "SHA1":      AlgorithmInfo("SHA-1",   QuantumClass.PARTIALLY_SAFE,"hash",                  "SHA3-256",   None,       "Deprecated; collision attacks demonstrated"),
    "SHA-1":     AlgorithmInfo("SHA-1",   QuantumClass.PARTIALLY_SAFE,"hash",                  "SHA3-256",   None,       "Deprecated by NIST; Grover's further weakens"),
    "SHA224":    AlgorithmInfo("SHA-224", QuantumClass.PARTIALLY_SAFE,"hash",                  "SHA3-256",   None,       "112-bit post-quantum security; upgrade recommended"),
    "SHA-224":   AlgorithmInfo("SHA-224", QuantumClass.PARTIALLY_SAFE,"hash",                  "SHA3-256",   None,       "112-bit post-quantum security"),
    "SHA256":    AlgorithmInfo("SHA-256", QuantumClass.PARTIALLY_SAFE,"hash",                  "SHA3-256",   None,       "128-bit post-quantum security; borderline acceptable"),
    "SHA-256":   AlgorithmInfo("SHA-256", QuantumClass.PARTIALLY_SAFE,"hash",                  "SHA3-256",   None,       "128-bit post-quantum security; borderline"),
    "MD5":       AlgorithmInfo("MD5",     QuantumClass.PARTIALLY_SAFE,"hash",                  "SHA3-256",   None,       "Classically broken; retire immediately"),
    "MD4":       AlgorithmInfo("MD4",     QuantumClass.PARTIALLY_SAFE,"hash",                  "SHA3-256",   None,       "Severely broken; retire immediately"),
    "HMACSHA1":  AlgorithmInfo("HMAC-SHA1",QuantumClass.PARTIALLY_SAFE,"mac",                  "HMAC-SHA3-256",None,    "SHA-1 weaknesses apply"),
    "HMACMD5":   AlgorithmInfo("HMAC-MD5",QuantumClass.PARTIALLY_SAFE,"mac",                   "HMAC-SHA3-256",None,    "MD5 broken; retire immediately"),
    "HMACSHA256":AlgorithmInfo("HMAC-SHA256",QuantumClass.PARTIALLY_SAFE,"mac",                "HMAC-SHA3-256",None,    "128-bit post-quantum security"),
    "PBKDF2":    AlgorithmInfo("PBKDF2",  QuantumClass.PARTIALLY_SAFE,"kdf",                   "Argon2id",   None,       "Depends on underlying hash strength"),

    # SAFE: quantum-resistant classical algorithms
    "AES256":    AlgorithmInfo("AES-256", QuantumClass.SAFE,"symmetric_encryption", None, None, "256-bit key; 128-bit post-quantum security"),
    "AES-256":   AlgorithmInfo("AES-256", QuantumClass.SAFE,"symmetric_encryption", None, None, "256-bit key; quantum-safe"),
    "AES256GCM": AlgorithmInfo("AES-256", QuantumClass.SAFE,"symmetric_encryption", None, None, "AES-256-GCM; quantum-safe AEAD"),
    "AES-256-GCM":AlgorithmInfo("AES-256",QuantumClass.SAFE,"symmetric_encryption", None, None, "AES-256-GCM; quantum-safe"),
    "CHACHA20":  AlgorithmInfo("ChaCha20",QuantumClass.SAFE,"symmetric_encryption", None, None, "256-bit key; quantum-safe"),
    "CHACHA20POLY1305":AlgorithmInfo("ChaCha20-Poly1305",QuantumClass.SAFE,"symmetric_encryption",None,None,"Quantum-safe AEAD"),
    "SHA384":    AlgorithmInfo("SHA-384", QuantumClass.SAFE,"hash", None, None, "192-bit post-quantum security"),
    "SHA-384":   AlgorithmInfo("SHA-384", QuantumClass.SAFE,"hash", None, None, "192-bit post-quantum security"),
    "SHA512":    AlgorithmInfo("SHA-512", QuantumClass.SAFE,"hash", None, None, "256-bit post-quantum security"),
    "SHA-512":   AlgorithmInfo("SHA-512", QuantumClass.SAFE,"hash", None, None, "256-bit post-quantum security"),
    "SHA3256":   AlgorithmInfo("SHA3-256",QuantumClass.SAFE,"hash", None, None, "NIST SHA-3; 128-bit post-quantum security"),
    "SHA3-256":  AlgorithmInfo("SHA3-256",QuantumClass.SAFE,"hash", None, None, "NIST SHA-3 family; quantum-safe"),
    "SHA3512":   AlgorithmInfo("SHA3-512",QuantumClass.SAFE,"hash", None, None, "NIST SHA-3; 256-bit post-quantum security"),
    "SHA3-512":  AlgorithmInfo("SHA3-512",QuantumClass.SAFE,"hash", None, None, "NIST SHA-3; quantum-safe"),
    "BLAKE2B":   AlgorithmInfo("BLAKE2b", QuantumClass.SAFE,"hash", None, None, "256-bit post-quantum security"),
    "BLAKE3":    AlgorithmInfo("BLAKE3",  QuantumClass.SAFE,"hash", None, None, "256-bit post-quantum security"),
    "ARGON2ID":  AlgorithmInfo("Argon2id",QuantumClass.SAFE,"kdf",  None, None, "Memory-hard KDF; quantum-safe"),
    "BCRYPT":    AlgorithmInfo("bcrypt",  QuantumClass.SAFE,"kdf",  None, None, "Work-factor KDF; acceptable for passwords"),
    "SCRYPT":    AlgorithmInfo("scrypt",  QuantumClass.SAFE,"kdf",  None, None, "Memory-hard KDF; quantum-safe"),
    "HMACSHA384":AlgorithmInfo("HMAC-SHA384",QuantumClass.SAFE,"mac",None, None,"192-bit post-quantum security"),
    "HMACSHA512":AlgorithmInfo("HMAC-SHA512",QuantumClass.SAFE,"mac",None, None,"256-bit post-quantum security"),

    # PQC: NIST FIPS 203/204/205 standardized
    "MLKEM":     AlgorithmInfo("ML-KEM",     QuantumClass.PQC,"pqc_kem",       None,"FIPS 203","Module-Lattice KEM; NIST standardized"),
    "ML-KEM":    AlgorithmInfo("ML-KEM",     QuantumClass.PQC,"pqc_kem",       None,"FIPS 203","ML-KEM; NIST standardized"),
    "MLKEM512":  AlgorithmInfo("ML-KEM-512", QuantumClass.PQC,"pqc_kem",       None,"FIPS 203","ML-KEM security level 1"),
    "ML-KEM-512":AlgorithmInfo("ML-KEM-512", QuantumClass.PQC,"pqc_kem",       None,"FIPS 203","ML-KEM security level 1"),
    "MLKEM768":  AlgorithmInfo("ML-KEM-768", QuantumClass.PQC,"pqc_kem",       None,"FIPS 203","ML-KEM security level 3 (recommended)"),
    "ML-KEM-768":AlgorithmInfo("ML-KEM-768", QuantumClass.PQC,"pqc_kem",       None,"FIPS 203","ML-KEM security level 3 (recommended)"),
    "KYBER":     AlgorithmInfo("ML-KEM",     QuantumClass.PQC,"pqc_kem",       None,"FIPS 203","Kyber: pre-standard name for ML-KEM"),
    "KYBER768":  AlgorithmInfo("ML-KEM-768", QuantumClass.PQC,"pqc_kem",       None,"FIPS 203","Kyber-768 -> ML-KEM-768"),
    "MLDSA":     AlgorithmInfo("ML-DSA",     QuantumClass.PQC,"pqc_signature", None,"FIPS 204","Module-Lattice DSA; NIST standardized"),
    "ML-DSA":    AlgorithmInfo("ML-DSA",     QuantumClass.PQC,"pqc_signature", None,"FIPS 204","ML-DSA; NIST standardized"),
    "MLDSA44":   AlgorithmInfo("ML-DSA-44",  QuantumClass.PQC,"pqc_signature", None,"FIPS 204","ML-DSA security level 2"),
    "ML-DSA-44": AlgorithmInfo("ML-DSA-44",  QuantumClass.PQC,"pqc_signature", None,"FIPS 204","ML-DSA security level 2"),
    "MLDSA65":   AlgorithmInfo("ML-DSA-65",  QuantumClass.PQC,"pqc_signature", None,"FIPS 204","ML-DSA security level 3 (recommended)"),
    "ML-DSA-65": AlgorithmInfo("ML-DSA-65",  QuantumClass.PQC,"pqc_signature", None,"FIPS 204","ML-DSA security level 3 (recommended)"),
    "DILITHIUM": AlgorithmInfo("ML-DSA",     QuantumClass.PQC,"pqc_signature", None,"FIPS 204","Dilithium: pre-standard name for ML-DSA"),
    "SLHDSA":    AlgorithmInfo("SLH-DSA",    QuantumClass.PQC,"pqc_signature", None,"FIPS 205","Stateless Hash-Based DSA; NIST standardized"),
    "SLH-DSA":   AlgorithmInfo("SLH-DSA",    QuantumClass.PQC,"pqc_signature", None,"FIPS 205","SLH-DSA; NIST standardized"),
    "SPHINCS":   AlgorithmInfo("SLH-DSA",    QuantumClass.PQC,"pqc_signature", None,"FIPS 205","SPHINCS+: pre-standard name for SLH-DSA"),
    "FALCON":    AlgorithmInfo("FALCON",     QuantumClass.PQC,"pqc_signature", None,None,       "FALCON lattice-based signature"),
}


def normalize_algorithm(name: str) -> str:
    return name.upper().replace("-", "").replace("_", "").replace(" ", "")


def classify(algorithm: str) -> AlgorithmInfo:
    normalized = normalize_algorithm(algorithm)
    if normalized in ALGORITHM_DB:
        return ALGORITHM_DB[normalized]
    for key, info in ALGORITHM_DB.items():
        if normalized.startswith(key) or key.startswith(normalized[:6]):
            return info
    return AlgorithmInfo(algorithm, QuantumClass.UNKNOWN, "unknown", None, None,
                         "Algorithm not found in classification DB")
```

---

## deduplicator.py

```python
from __future__ import annotations
import re
import uuid

NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace


def compute_dedup_hash(algorithm: str, location: str, key_size: int | None) -> str:
    normalized_algo = algorithm.upper().replace("-", "").replace("_", "")
    normalized_loc = _normalize_location(location)
    key_str = str(key_size) if key_size else "none"
    fingerprint = f"{normalized_algo}|{normalized_loc}|{key_str}"
    return str(uuid.uuid5(NAMESPACE, fingerprint))


def _normalize_location(location: str) -> str:
    location = re.sub(r"^/tmp/scan-[^/]+/", "/", location)
    location = location.replace("\\", "/")
    return location.lower().strip()
```

---

## generator.py

```python
from __future__ import annotations
import uuid
from datetime import UTC, datetime
from typing import Any
from .classifier import classify, QuantumClass

TOOL_NAME = "CBOM Discovery Platform"
TOOL_VERSION = "1.0.0-mvp"


def build_cyclonedx_component(asset: dict[str, Any]) -> dict[str, Any]:
    info = classify(asset["algorithm"])
    return {
        "type": "cryptographic-asset",
        "bom-ref": asset.get("dedup_hash", str(uuid.uuid4())),
        "name": info.normalized,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": _map_primitive(info.crypto_type),
                "parameterSetIdentifier": str(asset["key_size"]) if asset.get("key_size") else None,
                "curve": _extract_curve(asset["algorithm"]),
                "executionEnvironment": "software-plain-ram",
                "cryptoFunctions": _map_crypto_functions(info.crypto_type),
                "nistQuantumSecurityLevel": _nist_level(info.quantum_class),
            },
        },
        "evidence": {"occurrences": [{"location": asset["location"], "line": asset.get("line_number")}]},
        "properties": [
            {"name": "cbom:quantumClass",    "value": info.quantum_class.value},
            {"name": "cbom:pqcReplacement",  "value": info.pqc_replacement or "none"},
            {"name": "cbom:nistFips",         "value": info.nist_fips or "none"},
            {"name": "cbom:reason",           "value": info.reason},
            {"name": "cbom:discoverySource",  "value": asset.get("source", "unknown")},
            {"name": "cbom:confidence",       "value": asset.get("confidence", "medium")},
        ],
    }


def build_cbom(scan_id: str, assets: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "CBOM Platform", "name": TOOL_NAME, "version": TOOL_VERSION}],
            "properties": [{"name": "cbom:scanId", "value": scan_id}],
        },
        "components": [build_cyclonedx_component(a) for a in assets],
        "vulnerabilities": [],
    }


def _map_primitive(crypto_type: str) -> str:
    return {"asymmetric_encryption":"pke","digital_signature":"signature",
            "key_exchange":"key-agree","symmetric_encryption":"cipher",
            "hash":"hash","mac":"mac","kdf":"kdf",
            "pqc_kem":"pke","pqc_signature":"signature"}.get(crypto_type, "other")


def _map_crypto_functions(crypto_type: str) -> list[str]:
    return {"asymmetric_encryption":["encapsulate","decapsulate"],
            "digital_signature":["sign","verify"],
            "key_exchange":["generate","agree"],
            "symmetric_encryption":["encrypt","decrypt"],
            "hash":["digest"],"mac":["generate","verify"],
            "kdf":["derive"],"pqc_kem":["encapsulate","decapsulate"],
            "pqc_signature":["sign","verify"]}.get(crypto_type, ["other"])


def _extract_curve(algorithm: str) -> str | None:
    curve_map = {"P256":"P-256","SECP256R1":"P-256","P384":"P-384",
                 "SECP384R1":"P-384","P521":"P-521","SECP521R1":"P-521",
                 "X25519":"Curve25519","ED25519":"Curve25519","X448":"Curve448"}
    upper = algorithm.upper().replace("-","").replace("_","")
    for k, v in curve_map.items():
        if k in upper:
            return v
    return None


def _nist_level(quantum_class: QuantumClass) -> int:
    return {QuantumClass.PQC: 3, QuantumClass.SAFE: 3,
            QuantumClass.PARTIALLY_SAFE: 1, QuantumClass.VULNERABLE: 0,
            QuantumClass.UNKNOWN: 0}.get(quantum_class, 0)
```

---

## findings.py

```python
from __future__ import annotations
from typing import Any
from .classifier import QuantumClass, classify

CRITICAL_ALGORITHMS = {"MD5","SHA1","SHA-1","RC4","DES","3DES","DES3","RC2"}

SEVERITY_MAP = {
    "vulnerable":     "high",
    "partially_safe": "medium",
    "safe":           "low",
    "pqc":            "info",
    "unknown":        "medium",
}

COMPLIANCE_MAP = {
    "vulnerable": {
        "DORA":   [{"control_id":"ICT-2.1","description":"Quantum-vulnerable algorithm in critical ICT system"},
                   {"control_id":"ICT-6.1","description":"Inadequate encryption for data-in-transit"}],
        "NIS2":   [{"control_id":"ART-21-2e","description":"Inadequate cryptographic controls"}],
        "NSM-10": [{"control_id":"NSM10-4.1","description":"Non-compliant algorithm requiring PQC migration"}],
    },
    "partially_safe": {
        "DORA":   [{"control_id":"ICT-2.1","description":"Algorithm with reduced post-quantum security"}],
        "NIS2":   [{"control_id":"ART-21-2e","description":"Cryptographic control requires upgrade"}],
        "NSM-10": [{"control_id":"NSM10-4.2","description":"Algorithm requiring planned migration"}],
    },
}


def generate_findings(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for a in assets if (f := _asset_to_finding(a)) is not None]


def _asset_to_finding(asset: dict[str, Any]) -> dict[str, Any] | None:
    quantum_class = asset.get("quantum_class", "unknown")
    algorithm = asset.get("algorithm", "UNKNOWN")
    info = classify(algorithm)

    if quantum_class in ("safe", "pqc"):
        return None

    normalized = info.normalized.upper().replace("-","").replace("_","")
    is_critical = any(c.upper().replace("-","").replace("_","") == normalized for c in CRITICAL_ALGORITHMS)

    if is_critical:
        severity, ftype = "critical", "deprecated_algorithm"
    elif quantum_class == "vulnerable":
        severity, ftype = "high", "quantum_vulnerable_algorithm"
    else:
        severity, ftype = "medium", "algorithm_risk"

    compliance_gaps = []
    for framework, controls in COMPLIANCE_MAP.get(quantum_class, {}).items():
        for ctrl in controls:
            compliance_gaps.append({"framework": framework, **ctrl})

    return {
        "severity": severity,
        "finding_type": ftype,
        "title": f"{algorithm} detected -- {quantum_class.replace('_',' ').title()}",
        "description": f"Algorithm '{algorithm}' found at '{asset['location']}'. {info.reason}",
        "recommendation": (f"Replace with {info.pqc_replacement} ({info.nist_fips})"
                           if info.pqc_replacement else "Review usage and plan migration."),
        "asset_id": asset.get("id"),
        "framework": "DORA,NIS2,NSM-10",
        "compliance_gaps": compliance_gaps,
    }
```

---

## main.py

```python
from __future__ import annotations
import asyncio
import json
from collections import defaultdict
from typing import Any
import aio_pika
import structlog
from .classifier import classify
from .config import get_settings
from .deduplicator import compute_dedup_hash
from .findings import generate_findings
from .generator import build_cbom
from .publisher import save_asset_to_db, save_cbom_to_minio, save_finding_to_db, notify_scan_complete

logger = structlog.get_logger()
settings = get_settings()

ASSET_BUFFER: dict[str, list[dict]] = defaultdict(list)
FLUSH_INTERVAL = 30
FLUSH_BATCH_SIZE = 100


async def process_asset_event(message: aio_pika.IncomingMessage) -> None:
    async with message.process(requeue=True):
        try:
            event = json.loads(message.body)
            scan_id = event["scan_id"]
            info = classify(event["algorithm"])
            dedup_hash = compute_dedup_hash(event["algorithm"], event["location"], event.get("key_size"))
            enriched = {
                **event,
                "dedup_hash": dedup_hash,
                "algorithm_normalized": info.normalized,
                "quantum_class": info.quantum_class.value,
                "crypto_type": info.crypto_type,
                "pqc_replacement": info.pqc_replacement,
            }
            ASSET_BUFFER[scan_id].append(enriched)
            if len(ASSET_BUFFER[scan_id]) >= FLUSH_BATCH_SIZE:
                await flush_scan_buffer(scan_id)
        except Exception as e:
            logger.error("asset_processing_failed", error=str(e))


async def flush_scan_buffer(scan_id: str) -> None:
    assets = ASSET_BUFFER.pop(scan_id, [])
    if not assets:
        return
    logger.info("flushing_asset_buffer", scan_id=scan_id, count=len(assets))
    for asset in assets:
        await save_asset_to_db(asset)
    findings = generate_findings(assets)
    for finding in findings:
        await save_finding_to_db({**finding, "scan_id": scan_id})


async def periodic_flush() -> None:
    while True:
        await asyncio.sleep(FLUSH_INTERVAL)
        for scan_id in list(ASSET_BUFFER.keys()):
            await flush_scan_buffer(scan_id)


async def main() -> None:
    connection = await aio_pika.connect_robust(settings.rabbitmq_url)
    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=50)
        queue = await channel.get_queue("cbom.ingest")
        asyncio.create_task(periodic_flush())
        logger.info("cbom_generator_started")
        async with queue.iterator() as q:
            async for message in q:
                await process_asset_event(message)


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Dockerfile

```dockerfile
FROM python:3.12-slim
RUN groupadd -r cbom && useradd -r -g cbom cbom
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl libpq-dev gcc && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .
COPY src/ ./src/
USER cbom
CMD ["python", "-m", "cbom_generator.main"]
```

---

## pyproject.toml

```toml
[project]
name = "cbom-generator"
version = "1.0.0"
requires-python = ">=3.12"
dependencies = [
    "aio-pika==9.*", "sqlalchemy[asyncio]==2.*", "asyncpg==0.29.*",
    "boto3==1.34.*", "cyclonedx-python-lib==7.*",
    "structlog==24.*", "pydantic-settings==2.*",
]
```
