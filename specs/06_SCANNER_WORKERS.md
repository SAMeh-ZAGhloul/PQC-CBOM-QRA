# 06 — Scanner Workers

> Read `00_MASTER_SPEC.md`, `04_RABBITMQ.md` first.

---

## Directory Structure

```
scanners/
├── Dockerfile
├── pyproject.toml
└── src/
    └── cbom_scanners/
        ├── __init__.py
        ├── config.py
        ├── celery_app.py          # Celery app factory (see spec 04)
        ├── tasks.py               # All Celery task definitions
        ├── ast_scanner.py         # AST-based crypto detection
        ├── binary_scanner.py      # ELF/PE/Mach-O symbol analysis
        ├── cert_scanner.py        # Certificate + TLS probe
        ├── db_scanner.py          # Database encryption discovery
        ├── patterns/
        │   ├── __init__.py
        │   ├── python_patterns.py
        │   ├── java_patterns.py
        │   ├── go_patterns.py
        │   ├── javascript_patterns.py
        │   └── c_patterns.py
        └── utils/
            ├── magika_client.py   # HTTP client for Magika service
            ├── ollama_client.py   # HTTP client for llama.cpp SLM
            ├── publisher.py       # Publish CryptoAssetFound events
            └── archive.py        # ZIP/JAR/TAR unpacking
```

---

## tasks.py

```python
"""Celery task definitions for all scanner worker types."""
from __future__ import annotations

import uuid
from typing import Any

import structlog

from .celery_app import app
from .ast_scanner import scan_file_ast
from .binary_scanner import scan_file_binary
from .cert_scanner import scan_cert_or_host
from .db_scanner import scan_database
from .utils.magika_client import classify_file
from .utils.ollama_client import analyze_with_slm  # llama.cpp SLM fallback
from .utils.publisher import publish_asset_found
from .utils.archive import unpack_and_dispatch

logger = structlog.get_logger()


@app.task(
    name="cbom_scanners.tasks.scan_ast",
    queue="scanner.ast",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    acks_late=True,
)
def scan_ast(self: Any, job: dict) -> None:
    """AST scan a single file or directory."""
    scan_id = job["scan_id"]
    target = job["target"]
    trace_id = job.get("trace_id", str(uuid.uuid4()))
    log = logger.bind(scan_id=scan_id, target=target, trace_id=trace_id)

    try:
        # 1. Classify with Magika
        classification = classify_file(target)
        content_type = classification["content_type"]
        confidence = classification["confidence"]

        # 2. Handle archives/containers
        if content_type in ("zip", "jar", "war", "tar", "gz", "docker"):
            unpack_and_dispatch(target, job, max_depth=job.get("max_depth", 5))
            return

        # 3. AST scan if source code
        if content_type in ("python", "java", "go", "javascript", "typescript", "c", "cpp"):
            assets = scan_file_ast(target, content_type)
            for asset in assets:
                publish_asset_found({**asset, "scan_id": scan_id, "source": "ast_scanner", "trace_id": trace_id})
            log.info("ast_scan_complete", assets_found=len(assets))
            return

        # 4. IaC files (yaml, toml, json → check for crypto patterns)
        if content_type in ("yaml", "toml", "json"):
            assets = scan_file_ast(target, content_type)
            for asset in assets:
                publish_asset_found({**asset, "scan_id": scan_id, "source": "ast_scanner", "trace_id": trace_id})
            return

        # 5. SLM fallback for unknown/low-confidence files
        if confidence < 0.6 or content_type == "unknown":
            log.info("routing_to_slm", confidence=confidence, content_type=content_type)
            assets = analyze_with_slm(target)
            for asset in assets:
                publish_asset_found({**asset, "scan_id": scan_id, "source": "slm_fallback", "trace_id": trace_id})

    except Exception as exc:
        log.error("ast_scan_failed", error=str(exc))
        raise self.retry(exc=exc)


@app.task(
    name="cbom_scanners.tasks.scan_binary",
    queue="scanner.binary",
    bind=True,
    max_retries=3,
    acks_late=True,
)
def scan_binary(self: Any, job: dict) -> None:
    """Binary/bytecode symbol table scanning."""
    scan_id = job["scan_id"]
    target = job["target"]
    trace_id = job.get("trace_id", str(uuid.uuid4()))
    log = logger.bind(scan_id=scan_id, target=target, trace_id=trace_id)

    try:
        classification = classify_file(target)
        content_type = classification["content_type"]

        if content_type not in ("elf", "pe", "macho", "jvm_class", "pyc"):
            log.info("skipping_non_binary", content_type=content_type)
            return

        assets = scan_file_binary(target, content_type)
        for asset in assets:
            publish_asset_found({**asset, "scan_id": scan_id, "source": "binary_scanner", "trace_id": trace_id})
        log.info("binary_scan_complete", assets_found=len(assets))

    except Exception as exc:
        log.error("binary_scan_failed", error=str(exc))
        raise self.retry(exc=exc)


@app.task(
    name="cbom_scanners.tasks.scan_cert",
    queue="scanner.cert",
    bind=True,
    max_retries=3,
    acks_late=True,
)
def scan_cert(self: Any, job: dict) -> None:
    """Certificate file parsing or live TLS endpoint probing."""
    scan_id = job["scan_id"]
    target = job["target"]   # file path OR "host:port"
    trace_id = job.get("trace_id", str(uuid.uuid4()))
    log = logger.bind(scan_id=scan_id, target=target, trace_id=trace_id)

    try:
        assets = scan_cert_or_host(target)
        for asset in assets:
            publish_asset_found({**asset, "scan_id": scan_id, "source": "cert_scanner", "trace_id": trace_id})
        log.info("cert_scan_complete", assets_found=len(assets))

    except Exception as exc:
        log.error("cert_scan_failed", error=str(exc))
        raise self.retry(exc=exc)


@app.task(
    name="cbom_scanners.tasks.scan_db",
    queue="scanner.db",
    bind=True,
    max_retries=2,
    acks_late=True,
)
def scan_db(self: Any, job: dict) -> None:
    """Database encryption discovery (TDE, field-level, connection TLS)."""
    scan_id = job["scan_id"]
    target = job["target"]   # connection string (encrypted)
    trace_id = job.get("trace_id", str(uuid.uuid4()))
    log = logger.bind(scan_id=scan_id, trace_id=trace_id)

    try:
        assets = scan_database(target)
        for asset in assets:
            publish_asset_found({**asset, "scan_id": scan_id, "source": "db_scanner", "trace_id": trace_id})
        log.info("db_scan_complete", assets_found=len(assets))

    except Exception as exc:
        log.error("db_scan_failed", error=str(exc))
        raise self.retry(exc=exc)
```

---

## ast_scanner.py

```python
"""AST-based cryptographic detection for multiple languages."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import tree_sitter_python as tspython
import tree_sitter_java as tsjava
import tree_sitter_go as tsgo
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser

from .patterns import (
    PYTHON_PATTERNS, JAVA_PATTERNS, GO_PATTERNS,
    JS_PATTERNS, C_PATTERNS, IAC_PATTERNS,
)

LANGUAGE_MAP = {
    "python":     Language(tspython.language()),
    "java":       Language(tsjava.language()),
    "go":         Language(tsgo.language()),
    "javascript": Language(tsjavascript.language()),
    "typescript": Language(tsjavascript.language()),
}


def scan_file_ast(file_path: str, content_type: str) -> list[dict[str, Any]]:
    """Scan a source file using AST parsing + regex fallback."""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return []

    content = path.read_bytes()
    text = content.decode("utf-8", errors="ignore")
    findings: list[dict[str, Any]] = []

    # IaC files: regex only (no AST)
    if content_type in ("yaml", "toml", "json"):
        return _scan_with_regex(text, IAC_PATTERNS, file_path)

    # AST-based scan
    lang = LANGUAGE_MAP.get(content_type)
    if lang:
        findings.extend(_scan_with_ast(content, text, lang, content_type, file_path))

    # Supplement with regex patterns for comments and string literals
    patterns = {
        "python": PYTHON_PATTERNS,
        "java": JAVA_PATTERNS,
        "go": GO_PATTERNS,
        "javascript": JS_PATTERNS,
        "typescript": JS_PATTERNS,
        "c": C_PATTERNS,
        "cpp": C_PATTERNS,
    }.get(content_type, [])

    findings.extend(_scan_with_regex(text, patterns, file_path))
    return _deduplicate_findings(findings)


def _scan_with_ast(content: bytes, text: str, lang: Language, content_type: str, file_path: str) -> list[dict]:
    parser = Parser(lang)
    tree = parser.parse(content)
    findings = []

    # Walk all string literals and function calls
    for node in _walk(tree.root_node):
        if node.type in ("string", "string_literal", "interpreted_string_literal"):
            value = node.text.decode("utf-8", errors="ignore").strip("'\"\"`")
            finding = _classify_string_value(value, file_path, node.start_point[0] + 1)
            if finding:
                findings.append(finding)

        elif node.type in ("call_expression", "method_invocation", "call"):
            call_text = text[node.start_byte:node.end_byte]
            for finding in _match_call_patterns(call_text, file_path, node.start_point[0] + 1, content_type):
                findings.append(finding)

    return findings


def _walk(node: Any):
    yield node
    for child in node.children:
        yield from _walk(child)


def _classify_string_value(value: str, file_path: str, line: int) -> dict | None:
    """Detect algorithm names embedded in string literals."""
    ALGORITHM_STRINGS = {
        "RS256": ("RSA", "digital_signature", 2048),
        "RS512": ("RSA", "digital_signature", 2048),
        "ES256": ("ECDSA", "digital_signature", 256),
        "HS256": ("HMAC-SHA256", "mac", 256),
        "AES-128": ("AES-128", "symmetric_encryption", 128),
        "AES-256": ("AES-256", "symmetric_encryption", 256),
        "AES-256-GCM": ("AES-256", "symmetric_encryption", 256),
        "AES-256-CBC": ("AES-256", "symmetric_encryption", 256),
        "AES-128-GCM": ("AES-128", "symmetric_encryption", 128),
        "RSA-2048": ("RSA", "asymmetric_encryption", 2048),
        "RSA-4096": ("RSA", "asymmetric_encryption", 4096),
        "ECDH": ("ECDH", "key_exchange", 256),
        "SHA-1": ("SHA-1", "hash", None),
        "SHA1": ("SHA-1", "hash", None),
        "SHA-256": ("SHA-256", "hash", 256),
        "SHA-512": ("SHA-512", "hash", 512),
        "MD5": ("MD5", "hash", None),
        "RC4": ("RC4", "symmetric_encryption", 128),
        "3DES": ("3DES", "symmetric_encryption", 168),
        "DES": ("DES", "symmetric_encryption", 56),
    }
    upper = value.upper()
    for key, (algo, ctype, keysize) in ALGORITHM_STRINGS.items():
        if key.upper() == upper or f"WITH{key.upper()}" in upper:
            return {
                "algorithm": algo,
                "key_size": keysize,
                "crypto_type": ctype,
                "location": file_path,
                "line_number": line,
                "confidence": "high",
                "raw_evidence": value,
            }
    return None


def _match_call_patterns(call_text: str, file_path: str, line: int, lang: str) -> list[dict]:
    # Delegated to per-language pattern files
    from .patterns import match_patterns
    return match_patterns(call_text, lang, file_path, line)


def _scan_with_regex(text: str, patterns: list[tuple], file_path: str) -> list[dict]:
    findings = []
    lines = text.splitlines()
    for pattern, algo, ctype, keysize in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            line_num = text[:match.start()].count("\n") + 1
            findings.append({
                "algorithm": algo,
                "key_size": keysize,
                "crypto_type": ctype,
                "location": file_path,
                "line_number": line_num,
                "confidence": "medium",
                "raw_evidence": match.group(0)[:200],
            })
    return findings


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    result = []
    for f in findings:
        key = (f["algorithm"], f["location"], f.get("line_number"))
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
```

---

## patterns/python_patterns.py

```python
"""Regex patterns for Python crypto API detection."""
# Format: (regex_pattern, algorithm_name, crypto_type, key_size_or_None)
PYTHON_PATTERNS = [
    # cryptography library
    (r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+(rsa|ec|dh|ed25519|x25519)', "RSA/ECC", "asymmetric_encryption", None),
    (r'algorithms\.(AES|TripleDES|Blowfish|CAST5|SEED|SM4)', r"\1", "symmetric_encryption", None),
    (r'hashes\.(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|BLAKE2)', r"\1", "hash", None),
    (r'padding\.(PKCS1v15|OAEP|PSS)', "RSA", "asymmetric_encryption", None),
    (r'ec\.SECP256R1|ec\.SECP384R1|ec\.SECP521R1', "ECDSA", "digital_signature", 256),
    (r'rsa\.generate_private_key.*key_size=([0-9]+)', "RSA", "asymmetric_encryption", None),
    # pycryptodome
    (r'from\s+Crypto\.Cipher\s+import\s+(AES|DES3|DES|ARC4|Blowfish)', r"\1", "symmetric_encryption", None),
    (r'from\s+Crypto\.PublicKey\s+import\s+(RSA|ECC|DSA)', r"\1", "asymmetric_encryption", None),
    (r'from\s+Crypto\.Hash\s+import\s+(MD5|SHA1|SHA256|SHA512)', r"\1", "hash", None),
    # PyJWT
    (r'jwt\.encode.*algorithm=["\'](RS256|RS512|HS256|HS512|ES256)["\'\]', r"\1", "digital_signature", None),
    # hashlib
    (r'hashlib\.(md5|sha1|sha224|sha256|sha512|sha3_256|sha3_512)\(', r"\1", "hash", None),
    # ssl module
    (r'ssl\.PROTOCOL_TLS|ssl\.TLSVersion\.TLS(?:v1|v1_1|v1_2|v1_3)', "TLS", "key_exchange", None),
    # paramiko
    (r'paramiko\.(RSAKey|ECDSAKey|Ed25519Key)\.generate', "RSA/ECDSA/ED25519", "digital_signature", None),
]
```

---

## patterns/java_patterns.py

```python
JAVA_PATTERNS = [
    (r'KeyPairGenerator\.getInstance\(["\'](RSA|EC|DSA|DH)["\'\]', r"\1", "asymmetric_encryption", None),
    (r'Cipher\.getInstance\(["\'](AES|DES|DESede|Blowfish|RSA)[^"\']*["\'\]', r"\1", "symmetric_encryption", None),
    (r'MessageDigest\.getInstance\(["\'](MD5|SHA-1|SHA-256|SHA-512)["\'\]', r"\1", "hash", None),
    (r'Signature\.getInstance\(["\'](SHA[0-9]+with(?:RSA|ECDSA|DSA))["\'\]', r"\1", "digital_signature", None),
    (r'SecretKeyFactory\.getInstance\(["\'](PBKDF2WithHmac|bcrypt)["\'\]', r"\1", "kdf", None),
    (r'KeyFactory\.getInstance\(["\'](RSA|EC|DSA)["\'\]', r"\1", "asymmetric_encryption", None),
    (r'javax\.net\.ssl\.SSLContext\.getInstance\(["\'](TLS|TLSv1|TLSv1\.2|TLSv1\.3)["\'\]', "TLS", "key_exchange", None),
    (r'new\s+RSAKeyGenParameterSpec\(([0-9]+)', "RSA", "asymmetric_encryption", None),
]
```

---

## patterns/go_patterns.py

```python
GO_PATTERNS = [
    (r'"crypto/rsa"', "RSA", "asymmetric_encryption", None),
    (r'"crypto/ecdsa"', "ECDSA", "digital_signature", None),
    (r'"crypto/elliptic"', "ECC", "key_exchange", None),
    (r'"crypto/md5"', "MD5", "hash", None),
    (r'"crypto/sha1"', "SHA-1", "hash", None),
    (r'"crypto/sha256"', "SHA-256", "hash", 256),
    (r'"crypto/sha512"', "SHA-512", "hash", 512),
    (r'"crypto/des"', "DES", "symmetric_encryption", 56),
    (r'"crypto/aes"', "AES", "symmetric_encryption", None),
    (r'"golang\.org/x/crypto/ed25519"', "ED25519", "digital_signature", 256),
    (r'"golang\.org/x/crypto/curve25519"', "X25519", "key_exchange", 256),
    (r'elliptic\.P256\(\)|elliptic\.P384\(\)|elliptic\.P521\(\)', "ECDSA", "digital_signature", 256),
    (r'rsa\.GenerateKey.*([0-9]{4})', "RSA", "asymmetric_encryption", None),
    (r'tls\.VersionTLS10|tls\.VersionTLS11|tls\.VersionTLS12', "TLS", "key_exchange", None),
]
```

---

## cert_scanner.py

```python
"""Certificate and TLS endpoint inspection."""
from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519


def scan_cert_or_host(target: str) -> list[dict[str, Any]]:
    """Scan a cert file (PEM/DER) or probe a live TLS endpoint (host:port)."""
    if ":" in target and not Path(target).exists():
        # Live endpoint probe
        host, port_str = target.rsplit(":", 1)
        return _probe_tls_endpoint(host, int(port_str))
    else:
        return _parse_cert_file(target)


def _parse_cert_file(file_path: str) -> list[dict[str, Any]]:
    path = Path(file_path)
    content = path.read_bytes()

    certs = []
    # Try PEM first, then DER
    try:
        cert = x509.load_pem_x509_certificate(content, default_backend())
        certs.append(cert)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(content, default_backend())
            certs.append(cert)
        except Exception:
            return []

    return [_extract_cert_info(cert, file_path) for cert in certs]


def _probe_tls_endpoint(host: str, port: int) -> list[dict[str, Any]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher_name, tls_proto, bits = ssock.cipher()
                der_cert = ssock.getpeercert(binary_form=True)

        assets = []
        # TLS cipher suite asset
        assets.append({
            "algorithm": cipher_name,
            "key_size": bits,
            "crypto_type": "key_exchange",
            "location": f"{host}:{port}",
            "line_number": None,
            "confidence": "high",
            "usage_context": f"TLS {tls_proto} cipher suite",
            "raw_evidence": f"{host}:{port} -> {cipher_name}",
        })

        # Parse certificate
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        assets.append(_extract_cert_info(cert, f"{host}:{port}"))
        return assets

    except Exception as e:
        return []


def _extract_cert_info(cert: x509.Certificate, location: str) -> dict[str, Any]:
    pub_key = cert.public_key()
    key_type = type(pub_key).__name__

    algo_map = {
        "RSAPublicKey": ("RSA", "asymmetric_encryption"),
        "EllipticCurvePublicKey": ("ECDSA", "digital_signature"),
        "DSAPublicKey": ("DSA", "digital_signature"),
        "Ed25519PublicKey": ("ED25519", "digital_signature"),
    }
    algorithm, crypto_type = algo_map.get(key_type, ("UNKNOWN", "unknown"))
    key_size = getattr(pub_key, "key_size", None)

    return {
        "algorithm": algorithm,
        "key_size": key_size,
        "crypto_type": crypto_type,
        "location": location,
        "line_number": None,
        "confidence": "high",
        "usage_context": "X.509 certificate",
        "raw_evidence": f"Subject: {cert.subject.rfc4514_string()} | Expires: {cert.not_valid_after_utc}",
    }
```

---

## db_scanner.py

```python
"""Database encryption discovery — TDE, field-level, TLS settings."""
from __future__ import annotations

from typing import Any
import psycopg2
import pymysql


def scan_database(connection_string: str) -> list[dict[str, Any]]:
    """Detect encryption settings for a given database connection."""
    if connection_string.startswith("postgresql"):
        return _scan_postgres(connection_string)
    elif connection_string.startswith("mysql"):
        return _scan_mysql(connection_string)
    else:
        return []


def _scan_postgres(conn_str: str) -> list[dict[str, Any]]:
    assets = []
    try:
        conn = psycopg2.connect(conn_str)
        cur = conn.cursor()

        # Check SSL/TLS
        cur.execute("SHOW ssl;")
        ssl_on = cur.fetchone()[0] == "on"
        if ssl_on:
            assets.append({
                "algorithm": "TLS",
                "crypto_type": "key_exchange",
                "location": conn_str.split("@")[-1],
                "confidence": "high",
                "usage_context": "PostgreSQL TLS connection",
                "raw_evidence": "ssl=on",
            })

        # Check pgcrypto usage (field-level encryption)
        cur.execute("""
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE column_default LIKE '%pgcrypto%'
               OR column_name ILIKE '%encrypt%'
               OR column_name ILIKE '%crypt%'
            LIMIT 50;
        """)
        for table, column in cur.fetchall():
            assets.append({
                "algorithm": "AES",  # pgcrypto default
                "crypto_type": "symmetric_encryption",
                "location": f"db.{table}.{column}",
                "confidence": "medium",
                "usage_context": "PostgreSQL field-level encryption (pgcrypto)",
                "raw_evidence": f"{table}.{column}",
            })

        # Check password hashing function usage
        cur.execute("""
            SELECT proname, prosrc
            FROM pg_proc
            WHERE prosrc ILIKE '%crypt%' OR prosrc ILIKE '%md5%' OR prosrc ILIKE '%sha%'
            LIMIT 20;
        """)
        for proc_name, proc_src in cur.fetchall():
            for algo in ["md5", "sha1", "sha256", "bcrypt", "scrypt"]:
                if algo.lower() in proc_src.lower():
                    assets.append({
                        "algorithm": algo.upper(),
                        "crypto_type": "hash",
                        "location": f"db.procedure.{proc_name}",
                        "confidence": "low",
                        "usage_context": "PostgreSQL stored procedure",
                        "raw_evidence": proc_name,
                    })

        conn.close()
    except Exception as e:
        pass
    return assets
```

---

## utils/magika_client.py

```python
"""HTTP client for the Magika file classification service."""
from __future__ import annotations

import httpx
import os

MAGIKA_URL = os.environ.get("MAGIKA_SERVICE_URL", "http://worker-magika:8002")
CONFIDENCE_THRESHOLD = float(os.environ.get("MAGIKA_CONFIDENCE_THRESHOLD", "0.6"))


def classify_file(file_path: str) -> dict:
    """Return {content_type, confidence, group}."""
    try:
        response = httpx.post(
            f"{MAGIKA_URL}/classify",
            json={"file_path": file_path},
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return {"content_type": "unknown", "confidence": 0.0, "group": "unknown"}
```

---

## utils/ollama_client.py

> **Note:** Despite the file name `ollama_client.py`, this module connects to the **llama.cpp** server at `llama-cpp:11434`. The name is kept for backward compatibility. The client uses llama.cpp's native `/completion` endpoint (not Ollama's `/api/generate`). Environment variables default to `LLM_*` prefixed names; `OLLAMA_*` fallbacks are supported for migration.

```python
"""HTTP client for the llama.cpp SLM fallback service."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

# Primary: LLM_* vars; fallback: OLLAMA_* vars for migration compatibility
LLM_HOST = os.environ.get("LLM_HOST", os.environ.get("OLLAMA_HOST", "llama-cpp"))
LLM_PORT = os.environ.get("LLM_PORT", os.environ.get("OLLAMA_PORT", "11434"))
LLM_MODEL = os.environ.get("LLM_MODEL", os.environ.get("OLLAMA_MODEL", "cbom-slm"))
LLM_BASE_URL = f"http://{LLM_HOST}:{LLM_PORT}"

CRYPTO_DETECTION_PROMPT = """You are a cryptographic security analyst. Analyze the code/config below for cryptographic operations.

Return JSON ONLY with this exact structure (no markdown, no explanation):
{
  "findings": [
    {
      "algorithm": "string (e.g. RSA, AES-256, SHA-1)",
      "quantum_vulnerable": true or false,
      "confidence": "high or medium or low",
      "reason": "one sentence max",
      "line_number": integer or null
    }
  ]
}

Code to analyze:
<code>
{content}
</code>"""


def analyze_with_slm(file_path: str) -> list[dict[str, Any]]:
    """Use llama.cpp SLM to analyze a file for crypto usage."""
    path = Path(file_path)
    if not path.exists():
        return []

    content = path.read_text(errors="ignore")[:2000]  # Token budget
    prompt = CRYPTO_DETECTION_PROMPT.format(content=content)

    try:
        response = httpx.post(
            f"{LLM_BASE_URL}/completion",
            json={
                "prompt": prompt,
                "temperature": 0.1,
                "n_predict": 500,
            },
            timeout=60.0,
        )
        response.raise_for_status()
        raw = response.json().get("content", "")
        data = json.loads(raw.strip())
        findings = data.get("findings", [])

        return [
            {
                "algorithm": f["algorithm"],
                "key_size": None,
                "crypto_type": "unknown",
                "location": file_path,
                "line_number": f.get("line_number"),
                "confidence": f.get("confidence", "low"),
                "raw_evidence": f.get("reason", ""),
            }
            for f in findings
            if f.get("confidence") in ("high", "medium")
        ]
    except Exception:
        return []
```

---

## magika-service/main.py (FastAPI microservice)

```python
"""Magika file type classification HTTP microservice."""
from pathlib import Path

from fastapi import FastAPI, HTTPException
from magika import Magika
from pydantic import BaseModel

app = FastAPI(title="Magika File Router", version="1.0.0")
_magika = Magika()

ROUTING_GROUPS = {
    "python":      "source_code",
    "java":        "source_code",
    "javascript":  "source_code",
    "typescript":  "source_code",
    "go":          "source_code",
    "c":           "source_code",
    "cpp":         "source_code",
    "rust":        "source_code",
    "yaml":        "iac",
    "toml":        "iac",
    "json":        "iac",
    "elf":         "binary",
    "pe":          "binary",
    "macho":       "binary",
    "jvm_class":   "binary",
    "pyc":         "binary",
    "pem":         "certificate",
    "x509_der":    "certificate",
    "pkcs12":      "certificate",
    "zip":         "archive",
    "jar":         "archive",
    "tar":         "archive",
    "gz":          "archive",
}


class ClassifyRequest(BaseModel):
    file_path: str


class ClassifyResponse(BaseModel):
    content_type: str
    confidence: float
    group: str


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/classify", response_model=ClassifyResponse)
async def classify(request: ClassifyRequest) -> ClassifyResponse:
    path = Path(request.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")

    result = _magika.identify_path(path)
    ct = result.output.ct_label
    score = float(result.output.score)
    group = ROUTING_GROUPS.get(ct, "unknown")

    return ClassifyResponse(content_type=ct, confidence=score, group=group)
```

---

## Dockerfile (scanners)

```dockerfile
FROM python:3.12-slim

RUN groupadd -r cbom && useradd -r -g cbom cbom

WORKDIR /app

# Install binary analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    file \
    curl \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY src/ ./src/

USER cbom

CMD ["celery", "-A", "cbom_scanners.tasks", "worker", "--loglevel=info"]
```
