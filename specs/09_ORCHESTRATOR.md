# 09 -- Discovery Orchestrator

> Read `00_MASTER_SPEC.md`, `04_RABBITMQ.md`, `06_SCANNER_WORKERS.md` first.

---

## Directory Structure

```
orchestrator/
├── Dockerfile
├── pyproject.toml
└── src/
    └── cbom_orchestrator/
        ├── __init__.py
        ├── main.py             # Entry point: consume orchestrator.requests
        ├── config.py
        ├── decomposer.py       # Scan -> individual job messages
        ├── log_watcher.py      # Zeek log file monitor (watchdog)
        ├── zeek_parser.py      # Parse Zeek JSON logs -> CryptoAssetFound
        ├── state.py            # Scan state machine in Redis + PostgreSQL
        └── repo_crawler.py     # Git repo -> file list for AST scanner
```

---

## decomposer.py

```python
from __future__ import annotations
import uuid
from pathlib import Path
from typing import Any
import aio_pika
import structlog
from .repo_crawler import crawl_repo
from .state import update_scan_status

logger = structlog.get_logger()

AST_EXTS = {".py",".java",".go",".js",".ts",".jsx",".tsx",".c",".cpp",
            ".cc",".h",".hpp",".cs",".rb",".php",".yaml",".yml",
            ".toml",".json",".tf",".hcl"}
BINARY_EXTS = {".so",".dll",".exe",".elf",".class",".pyc",".jar",".war",".ear",".ko"}
CERT_EXTS = {".pem",".crt",".cer",".der",".p12",".pfx",".jks",".key"}


async def decompose_scan(
    scan_id: str,
    config: dict[str, Any],
    channel: aio_pika.abc.AbstractChannel,
) -> int:
    log = logger.bind(scan_id=scan_id)
    total_jobs = 0
    trace_id = str(uuid.uuid4())
    await update_scan_status(scan_id, "running")

    # 1. Repos / source code
    for repo_url in config.get("target_repos", []):
        file_list = await crawl_repo(repo_url)
        for file_path in file_list:
            ext = Path(file_path).suffix.lower()
            queue = _route_by_extension(ext)
            await _publish_job(channel, queue, scan_id, file_path,
                               config.get("max_file_depth", 5), trace_id)
            total_jobs += 1

    # 2. TLS/host certificate probing
    for host in config.get("target_hosts", []):
        if ":" not in host:
            host = f"{host}:443"
        await _publish_job(channel, "scanner.cert", scan_id, host, 0, trace_id)
        total_jobs += 1

    # 3. Database scanner
    for db_conn in config.get("target_db_connections", []):
        await _publish_job(channel, "scanner.db", scan_id, db_conn, 0, trace_id)
        total_jobs += 1

    log.info("scan_decomposed", total_jobs=total_jobs)
    return total_jobs


def _route_by_extension(ext: str) -> str:
    if ext in AST_EXTS:    return "scanner.ast"
    if ext in BINARY_EXTS: return "scanner.binary"
    if ext in CERT_EXTS:   return "scanner.cert"
    return "scanner.ast"   # Default: let Magika decide


async def _publish_job(channel, queue, scan_id, target, max_depth, trace_id) -> None:
    import json
    exchange = await channel.get_exchange("cbom.direct")
    payload = {
        "message_type": "ScanJob", "job_id": str(uuid.uuid4()),
        "scan_id": scan_id, "target": target,
        "max_depth": max_depth, "trace_id": trace_id,
    }
    await exchange.publish(
        aio_pika.Message(
            body=json.dumps(payload).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
        ),
        routing_key=queue,
    )
```

---

## zeek_parser.py

```python
from __future__ import annotations
import json
from typing import Any

CIPHER_SUITE_MAP = {
    "TLS_AES_256_GCM_SHA384":            ("AES-256", "symmetric_encryption", 256),
    "TLS_CHACHA20_POLY1305_SHA256":      ("ChaCha20", "symmetric_encryption", 256),
    "TLS_AES_128_GCM_SHA256":            ("AES-128", "symmetric_encryption", 128),
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": ("RSA", "asymmetric_encryption", None),
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": ("ECDSA","digital_signature", None),
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": ("DH", "key_exchange", None),
    "TLS_RSA_WITH_AES_256_CBC_SHA256":   ("RSA", "asymmetric_encryption", None),
    "TLS_RSA_WITH_RC4_128_SHA":          ("RC4", "symmetric_encryption", 128),
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA":     ("3DES", "symmetric_encryption", 168),
}

SSH_KEXALG_MAP = {
    "curve25519-sha256":                  ("X25519", "key_exchange", 256),
    "ecdh-sha2-nistp256":                 ("ECDH", "key_exchange", 256),
    "ecdh-sha2-nistp384":                 ("ECDH", "key_exchange", 384),
    "diffie-hellman-group14-sha256":      ("DH", "key_exchange", 2048),
    "diffie-hellman-group1-sha1":         ("DH", "key_exchange", 1024),
}

SSH_HOSTKEY_MAP = {
    "ssh-rsa":              ("RSA", "digital_signature", 2048),
    "rsa-sha2-256":         ("RSA", "digital_signature", 2048),
    "rsa-sha2-512":         ("RSA", "digital_signature", 4096),
    "ecdsa-sha2-nistp256":  ("ECDSA", "digital_signature", 256),
    "ecdsa-sha2-nistp384":  ("ECDSA", "digital_signature", 384),
    "ssh-ed25519":          ("ED25519", "digital_signature", 256),
}


def _read_jsonl(file_path: str) -> list[dict]:
    records = []
    try:
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return records


def parse_ssl_log(file_path: str) -> list[dict[str, Any]]:
    assets = []
    for r in _read_jsonl(file_path):
        cipher = r.get("cipher")
        location = f"{r.get('server_name') or r.get('id.resp_h','')}:{r.get('id.resp_p',443)}"
        version = r.get("version","")
        if cipher:
            algo, ctype, keysize = CIPHER_SUITE_MAP.get(cipher, ("TLS","key_exchange",None))
            assets.append({"algorithm":algo,"key_size":keysize,"crypto_type":ctype,
                           "location":location,"source":"zeek_network","confidence":"high",
                           "usage_context":f"TLS {version} cipher suite","raw_evidence":cipher})
    return assets


def parse_x509_log(file_path: str) -> list[dict[str, Any]]:
    assets = []
    for r in _read_jsonl(file_path):
        key_alg = r.get("certificate.key_alg","") or r.get("certificate.key_type","")
        key_length = r.get("certificate.key_length")
        subject = r.get("certificate.subject","")
        if key_alg:
            assets.append({"algorithm":key_alg,
                           "key_size":int(key_length) if key_length else None,
                           "crypto_type":"asymmetric_encryption",
                           "location":f"cert:{subject[:100]}",
                           "source":"zeek_network","confidence":"high",
                           "usage_context":f"X.509 certificate",
                           "raw_evidence":f"{key_alg} {key_length}bit"})
    return assets


def parse_ssh_log(file_path: str) -> list[dict[str, Any]]:
    assets = []
    for r in _read_jsonl(file_path):
        location = f"{r.get('id.resp_h','')}:{r.get('id.resp_p',22)}"
        kex = r.get("kex_alg","")
        if kex in SSH_KEXALG_MAP:
            algo, ctype, keysize = SSH_KEXALG_MAP[kex]
            assets.append({"algorithm":algo,"key_size":keysize,"crypto_type":ctype,
                           "location":location,"source":"zeek_network","confidence":"high",
                           "usage_context":f"SSH key exchange: {kex}","raw_evidence":kex})
        hk = r.get("host_key_alg","")
        if hk in SSH_HOSTKEY_MAP:
            algo, ctype, keysize = SSH_HOSTKEY_MAP[hk]
            assets.append({"algorithm":algo,"key_size":keysize,"crypto_type":ctype,
                           "location":location,"source":"zeek_network","confidence":"high",
                           "usage_context":f"SSH host key: {hk}","raw_evidence":hk})
    return assets
```

---

## log_watcher.py

```python
from __future__ import annotations
import asyncio
from pathlib import Path
import aio_pika, structlog
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from .zeek_parser import parse_ssl_log, parse_x509_log, parse_ssh_log

logger = structlog.get_logger()


class ZeekLogHandler(FileSystemEventHandler):
    def __init__(self, queue: asyncio.Queue) -> None:
        self._queue = queue

    def on_modified(self, event):
        if not event.is_directory:
            self._queue.put_nowait(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._queue.put_nowait(event.src_path)


async def watch_zeek_logs(
    log_dir: str,
    channel: aio_pika.abc.AbstractChannel,
    scan_id: str,
) -> None:
    event_queue: asyncio.Queue = asyncio.Queue()
    observer = Observer()
    observer.schedule(ZeekLogHandler(event_queue), log_dir, recursive=False)
    observer.start()
    logger.info("zeek_log_watcher_started", log_dir=log_dir, scan_id=scan_id)
    try:
        while True:
            try:
                file_path = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                await _process_log_file(file_path, channel, scan_id)
            except asyncio.TimeoutError:
                pass
    finally:
        observer.stop()
        observer.join()


LOG_PARSERS = {"ssl": parse_ssl_log, "x509": parse_x509_log, "ssh": parse_ssh_log}


async def _process_log_file(file_path, channel, scan_id) -> None:
    import json
    filename = Path(file_path).name
    for log_name, parser in LOG_PARSERS.items():
        if log_name in filename:
            assets = parser(file_path)
            exchange = await channel.get_exchange("cbom.direct")
            for asset in assets:
                payload = {**asset, "scan_id": scan_id, "message_type": "CryptoAssetFound"}
                await exchange.publish(
                    aio_pika.Message(body=json.dumps(payload).encode(),
                                     delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
                    routing_key="cbom.ingest",
                )
            logger.info("zeek_log_processed", file=filename, assets=len(assets))
            return
```

---

## repo_crawler.py

```python
from __future__ import annotations
import subprocess
import tempfile
from pathlib import Path
import structlog

logger = structlog.get_logger()

SCAN_EXTENSIONS = {
    ".py",".java",".go",".js",".ts",".jsx",".tsx",".c",".cpp",".cc",
    ".h",".hpp",".cs",".rb",".php",".yaml",".yml",".toml",".json",
    ".tf",".hcl",".pem",".crt",".cer",".der",".p12",".pfx",".jks",
    ".so",".dll",".exe",".class",".pyc",".jar",".war",
}

SKIP_DIRS = {".git","node_modules",".venv","__pycache__","dist","build",".next"}
MAX_FILE_SIZE_MB = 50


async def crawl_repo(repo_url: str) -> list[str]:
    if Path(repo_url).exists():
        return _crawl_local(repo_url)
    return await _clone_and_crawl(repo_url)


def _crawl_local(directory: str) -> list[str]:
    result = []
    for path in Path(directory).rglob("*"):
        if path.is_file() and path.suffix.lower() in SCAN_EXTENSIONS:
            if not SKIP_DIRS.intersection(path.parts):
                if path.stat().st_size <= MAX_FILE_SIZE_MB * 1024 * 1024:
                    result.append(str(path))
    logger.info("local_crawl_complete", directory=directory, files=len(result))
    return result


async def _clone_and_crawl(git_url: str) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="cbom-scan-") as tmpdir:
        try:
            subprocess.run(
                ["git","clone","--depth=1","--single-branch", git_url, tmpdir],
                check=True, capture_output=True, timeout=300,
            )
            return _crawl_local(tmpdir)
        except subprocess.CalledProcessError as e:
            logger.error("git_clone_failed", url=git_url, error=e.stderr.decode())
            return []
```

---

## state.py

```python
from __future__ import annotations
import json
from typing import Any
import structlog

logger = structlog.get_logger()

VALID_TRANSITIONS = {
    "queued":    {"running"},
    "running":   {"partial","complete","failed","cancelled"},
    "partial":   {"complete","failed"},
    "complete":  set(),
    "failed":    set(),
    "cancelled": set(),
}


async def update_scan_status(scan_id: str, status: str,
                              redis_client=None, db_session=None) -> None:
    if redis_client:
        await redis_client.setex(f"scan:{scan_id}:status", 86400, status)
    if db_session:
        from sqlalchemy import text
        await db_session.execute(
            text("UPDATE scans SET status=:s, updated_at=NOW() WHERE id=:id"),
            {"s": status, "id": scan_id},
        )
        await db_session.commit()
    logger.info("scan_status_updated", scan_id=scan_id, status=status)


async def update_scan_progress(scan_id: str, redis_client,
                                assets_found: int = 0, files_scanned: int = 0) -> None:
    await redis_client.setex(
        f"scan:{scan_id}:progress", 86400,
        json.dumps({"assets_found": assets_found, "files_scanned": files_scanned}),
    )
```
