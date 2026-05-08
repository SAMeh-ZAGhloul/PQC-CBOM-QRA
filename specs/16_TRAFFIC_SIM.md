# 16 -- Traffic Generation & Simulation Module

> Read `00_MASTER_SPEC.md` and all prior specs first.

---

## Overview

Dual-purpose module served from a single container on port 8080:

1. **Demo mode** -- generates crypto-rich traffic against bundled sample
   apps so Zeek discovers assets in a demo/PoC environment.
2. **Benchmark mode** -- standalone tool clients can deploy against their
   own infrastructure to measure scanner coverage and QARS accuracy.

Technology: **Python + Locust v2** with a lightweight FastAPI control API.

---

## Directory Structure

```
traffic-sim/
├── Dockerfile
├── pyproject.toml
├── main.py                  # FastAPI control API (:8080)
├── locustfile.py            # Locust scenario entry point
├── scenarios/
│   ├── __init__.py
│   ├── web_tls.py           # HTTPS scenario (RSA-2048, AES-256-GCM)
│   ├── ssh_keyx.py          # SSH key exchange scenario
│   ├── db_tls.py            # PostgreSQL TLS + SCRAM-SHA-256
│   ├── weak_crypto.py       # Legacy cipher scenario (TLS 1.0, RC4, DES)
│   ├── cert_chain.py        # Multi-level cert chain scenario
│   ├── mixed_load.py        # All scenarios in parallel
│   └── pqc_demo.py          # Hybrid classical+ML-KEM (requires OQS-OpenSSL)
├── benchmark/
│   ├── __init__.py
│   ├── coverage_report.py   # Detection coverage: planted vs found assets
│   ├── accuracy_report.py   # QARS accuracy: expected vs actual scores
│   └── throughput_report.py # Scan speed: files/sec, assets/sec
└── sample-apps/
    ├── web-app/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   └── app.py           # Flask + PyOpenSSL, RSA-2048 cert, port 8443
    ├── ssh-service/
    │   ├── Dockerfile
    │   └── sshd_config      # OpenSSH: RSA/ECDSA/ED25519 host keys, port 2222
    └── db-service/
        ├── Dockerfile
        ├── postgresql.conf  # TLS enabled, min version TLS 1.2
        ├── pg_hba.conf      # SCRAM-SHA-256, SSL required
        └── init.sql         # crypto_inventory sample table
```

---

## main.py -- FastAPI Control API

```python
"""Traffic simulation control API.
Provides REST endpoints to start/stop/status Locust scenarios.
Also serves the Locust web UI by proxying to the Locust master process.
"""
from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

logger = structlog.get_logger()
app = FastAPI(title="CBOM Traffic Simulator", version="1.0.0")

# Running scenario state
_active_process: subprocess.Popen | None = None
_active_scenario: str | None = None
_start_time: datetime | None = None
_output_lines: list[str] = []
MAX_OUTPUT_LINES = 500

WEB_TARGET  = os.environ.get("TRAFFIC_WEB_TARGET", "https://sample-web:8443")
SSH_HOST    = os.environ.get("TRAFFIC_SSH_HOST", "sample-ssh")
SSH_PORT    = int(os.environ.get("TRAFFIC_SSH_PORT", "2222"))
DB_HOST     = os.environ.get("TRAFFIC_DB_HOST", "sample-db")
DB_PORT     = int(os.environ.get("TRAFFIC_DB_PORT", "5432"))

SCENARIO_COMMANDS: dict[str, list[str]] = {
    "web-tls":    ["python3", "-m", "scenarios.web_tls"],
    "ssh-keyx":   ["python3", "-m", "scenarios.ssh_keyx"],
    "db-tls":     ["python3", "-m", "scenarios.db_tls"],
    "weak-crypto":["python3", "-m", "scenarios.weak_crypto"],
    "cert-chain": ["python3", "-m", "scenarios.cert_chain"],
    "mixed-load": ["python3", "-m", "scenarios.mixed_load"],
    "pqc-demo":   ["python3", "-m", "scenarios.pqc_demo"],
    "all": ["python3", "-m", "scenarios.mixed_load", "--all"],
    "loop": ["python3", "-m", "scenarios.mixed_load", "--loop"],
}


class ScenarioStartRequest(BaseModel):
    users: int = 1
    spawn_rate: float = 1.0
    duration_seconds: int = 60
    target_override: str | None = None


class ScenarioStatus(BaseModel):
    active: bool
    scenario: str | None
    started_at: str | None
    duration_seconds: int | None
    output_lines: list[str]


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "active_scenario": _active_scenario}


@app.get("/api/scenarios")
async def list_scenarios() -> dict:
    return {
        "scenarios": [
            {"id": "web-tls",    "description": "HTTPS traffic (RSA-2048, AES-256-GCM)", "protocols": ["TLS 1.2/1.3"]},
            {"id": "ssh-keyx",   "description": "SSH connections (ED25519/ECDSA/RSA key exchange)", "protocols": ["SSH"]},
            {"id": "db-tls",     "description": "PostgreSQL TLS with SCRAM-SHA-256 auth", "protocols": ["TLS", "PostgreSQL"]},
            {"id": "weak-crypto","description": "Legacy cipher suites (RC4, DES, TLS 1.0)", "protocols": ["TLS 1.0"]},
            {"id": "cert-chain", "description": "Multi-level X.509 cert chain (root+intermediate+leaf)", "protocols": ["X.509"]},
            {"id": "mixed-load", "description": "All scenarios in parallel", "protocols": ["All"]},
            {"id": "pqc-demo",   "description": "Hybrid ML-KEM+ECDH key exchange", "protocols": ["TLS 1.3+PQC"]},
            {"id": "all",        "description": "Run all scenarios once sequentially", "protocols": ["All"]},
            {"id": "loop",       "description": "Loop all scenarios continuously", "protocols": ["All"]},
        ]
    }


@app.post("/api/scenarios/{scenario}/start")
async def start_scenario(scenario: str, body: ScenarioStartRequest) -> dict:
    global _active_process, _active_scenario, _start_time, _output_lines

    if scenario not in SCENARIO_COMMANDS:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {scenario}")

    if _active_process and _active_process.poll() is None:
        raise HTTPException(status_code=409, detail=f"Scenario '{_active_scenario}' already running. Stop it first.")

    _output_lines = []
    cmd = SCENARIO_COMMANDS[scenario] + [
        f"--users={body.users}",
        f"--spawn-rate={body.spawn_rate}",
        f"--duration={body.duration_seconds}",
        f"--web-target={body.target_override or WEB_TARGET}",
        f"--ssh-host={SSH_HOST}",
        f"--ssh-port={SSH_PORT}",
        f"--db-host={DB_HOST}",
        f"--db-port={DB_PORT}",
    ]

    _active_process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    _active_scenario = scenario
    _start_time = datetime.now(UTC)

    # Stream output in background
    asyncio.create_task(_collect_output(_active_process))

    logger.info("scenario_started", scenario=scenario, users=body.users)
    return {"job_id": str(uuid.uuid4()), "scenario": scenario, "status": "running"}


@app.post("/api/scenarios/stop")
async def stop_scenario() -> dict:
    global _active_process, _active_scenario

    if not _active_process or _active_process.poll() is not None:
        return {"status": "no_active_scenario"}

    _active_process.send_signal(signal.SIGINT)
    try:
        _active_process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _active_process.kill()

    stopped = _active_scenario
    _active_scenario = None
    logger.info("scenario_stopped", scenario=stopped)
    return {"status": "stopped", "scenario": stopped}


@app.get("/api/scenarios/status", response_model=ScenarioStatus)
async def get_status() -> ScenarioStatus:
    active = bool(_active_process and _active_process.poll() is None)
    duration = None
    if _start_time and active:
        duration = int((datetime.now(UTC) - _start_time).total_seconds())

    return ScenarioStatus(
        active=active,
        scenario=_active_scenario if active else None,
        started_at=_start_time.isoformat() if _start_time and active else None,
        duration_seconds=duration,
        output_lines=_output_lines[-100:],  # Last 100 lines
    )


@app.get("/api/scenarios/output/stream")
async def stream_output():
    """Server-sent events stream of scenario output."""
    async def generate():
        last_idx = 0
        while True:
            if last_idx < len(_output_lines):
                for line in _output_lines[last_idx:]:
                    yield f"data: {line}\n\n"
                last_idx = len(_output_lines)
            await asyncio.sleep(0.5)
            if not _active_process or _active_process.poll() is not None:
                yield "data: [SCENARIO_COMPLETE]\n\n"
                break

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/benchmark/run")
async def run_benchmark(
    target_api_url: str,
    scan_id: str,
    api_token: str,
) -> dict:
    """Run full benchmark suite against a live CBOM API instance."""
    from benchmark.coverage_report import run_coverage_benchmark
    from benchmark.accuracy_report import run_accuracy_benchmark
    from benchmark.throughput_report import run_throughput_benchmark

    results = {}
    results["coverage"] = await run_coverage_benchmark(target_api_url, scan_id, api_token)
    results["accuracy"] = await run_accuracy_benchmark(target_api_url, scan_id, api_token)
    results["throughput"] = await run_throughput_benchmark(target_api_url, scan_id, api_token)
    return results


async def _collect_output(process: subprocess.Popen) -> None:
    """Collect process output into the global output buffer."""
    global _output_lines
    if not process.stdout:
        return
    for line in process.stdout:
        line = line.rstrip()
        _output_lines.append(line)
        if len(_output_lines) > MAX_OUTPUT_LINES:
            _output_lines = _output_lines[-MAX_OUTPUT_LINES:]
```

---

## scenarios/web_tls.py

```python
"""HTTPS TLS traffic scenario -- exercises RSA-2048 certs and AES-256-GCM."""
from __future__ import annotations

import argparse
import ssl
import time
import urllib.request


def run(web_target: str, users: int, duration: int, **kwargs) -> None:
    print(f"[web-tls] Starting {users} user(s) for {duration}s against {web_target}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    endpoints = ["/", "/api/data", "/api/health"]
    start = time.time()
    request_count = 0

    while time.time() - start < duration:
        for endpoint in endpoints:
            try:
                url = f"{web_target}{endpoint}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    _ = resp.read()
                    request_count += 1
                    print(f"[web-tls] GET {endpoint} -> {resp.status}")
            except Exception as e:
                print(f"[web-tls] ERROR {endpoint}: {e}")
        time.sleep(0.5)

    print(f"[web-tls] Complete. Total requests: {request_count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--web-target", default="https://localhost:8443")
    parser.add_argument("--users", type=int, default=1)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--spawn-rate", type=float, default=1.0)
    parser.add_argument("--ssh-host", default="localhost")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--db-host", default="localhost")
    parser.add_argument("--db-port", type=int, default=5432)
    args = parser.parse_args()
    run(args.web_target, args.users, args.duration)
```

---

## scenarios/ssh_keyx.py

```python
"""SSH key exchange scenario -- exercises ED25519/ECDSA/RSA host keys."""
from __future__ import annotations

import argparse
import subprocess
import time


def run(ssh_host: str, ssh_port: int, duration: int, **kwargs) -> None:
    print(f"[ssh-keyx] Starting SSH connections to {ssh_host}:{ssh_port} for {duration}s")
    start = time.time()
    conn_count = 0

    # Commands to run over SSH to exercise crypto
    commands = ["uname -a", "ls -la /etc/ssh/", "cat /etc/os-release"]

    while time.time() - start < duration:
        for cmd in commands:
            try:
                result = subprocess.run(
                    [
                        "ssh",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "LogLevel=ERROR",
                        "-o", "ConnectTimeout=10",
                        "-o", "BatchMode=yes",
                        "-p", str(ssh_port),
                        f"cbomuser@{ssh_host}",
                        cmd,
                    ],
                    capture_output=True, text=True, timeout=15,
                )
                conn_count += 1
                print(f"[ssh-keyx] SSH '{cmd}' -> returncode={result.returncode}")
            except subprocess.TimeoutExpired:
                print(f"[ssh-keyx] TIMEOUT: {cmd}")
            except Exception as e:
                print(f"[ssh-keyx] ERROR: {e}")
        time.sleep(1.0)

    print(f"[ssh-keyx] Complete. Total connections: {conn_count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh-host", default="localhost")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--users", type=int, default=1)
    parser.add_argument("--spawn-rate", type=float, default=1.0)
    parser.add_argument("--web-target", default="")
    parser.add_argument("--db-host", default="localhost")
    parser.add_argument("--db-port", type=int, default=5432)
    args = parser.parse_args()
    run(args.ssh_host, args.ssh_port, args.duration)
```

---

## scenarios/db_tls.py

```python
"""PostgreSQL TLS scenario -- exercises TLS connection and SCRAM-SHA-256 auth."""
from __future__ import annotations

import argparse
import time

import psycopg2


def run(db_host: str, db_port: int, duration: int, **kwargs) -> None:
    print(f"[db-tls] Starting DB connections to {db_host}:{db_port} for {duration}s")
    conn_str = (
        f"host={db_host} port={db_port} dbname=crypto_inventory "
        f"user=postgres password=cbom_demo_pass sslmode=require"
    )
    start = time.time()
    query_count = 0
    queries = [
        "SELECT * FROM crypto_inventory LIMIT 5;",
        "SELECT COUNT(*) FROM crypto_inventory;",
        "SELECT * FROM certificates LIMIT 5;",
        "INSERT INTO crypto_inventory (asset_name, algorithm, key_length, protocol, risk_level) "
        "VALUES ('TrafficGenTest', 'AES-256-GCM', 256, 'TLS 1.3', 'low');",
    ]

    while time.time() - start < duration:
        try:
            conn = psycopg2.connect(conn_str, connect_timeout=10)
            cur = conn.cursor()
            for q in queries:
                try:
                    cur.execute(q)
                    conn.commit()
                    query_count += 1
                    print(f"[db-tls] Query OK: {q[:60]}...")
                except Exception as qe:
                    conn.rollback()
                    print(f"[db-tls] Query error: {qe}")
            conn.close()
        except Exception as e:
            print(f"[db-tls] Connection error: {e}")
        time.sleep(1.0)

    print(f"[db-tls] Complete. Total queries: {query_count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-host", default="localhost")
    parser.add_argument("--db-port", type=int, default=5432)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--users", type=int, default=1)
    parser.add_argument("--spawn-rate", type=float, default=1.0)
    parser.add_argument("--web-target", default="")
    parser.add_argument("--ssh-host", default="localhost")
    parser.add_argument("--ssh-port", type=int, default=2222)
    args = parser.parse_args()
    run(args.db_host, args.db_port, args.duration)
```

---

## scenarios/mixed_load.py

```python
"""Mixed load scenario -- runs all scenarios in parallel threads."""
from __future__ import annotations

import argparse
import threading
from . import web_tls, ssh_keyx, db_tls, weak_crypto


def run(web_target: str, ssh_host: str, ssh_port: int,
        db_host: str, db_port: int, duration: int, **kwargs) -> None:
    print(f"[mixed-load] Starting all scenarios in parallel for {duration}s")
    threads = [
        threading.Thread(target=web_tls.run,   kwargs=dict(web_target=web_target, users=1, duration=duration)),
        threading.Thread(target=ssh_keyx.run,   kwargs=dict(ssh_host=ssh_host, ssh_port=ssh_port, duration=duration)),
        threading.Thread(target=db_tls.run,     kwargs=dict(db_host=db_host, db_port=db_port, duration=duration)),
        threading.Thread(target=weak_crypto.run, kwargs=dict(web_target=web_target, duration=duration)),
    ]
    for t in threads:
        t.daemon = True
        t.start()
    for t in threads:
        t.join(timeout=duration + 30)
    print("[mixed-load] All scenarios complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--web-target", default="https://localhost:8443")
    parser.add_argument("--ssh-host", default="localhost")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--db-host", default="localhost")
    parser.add_argument("--db-port", type=int, default=5432)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--users", type=int, default=1)
    parser.add_argument("--spawn-rate", type=float, default=1.0)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--loop", action="store_true")
    args = parser.parse_args()

    if args.loop:
        import time
        while True:
            run(args.web_target, args.ssh_host, args.ssh_port,
                args.db_host, args.db_port, args.duration)
            print("[mixed-load] Loop: sleeping 10s...")
            time.sleep(10)
    else:
        run(args.web_target, args.ssh_host, args.ssh_port,
            args.db_host, args.db_port, args.duration)
```

---

## benchmark/coverage_report.py

```python
"""Coverage benchmark: compare planted crypto assets vs discovered assets."""
from __future__ import annotations

import json
from typing import Any
import httpx

# Known planted assets in the sample apps
PLANTED_ASSETS = [
    {"algorithm": "RSA",    "location": "sample-web",   "key_size": 2048, "source": "cert_scanner"},
    {"algorithm": "AES-256","location": "sample-web",   "key_size": 256,  "source": "zeek_network"},
    {"algorithm": "ECDH",   "location": "sample-web",   "key_size": 256,  "source": "zeek_network"},
    {"algorithm": "ED25519","location": "sample-ssh",   "key_size": 256,  "source": "zeek_network"},
    {"algorithm": "RSA",    "location": "sample-ssh",   "key_size": 2048, "source": "zeek_network"},
    {"algorithm": "ECDSA",  "location": "sample-ssh",   "key_size": 256,  "source": "zeek_network"},
    {"algorithm": "TLS",    "location": "sample-db",    "key_size": None, "source": "zeek_network"},
    {"algorithm": "SHA-256","location": "sample-db",    "key_size": 256,  "source": "zeek_network"},
]


async def run_coverage_benchmark(api_url: str, scan_id: str, token: str) -> dict[str, Any]:
    """Compare planted assets against discovered assets for a scan."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{api_url}/api/assets",
            params={"scan_id": scan_id, "limit": 1000},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        discovered = resp.json().get("items", [])

    discovered_algos = {a["algorithm"].upper() for a in discovered}
    planted_algos    = {a["algorithm"].upper() for a in PLANTED_ASSETS}

    found     = discovered_algos & planted_algos
    missed    = planted_algos - discovered_algos
    extra     = discovered_algos - planted_algos

    coverage_pct = (len(found) / len(PLANTED_ASSETS)) * 100 if PLANTED_ASSETS else 0.0

    return {
        "planted_count":   len(PLANTED_ASSETS),
        "discovered_count": len(discovered),
        "matched_count":   len(found),
        "missed_count":    len(missed),
        "extra_count":     len(extra),
        "coverage_pct":    round(coverage_pct, 1),
        "missed_assets":   list(missed),
        "grade":           "A" if coverage_pct >= 90 else "B" if coverage_pct >= 75 else "C",
    }
```

---

## sample-apps/web-app/app.py

```python
"""Sample HTTPS web app with RSA-2048 self-signed certificate."""
from flask import Flask, jsonify
import ssl, os

app = Flask(__name__)

@app.route("/")
def index():
    return "<h1>CBOM Sample Web App</h1><p>TLS: RSA-2048, AES-256-GCM, ECDHE</p>"

@app.route("/api/data")
def api_data():
    return jsonify({"status": "ok", "algorithm": "AES-256-GCM", "key_exchange": "ECDHE-RSA"})

@app.route("/api/health")
def health():
    return jsonify({"healthy": True})

if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certs/server.crt", "/certs/server.key")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    app.run(host="0.0.0.0", port=8443, ssl_context=context)
```

---

## sample-apps/db-service/init.sql

```sql
-- Sample crypto inventory tables for traffic-sim demo
CREATE TABLE IF NOT EXISTS crypto_inventory (
    id          SERIAL PRIMARY KEY,
    asset_name  VARCHAR(200) NOT NULL,
    algorithm   VARCHAR(100) NOT NULL,
    key_length  INTEGER,
    protocol    VARCHAR(50),
    risk_level  VARCHAR(20),
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS certificates (
    id          SERIAL PRIMARY KEY,
    subject     TEXT,
    issuer      TEXT,
    algorithm   VARCHAR(100),
    key_length  INTEGER,
    valid_until TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Seed with known-weak assets for scanner validation
INSERT INTO crypto_inventory (asset_name, algorithm, key_length, protocol, risk_level) VALUES
    ('legacy-api', 'RSA-2048',   2048, 'TLS 1.2',  'high'),
    ('user-auth',  'ECDSA-256',   256, 'TLS 1.3',  'high'),
    ('file-enc',   'AES-256-GCM', 256, 'at-rest',  'low'),
    ('old-hash',   'MD5',         128, 'internal', 'critical'),
    ('jwt-sign',   'RS256',      2048, 'HTTPS',    'high');
```

---

## Dockerfile

```dockerfile
FROM python:3.12-slim

RUN groupadd -r cbom && useradd -r -g cbom cbom

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl openssh-client postgresql-client git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY . .

USER cbom
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
```

---

## pyproject.toml

```toml
[project]
name = "cbom-traffic-sim"
version = "1.0.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi==0.111.*",
    "uvicorn[standard]==0.29.*",
    "locust==2.*",
    "httpx==0.27.*",
    "psycopg2-binary==2.9.*",
    "flask==3.*",
    "structlog==24.*",
    "pydantic==2.*",
]
```
