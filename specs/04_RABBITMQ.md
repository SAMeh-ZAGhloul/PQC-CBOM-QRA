# 04 — RabbitMQ Message Broker

> Read `00_MASTER_SPEC.md` first.

---

## rabbitmq.conf

```ini
# rabbitmq/rabbitmq.conf
loopback_users.guest = false
default_vhost = /
default_user = cbom
default_permissions.configure = .*
default_permissions.read = .*
default_permissions.write = .*

# Memory
vm_memory_high_watermark.relative = 0.6
vm_memory_high_watermark_paging_ratio = 0.5

# Persistence
queue_master_locator = min-masters
durable_queues = true

# Delivery confirmation
consumer_timeout = 3600000

# Logging
log.console = true
log.console.level = info
```

---

## definitions.json (Pre-declared topology)

```json
{
  "vhosts": [{"name": "/"}],
  "exchanges": [
    {
      "name": "cbom.direct",
      "vhost": "/",
      "type": "direct",
      "durable": true,
      "auto_delete": false,
      "arguments": {}
    },
    {
      "name": "cbom.fanout",
      "vhost": "/",
      "type": "fanout",
      "durable": true,
      "auto_delete": false,
      "arguments": {}
    },
    {
      "name": "cbom.dlx",
      "vhost": "/",
      "type": "direct",
      "durable": true,
      "auto_delete": false,
      "arguments": {}
    }
  ],
  "queues": [
    {
      "name": "scanner.ast",
      "vhost": "/",
      "durable": true,
      "auto_delete": false,
      "arguments": {
        "x-dead-letter-exchange": "cbom.dlx",
        "x-dead-letter-routing-key": "cbom.dlq",
        "x-message-ttl": 3600000,
        "x-max-retries": 3
      }
    },
    {
      "name": "scanner.binary",
      "vhost": "/",
      "durable": true,
      "auto_delete": false,
      "arguments": {
        "x-dead-letter-exchange": "cbom.dlx",
        "x-dead-letter-routing-key": "cbom.dlq",
        "x-message-ttl": 3600000
      }
    },
    {
      "name": "scanner.cert",
      "vhost": "/",
      "durable": true,
      "auto_delete": false,
      "arguments": {
        "x-dead-letter-exchange": "cbom.dlx",
        "x-dead-letter-routing-key": "cbom.dlq",
        "x-message-ttl": 1800000
      }
    },
    {
      "name": "scanner.db",
      "vhost": "/",
      "durable": true,
      "auto_delete": false,
      "arguments": {
        "x-dead-letter-exchange": "cbom.dlx",
        "x-dead-letter-routing-key": "cbom.dlq",
        "x-message-ttl": 1800000
      }
    },
    {
      "name": "slm.fallback",
      "vhost": "/",
      "durable": true,
      "auto_delete": false,
      "arguments": {
        "x-dead-letter-exchange": "cbom.dlx",
        "x-dead-letter-routing-key": "cbom.dlq",
        "x-message-ttl": 60000,
        "x-max-length": 500
      }
    },
    {
      "name": "cbom.ingest",
      "vhost": "/",
      "durable": true,
      "auto_delete": false,
      "arguments": {
        "x-dead-letter-exchange": "cbom.dlx",
        "x-dead-letter-routing-key": "cbom.dlq"
      }
    },
    {
      "name": "cbom.notify",
      "vhost": "/",
      "durable": false,
      "auto_delete": false,
      "arguments": {"x-message-ttl": 30000}
    },
    {
      "name": "cbom.dlq",
      "vhost": "/",
      "durable": true,
      "auto_delete": false,
      "arguments": {}
    },
    {
      "name": "orchestrator.requests",
      "vhost": "/",
      "durable": true,
      "auto_delete": false,
      "arguments": {
        "x-dead-letter-exchange": "cbom.dlx",
        "x-dead-letter-routing-key": "cbom.dlq"
      }
    }
  ],
  "bindings": [
    {"source": "cbom.direct", "vhost": "/", "destination": "scanner.ast",           "destination_type": "queue", "routing_key": "scanner.ast",           "arguments": {}},
    {"source": "cbom.direct", "vhost": "/", "destination": "scanner.binary",        "destination_type": "queue", "routing_key": "scanner.binary",        "arguments": {}},
    {"source": "cbom.direct", "vhost": "/", "destination": "scanner.cert",          "destination_type": "queue", "routing_key": "scanner.cert",          "arguments": {}},
    {"source": "cbom.direct", "vhost": "/", "destination": "scanner.db",            "destination_type": "queue", "routing_key": "scanner.db",            "arguments": {}},
    {"source": "cbom.direct", "vhost": "/", "destination": "slm.fallback",          "destination_type": "queue", "routing_key": "slm.fallback",          "arguments": {}},
    {"source": "cbom.direct", "vhost": "/", "destination": "cbom.ingest",           "destination_type": "queue", "routing_key": "cbom.ingest",           "arguments": {}},
    {"source": "cbom.direct", "vhost": "/", "destination": "orchestrator.requests", "destination_type": "queue", "routing_key": "orchestrator.requests", "arguments": {}},
    {"source": "cbom.fanout", "vhost": "/", "destination": "cbom.notify",           "destination_type": "queue", "routing_key": "",                      "arguments": {}},
    {"source": "cbom.dlx",   "vhost": "/", "destination": "cbom.dlq",              "destination_type": "queue", "routing_key": "cbom.dlq",              "arguments": {}}
  ]
}
```

---

## Message Schemas

### ScanRequest (orchestrator.requests)
```json
{
  "message_type": "ScanRequest",
  "scan_id": "uuid",
  "config": {
    "target_repos": ["string"],
    "target_hosts": ["string"],
    "target_db_connections": ["encrypted-string"],
    "network_interface": "eth0",
    "max_file_depth": 5,
    "enable_llm_fallback": true,
    "sector": "financial_dora",
    "q_day_year": 2030
  },
  "created_at": "ISO8601",
  "trace_id": "uuid"
}
```

### ScanJob (scanner.ast / scanner.binary / scanner.cert / scanner.db)
```json
{
  "message_type": "ScanJob",
  "job_id": "uuid",
  "scan_id": "uuid",
  "job_type": "ast",
  "target": "/path/to/file-or-directory",
  "depth": 0,
  "max_depth": 5,
  "config": {},
  "trace_id": "uuid",
  "created_at": "ISO8601"
}
```

### CryptoAssetFound (cbom.ingest)
```json
{
  "message_type": "CryptoAssetFound",
  "scan_id": "uuid",
  "job_id": "uuid",
  "algorithm": "RSA",
  "algorithm_normalized": "RSA",
  "key_size": 2048,
  "crypto_type": "asymmetric_encryption",
  "location": "/src/auth/jwt.py",
  "line_number": 42,
  "source": "ast_scanner",
  "library": "cryptography",
  "usage_context": "JWT signing",
  "confidence": "high",
  "raw_evidence": "string",
  "trace_id": "uuid",
  "found_at": "ISO8601"
}
```

### ScanComplete (cbom.fanout → cbom.notify)
```json
{
  "message_type": "ScanComplete",
  "scan_id": "uuid",
  "status": "complete",
  "assets_found": 42,
  "findings_count": 7,
  "qars_avg": 0.71,
  "qsri_score": 34.5,
  "completed_at": "ISO8601",
  "trace_id": "uuid"
}
```

### SLMFallbackRequest (slm.fallback)
```json
{
  "message_type": "SLMFallbackRequest",
  "job_id": "uuid",
  "scan_id": "uuid",
  "file_path": "/path/to/file",
  "file_content_b64": "base64-truncated-to-2000-chars",
  "magika_result": {"content_type": "unknown", "confidence": 0.3},
  "trace_id": "uuid",
  "created_at": "ISO8601"
}
```

---

## Python Connection Helper (shared/rabbitmq.py)

```python
"""Shared RabbitMQ connection helper for all Python services."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import AsyncGenerator

import aio_pika
import structlog

logger = structlog.get_logger()

QUEUES = {
    "orchestrator_requests": "orchestrator.requests",
    "scanner_ast": "scanner.ast",
    "scanner_binary": "scanner.binary",
    "scanner_cert": "scanner.cert",
    "scanner_db": "scanner.db",
    "slm_fallback": "slm.fallback",
    "cbom_ingest": "cbom.ingest",
    "cbom_notify": "cbom.notify",
    "cbom_dlq": "cbom.dlq",
}

EXCHANGES = {
    "direct": "cbom.direct",
    "fanout": "cbom.fanout",
    "dlx": "cbom.dlx",
}


def _read_secret(env_var: str) -> str:
    file_path = os.environ.get(f"{env_var}_FILE")
    if file_path and Path(file_path).exists():
        return Path(file_path).read_text().strip()
    return os.environ.get(env_var, "")


async def get_rabbitmq_connection() -> aio_pika.abc.AbstractRobustConnection:
    host = os.environ.get("RABBITMQ_HOST", "rabbitmq")
    port = int(os.environ.get("RABBITMQ_PORT", "5672"))
    user = os.environ.get("RABBITMQ_USER", "cbom")
    password = _read_secret("RABBITMQ_PASSWORD")
    vhost = os.environ.get("RABBITMQ_VHOST", "/")

    url = f"amqp://{user}:{password}@{host}:{port}/{vhost}"
    return await aio_pika.connect_robust(
        url,
        reconnect_interval=5,
        heartbeat=60,
    )


async def publish_message(
    channel: aio_pika.abc.AbstractChannel,
    routing_key: str,
    payload: dict,
    exchange_name: str = "cbom.direct",
) -> None:
    import json
    exchange = await channel.get_exchange(exchange_name)
    message = aio_pika.Message(
        body=json.dumps(payload).encode(),
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        content_type="application/json",
    )
    await exchange.publish(message, routing_key=routing_key)
    logger.debug("message_published", routing_key=routing_key, message_type=payload.get("message_type"))
```

---

## Celery Config (scanners/src/cbom_scanners/celery_app.py)

```python
from celery import Celery
from .config import get_settings

settings = get_settings()

app = Celery(
    "cbom_scanners",
    broker=settings.rabbitmq_url,
    backend=None,  # No result backend — results published via RabbitMQ
    include=["cbom_scanners.tasks"],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,                 # Ack only after task completes
    task_reject_on_worker_lost=True,     # Requeue on worker crash
    worker_prefetch_multiplier=1,        # One job at a time per worker
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    broker_transport_options={
        "confirm_publish": True,
        "max_retries": 3,
    },
)
```
