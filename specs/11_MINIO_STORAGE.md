# 11 -- MinIO Object Storage

> Read `00_MASTER_SPEC.md`, `02_DOCKER_COMPOSE.md` first.

---

## Overview

MinIO provides S3-compatible object storage for all file artifacts.
It runs as a single container with AES-256 server-side encryption.
The boto3 client is used identically to AWS S3 -- zero code change if
a client later migrates to cloud object storage.

---

## Bucket Layout

| Bucket | Contents | Versioning | Retention |
|--------|---------|-----------|---------|
| `cbom-exports` | CycloneDX JSON/XML, PDF reports, CSV | Enabled | 7 years |
| `zeek-logs` | Raw Zeek JSON log files (rotated daily) | Disabled | 90 days |
| `scan-artifacts` | Uploaded source archives, target file sets | Disabled | 30 days |
| `compliance-packages` | DORA/NIS2/NSM-10 evidence packages | Enabled | 7 years |
| `backups` | PostgreSQL pg_dump archives | Disabled | 90 days |

---

## scripts/init-minio.sh

```bash
#!/usr/bin/env bash
# Initialize MinIO buckets, versioning, and encryption policies.
# Run once after first `docker compose up -d minio`.

set -euo pipefail

MINIO_ALIAS="cbom"
MINIO_URL="http://localhost:9000"
MINIO_USER="cbomadmin"
MINIO_PASS_FILE="./secrets/minio_password.txt"

if [[ ! -f "$MINIO_PASS_FILE" ]]; then
  echo "ERROR: MinIO password file not found: $MINIO_PASS_FILE"
  exit 1
fi
MINIO_PASS=$(cat "$MINIO_PASS_FILE")

echo "==> Waiting for MinIO to be ready..."
until curl -sf "$MINIO_URL/minio/health/live" > /dev/null 2>&1; do
  sleep 2
done

echo "==> Configuring MinIO client alias..."
docker exec cbom-minio mc alias set "$MINIO_ALIAS" "$MINIO_URL" "$MINIO_USER" "$MINIO_PASS"

echo "==> Creating buckets..."
for bucket in cbom-exports zeek-logs scan-artifacts compliance-packages backups; do
  docker exec cbom-minio mc mb --ignore-existing "$MINIO_ALIAS/$bucket"
done

echo "==> Enabling versioning on audit buckets..."
docker exec cbom-minio mc version enable "$MINIO_ALIAS/cbom-exports"
docker exec cbom-minio mc version enable "$MINIO_ALIAS/compliance-packages"

echo "==> Setting retention policies..."
# cbom-exports: 7 years (WORM-style compliance)
docker exec cbom-minio mc retention set --default COMPLIANCE 2555d "$MINIO_ALIAS/cbom-exports"
# compliance-packages: 7 years
docker exec cbom-minio mc retention set --default COMPLIANCE 2555d "$MINIO_ALIAS/compliance-packages"

echo "==> Setting lifecycle rules (auto-delete old logs)..."
cat > /tmp/zeek-lifecycle.json << 'LIFECYCLE'
{
  "Rules": [
    {
      "ID": "expire-zeek-logs",
      "Status": "Enabled",
      "Expiration": {"Days": 90}
    }
  ]
}
LIFECYCLE
docker cp /tmp/zeek-lifecycle.json cbom-minio:/tmp/
docker exec cbom-minio mc ilm import "$MINIO_ALIAS/zeek-logs" < /tmp/zeek-lifecycle.json

cat > /tmp/artifact-lifecycle.json << 'LIFECYCLE'
{
  "Rules": [
    {
      "ID": "expire-scan-artifacts",
      "Status": "Enabled",
      "Expiration": {"Days": 30}
    }
  ]
}
LIFECYCLE
docker cp /tmp/artifact-lifecycle.json cbom-minio:/tmp/
docker exec cbom-minio mc ilm import "$MINIO_ALIAS/scan-artifacts" < /tmp/artifact-lifecycle.json

echo "==> Creating application service account..."
docker exec cbom-minio mc admin user add "$MINIO_ALIAS" cbom-app "$MINIO_PASS"
docker exec cbom-minio mc admin policy attach "$MINIO_ALIAS" readwrite --user cbom-app

echo "==> MinIO initialization complete."
docker exec cbom-minio mc ls "$MINIO_ALIAS"
```

---

## Python MinIO Client (shared/minio_client.py)

```python
"""Shared MinIO/S3 client factory for all Python services."""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import IO

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
import structlog

logger = structlog.get_logger()


def _read_secret(env_var: str) -> str:
    file_path = os.environ.get(f"{env_var}_FILE")
    if file_path and Path(file_path).exists():
        return Path(file_path).read_text().strip()
    return os.environ.get(env_var, "")


def get_minio_client() -> boto3.client:
    """Return a configured boto3 S3 client pointing at MinIO."""
    endpoint = os.environ.get("MINIO_ENDPOINT", "minio:9000")
    use_ssl = os.environ.get("MINIO_USE_SSL", "false").lower() == "true"
    user = os.environ.get("MINIO_USER", "cbomadmin")
    password = _read_secret("MINIO_PASSWORD")

    return boto3.client(
        "s3",
        endpoint_url=f"{'https' if use_ssl else 'http'}://{endpoint}",
        aws_access_key_id=user,
        aws_secret_access_key=password,
        config=Config(
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "adaptive"},
        ),
        region_name="us-east-1",  # MinIO ignores this but boto3 requires it
    )


# Bucket name constants
BUCKET_CBOM_EXPORTS    = os.environ.get("MINIO_BUCKET_CBOM_EXPORTS",   "cbom-exports")
BUCKET_ZEEK_LOGS       = os.environ.get("MINIO_BUCKET_ZEEK_LOGS",      "zeek-logs")
BUCKET_SCAN_ARTIFACTS  = os.environ.get("MINIO_BUCKET_SCAN_ARTIFACTS", "scan-artifacts")
BUCKET_COMPLIANCE      = os.environ.get("MINIO_BUCKET_COMPLIANCE",     "compliance-packages")
BUCKET_BACKUPS         = "backups"


def upload_bytes(
    data: bytes,
    bucket: str,
    key: str,
    content_type: str = "application/octet-stream",
) -> str:
    """Upload bytes to MinIO. Returns the object key."""
    client = get_minio_client()
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ContentType=content_type,
        ServerSideEncryption="AES256",
    )
    logger.info("minio_upload_complete", bucket=bucket, key=key, size=len(data))
    return key


def upload_file(
    file_path: str,
    bucket: str,
    key: str,
    content_type: str = "application/octet-stream",
) -> str:
    """Upload a local file to MinIO. Returns the object key."""
    client = get_minio_client()
    client.upload_file(
        Filename=file_path,
        Bucket=bucket,
        Key=key,
        ExtraArgs={
            "ContentType": content_type,
            "ServerSideEncryption": "AES256",
        },
    )
    logger.info("minio_file_upload_complete", bucket=bucket, key=key)
    return key


def generate_presigned_url(
    bucket: str,
    key: str,
    expiry_seconds: int = 86400,  # 24 hours default
) -> str:
    """Generate a pre-signed download URL valid for expiry_seconds."""
    client = get_minio_client()
    url = client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expiry_seconds,
    )
    return url


def download_bytes(bucket: str, key: str) -> bytes:
    """Download an object from MinIO as bytes."""
    client = get_minio_client()
    response = client.get_object(Bucket=bucket, Key=key)
    return response["Body"].read()


def object_exists(bucket: str, key: str) -> bool:
    """Check if an object exists in MinIO."""
    client = get_minio_client()
    try:
        client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        raise


def list_objects(bucket: str, prefix: str = "") -> list[dict]:
    """List objects in a bucket with optional prefix filter."""
    client = get_minio_client()
    paginator = client.get_paginator("list_objects_v2")
    objects = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            objects.append({
                "key": obj["Key"],
                "size": obj["Size"],
                "last_modified": obj["LastModified"].isoformat(),
                "etag": obj.get("ETag", "").strip('"'),
            })
    return objects
```

---

## CBOM Export Key Schema

All objects are stored with structured keys for easy browsing and lifecycle management.

```
cbom-exports/
  {scan_id}/
    cbom-v{version}.cyclonedx.json     # CycloneDX JSON
    cbom-v{version}.cyclonedx.xml      # CycloneDX XML
    cbom-v{version}.csv                # CSV asset list
    cbom-v{version}-report.pdf         # Full PDF report
    cbom-v{version}-summary.json       # Summary stats

compliance-packages/
  {scan_id}/
    dora-evidence-{date}.pdf
    nis2-evidence-{date}.pdf
    nsm10-evidence-{date}.pdf

zeek-logs/
  {date}/
    ssl-{timestamp}.log
    x509-{timestamp}.log
    ssh-{timestamp}.log

backups/
  postgres/
    cbom-{date}-{time}.sql.gz
```

---

## scripts/backup.sh

```bash
#!/usr/bin/env bash
# PostgreSQL backup to MinIO. Run by backup-cron container daily at 02:00 UTC.

set -euo pipefail

DATE=$(date +%Y%m%d)
TIME=$(date +%H%M%S)
BACKUP_FILE="/tmp/cbom-${DATE}-${TIME}.sql.gz"

DB_HOST="${POSTGRES_HOST:-postgres}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_NAME="${POSTGRES_DB:-cbom}"
DB_USER="${POSTGRES_USER:-cbom}"
DB_PASS=$(cat /run/secrets/db_password)
MINIO_PASS=$(cat /run/secrets/minio_password)

echo "==> Starting PostgreSQL backup: ${BACKUP_FILE}"

PGPASSWORD="$DB_PASS" pg_dump \
  -h "$DB_HOST" \
  -p "$DB_PORT" \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  --format=plain \
  --no-owner \
  --no-acl \
  | gzip -9 > "$BACKUP_FILE"

echo "==> Backup size: $(du -sh $BACKUP_FILE | cut -f1)"

# Upload to MinIO
MINIO_ENDPOINT="${MINIO_ENDPOINT:-minio:9000}"
aws s3 cp "$BACKUP_FILE" \
  "s3://backups/postgres/cbom-${DATE}-${TIME}.sql.gz" \
  --endpoint-url "http://${MINIO_ENDPOINT}" \
  --no-verify-ssl \
  --sse AES256

echo "==> Backup uploaded to MinIO: backups/postgres/cbom-${DATE}-${TIME}.sql.gz"

# Cleanup local file
rm -f "$BACKUP_FILE"

# Delete backups older than BACKUP_RETENTION_DAYS (default 90)
RETENTION="${BACKUP_RETENTION_DAYS:-90}"
CUTOFF_DATE=$(date -d "-${RETENTION} days" +%Y%m%d 2>/dev/null || date -v "-${RETENTION}d" +%Y%m%d)

echo "==> Purging backups older than ${RETENTION} days (before ${CUTOFF_DATE})..."
aws s3 ls "s3://backups/postgres/" \
  --endpoint-url "http://${MINIO_ENDPOINT}" \
  --no-verify-ssl \
  | awk '{print $4}' \
  | while read -r key; do
      file_date=$(echo "$key" | grep -o '[0-9]\{8\}' | head -1)
      if [[ -n "$file_date" && "$file_date" < "$CUTOFF_DATE" ]]; then
        echo "  Deleting: $key"
        aws s3 rm "s3://backups/postgres/$key" \
          --endpoint-url "http://${MINIO_ENDPOINT}" \
          --no-verify-ssl
      fi
    done

echo "==> Backup complete."
```

---

## Report Generation (api/services/report_service.py)

```python
"""Generate and upload CBOM reports to MinIO."""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from ..models.db import Scan, CryptoAsset, QarsScore, Finding
from .minio_client import (
    upload_bytes, generate_presigned_url,
    BUCKET_CBOM_EXPORTS, BUCKET_COMPLIANCE,
)

logger = structlog.get_logger()


async def generate_report(
    scan_id: str,
    format: str,
    cbom_json: dict,
    assets: list[Any],
    findings: list[Any],
    qars_scores: list[Any],
) -> str:
    """Generate report in requested format, upload to MinIO, return presigned URL."""
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    report_id = str(uuid.uuid4())[:8]

    if format == "cyclonedx-json":
        data = json.dumps(cbom_json, indent=2, default=str).encode()
        key = f"{scan_id}/cbom-{timestamp}-{report_id}.cyclonedx.json"
        content_type = "application/json"
        bucket = BUCKET_CBOM_EXPORTS

    elif format == "cyclonedx-xml":
        from cyclonedx.output.xml import XmlV1Dot6
        data = XmlV1Dot6().output_as_string(cbom_json).encode()
        key = f"{scan_id}/cbom-{timestamp}-{report_id}.cyclonedx.xml"
        content_type = "application/xml"
        bucket = BUCKET_CBOM_EXPORTS

    elif format == "csv":
        data = _generate_csv(assets, qars_scores)
        key = f"{scan_id}/cbom-{timestamp}-{report_id}.csv"
        content_type = "text/csv"
        bucket = BUCKET_CBOM_EXPORTS

    elif format == "pdf":
        data = await _generate_pdf(scan_id, assets, findings, qars_scores)
        key = f"{scan_id}/cbom-{timestamp}-{report_id}-report.pdf"
        content_type = "application/pdf"
        bucket = BUCKET_CBOM_EXPORTS

    elif format in ("compliance-dora", "compliance-nis2", "compliance-nsm10"):
        framework = format.split("-", 1)[1].upper()
        data = await _generate_compliance_package(scan_id, framework, assets, findings)
        key = f"{scan_id}/{framework.lower()}-evidence-{timestamp}.pdf"
        content_type = "application/pdf"
        bucket = BUCKET_COMPLIANCE

    else:
        raise ValueError(f"Unknown report format: {format}")

    upload_bytes(data, bucket, key, content_type)
    url = generate_presigned_url(bucket, key, expiry_seconds=86400)
    logger.info("report_generated", scan_id=scan_id, format=format, key=key)
    return url


def _generate_csv(assets: list[Any], qars_scores: list[Any]) -> bytes:
    """Generate CSV asset list with QARS scores."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "algorithm", "key_size", "crypto_type", "quantum_class",
        "pqc_replacement", "location", "line_number", "source", "confidence",
        "qars_score", "severity", "first_seen_at",
    ])
    writer.writeheader()

    qars_map = {str(q.asset_id): q for q in qars_scores}
    for asset in assets:
        qars = qars_map.get(str(asset.id))
        writer.writerow({
            "id": str(asset.id),
            "algorithm": asset.algorithm,
            "key_size": asset.key_size or "",
            "crypto_type": asset.crypto_type,
            "quantum_class": asset.quantum_class,
            "pqc_replacement": asset.pqc_replacement or "",
            "location": asset.location,
            "line_number": asset.line_number or "",
            "source": asset.source,
            "confidence": asset.confidence,
            "qars_score": str(qars.weighted_qars) if qars else "",
            "severity": qars.severity if qars else "",
            "first_seen_at": asset.first_seen_at.isoformat(),
        })

    return output.getvalue().encode("utf-8")


async def _generate_pdf(
    scan_id: str,
    assets: list[Any],
    findings: list[Any],
    qars_scores: list[Any],
) -> bytes:
    """Generate PDF report using WeasyPrint."""
    from weasyprint import HTML

    vulnerable = [a for a in assets if a.quantum_class == "vulnerable"]
    critical_findings = [f for f in findings if f.severity == "critical"]
    avg_qars = (
        sum(float(q.weighted_qars) for q in qars_scores) / len(qars_scores)
        if qars_scores else 0.0
    )

    html_content = _render_pdf_template(
        scan_id=scan_id,
        total_assets=len(assets),
        vulnerable_count=len(vulnerable),
        critical_findings=len(critical_findings),
        avg_qars=avg_qars,
        findings=findings[:50],     # Cap at 50 for PDF size
        assets=assets[:100],
        qars_scores=qars_scores,
    )
    return HTML(string=html_content).write_pdf()


def _render_pdf_template(**context: Any) -> str:
    """Render the PDF HTML template with context data."""
    # Minimal inline template -- extend with Jinja2 for production
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>CBOM Report -- Scan {context['scan_id']}</title>
      <style>
        body {{ font-family: Arial, sans-serif; font-size: 11pt; color: #1B3A5C; }}
        h1 {{ color: #0F6E56; border-bottom: 2px solid #0F6E56; }}
        h2 {{ color: #1B3A5C; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #1B3A5C; color: white; padding: 6px 8px; text-align: left; }}
        td {{ padding: 5px 8px; border-bottom: 1px solid #ddd; }}
        tr:nth-child(even) {{ background: #f5f5f5; }}
        .critical {{ color: #A32D2D; font-weight: bold; }}
        .high {{ color: #BA7517; }}
        .medium {{ color: #185FA5; }}
        .summary-box {{ background: #EAF4F0; border-left: 4px solid #0F6E56; padding: 10px; margin: 10px 0; }}
      </style>
    </head>
    <body>
      <h1>Quantum-Safe CBOM Discovery Report</h1>
      <p>Scan ID: {context['scan_id']}<br>
         Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}</p>

      <h2>Executive Summary</h2>
      <div class="summary-box">
        <p><strong>Total Assets:</strong> {context['total_assets']}</p>
        <p><strong>Quantum-Vulnerable:</strong> {context['vulnerable_count']}</p>
        <p><strong>Critical Findings:</strong> {context['critical_findings']}</p>
        <p><strong>Average QARS Score:</strong> {context['avg_qars']:.3f}</p>
      </div>

      <h2>Findings ({len(context['findings'])} shown)</h2>
      <table>
        <tr><th>Severity</th><th>Algorithm</th><th>Location</th><th>Recommendation</th></tr>
        {''.join(
          f'<tr><td class="{f.severity}">{f.severity.upper()}</td>'
          f'<td>{f.title}</td>'
          f'<td>{str(f.description)[:80]}</td>'
          f'<td>{str(f.recommendation)[:100]}</td></tr>'
          for f in context['findings']
        )}
      </table>
    </body>
    </html>
    """
```
