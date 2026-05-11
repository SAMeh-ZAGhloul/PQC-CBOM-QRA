"""Generate and upload CBOM reports to MinIO."""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from weasyprint import HTML

from .minio_client import BUCKET_CBOM_EXPORTS, BUCKET_COMPLIANCE, generate_presigned_url, upload_bytes

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
        data = json.dumps(cbom_json, indent=2, default=str).encode()
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
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "algorithm",
            "key_size",
            "crypto_type",
            "quantum_class",
            "pqc_replacement",
            "location",
            "line_number",
            "source",
            "confidence",
            "qars_score",
            "severity",
            "first_seen_at",
        ],
    )
    writer.writeheader()

    qars_map = {str(q.asset_id): q for q in qars_scores}
    for asset in assets:
        qars = qars_map.get(str(asset.id))
        writer.writerow(
            {
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
            }
        )
    return output.getvalue().encode("utf-8")


async def _generate_pdf(
    scan_id: str,
    assets: list[Any],
    findings: list[Any],
    qars_scores: list[Any],
) -> bytes:
    html = f"""
    <html><body>
    <h1>CBOM Report</h1>
    <p>Scan: {scan_id}</p>
    <p>Assets: {len(assets)}</p>
    <p>Findings: {len(findings)}</p>
    <p>QARS Scores: {len(qars_scores)}</p>
    </body></html>
    """
    return HTML(string=html).write_pdf()


async def _generate_compliance_package(
    scan_id: str,
    framework: str,
    assets: list[Any],
    findings: list[Any],
) -> bytes:
    html = f"""
    <html><body>
    <h1>{framework} Compliance Evidence</h1>
    <p>Scan: {scan_id}</p>
    <p>Assets reviewed: {len(assets)}</p>
    <p>Findings included: {len(findings)}</p>
    </body></html>
    """
    return HTML(string=html).write_pdf()
