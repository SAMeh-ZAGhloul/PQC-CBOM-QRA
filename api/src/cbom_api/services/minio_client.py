"""Shared MinIO/S3 client factory for API services."""
from __future__ import annotations

import os
from pathlib import Path

import boto3
import structlog
from botocore.client import Config
from botocore.exceptions import ClientError

from ..config import get_settings

logger = structlog.get_logger()
settings = get_settings()


def get_minio_client():
    endpoint = settings.minio_endpoint
    use_ssl = settings.minio_use_ssl
    return boto3.client(
        "s3",
        endpoint_url=f"{'https' if use_ssl else 'http'}://{endpoint}",
        aws_access_key_id=settings.minio_user,
        aws_secret_access_key=settings.minio_password,
        config=Config(signature_version="s3v4", retries={"max_attempts": 3, "mode": "adaptive"}),
        region_name="us-east-1",
    )


BUCKET_CBOM_EXPORTS = settings.minio_bucket_cbom_exports
BUCKET_ZEEK_LOGS = settings.minio_bucket_zeek_logs
BUCKET_SCAN_ARTIFACTS = settings.minio_bucket_scan_artifacts
BUCKET_COMPLIANCE = settings.minio_bucket_compliance
BUCKET_BACKUPS = "backups"


def upload_bytes(data: bytes, bucket: str, key: str, content_type: str = "application/octet-stream") -> str:
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


def generate_presigned_url(bucket: str, key: str, expiry_seconds: int = 86400) -> str:
    client = get_minio_client()
    return client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expiry_seconds,
    )
