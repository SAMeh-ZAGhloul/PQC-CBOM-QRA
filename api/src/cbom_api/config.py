"""Application settings loaded from environment variables and Docker secrets."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(path: str) -> str:
    p = Path(path)
    if p.exists():
        return p.read_text().strip()
    raise ValueError(f"Secret file not found: {path}")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "production"
    app_version: str = "1.0.0-mvp"
    log_level: str = "INFO"
    domain: str = "localhost"

    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "cbom"
    postgres_user: str = "cbom"
    db_password_file: str = "/run/secrets/db_password"

    redis_host: str = "redis"
    redis_port: int = 6379
    redis_password_file: str = "/run/secrets/redis_password"

    rabbitmq_host: str = "rabbitmq"
    rabbitmq_port: int = 5672
    rabbitmq_user: str = "cbom"
    rabbitmq_vhost: str = "/"
    rabbitmq_password_file: str = "/run/secrets/rabbitmq_password"

    minio_endpoint: str = "minio:9000"
    minio_use_ssl: bool = False
    minio_user: str = "cbomadmin"
    minio_password_file: str = "/run/secrets/minio_password"
    minio_bucket_cbom_exports: str = "cbom-exports"
    minio_bucket_zeek_logs: str = "zeek-logs"
    minio_bucket_scan_artifacts: str = "scan-artifacts"
    minio_bucket_compliance: str = "compliance-packages"

    jwt_algorithm: str = "RS256"
    jwt_private_key_file: str = "/run/secrets/jwt_private_key"
    jwt_public_key_file: str = "/run/secrets/jwt_public_key"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 7

    ollama_host: str = "ollama"
    ollama_port: int = 11434
    ollama_model: str = "gemma2:2b"

    qars_default_q_day_year: int = 2030
    qars_default_sector: str = "general_enterprise"
    traffic_sim_url: str = "http://traffic-sim:8080"

    @field_validator("jwt_algorithm")
    @classmethod
    def validate_jwt_algorithm(cls, value: str) -> str:
        if value != "RS256":
            raise ValueError("JWT algorithm must be RS256")
        return value

    @property
    def database_url(self) -> str:
        pwd = _read_secret_file(self.db_password_file)
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{pwd}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        pwd = _read_secret_file(self.redis_password_file)
        return f"redis://:{pwd}@{self.redis_host}:{self.redis_port}/0"

    @property
    def rabbitmq_url(self) -> str:
        pwd = _read_secret_file(self.rabbitmq_password_file)
        return (
            f"amqp://{self.rabbitmq_user}:{pwd}@{self.rabbitmq_host}:"
            f"{self.rabbitmq_port}/{self.rabbitmq_vhost}"
        )

    @property
    def jwt_private_key(self) -> str:
        return _read_secret_file(self.jwt_private_key_file)

    @property
    def jwt_public_key(self) -> str:
        return _read_secret_file(self.jwt_public_key_file)

    @property
    def minio_password(self) -> str:
        return _read_secret_file(self.minio_password_file)


@lru_cache
def get_settings() -> Settings:
    return Settings()
