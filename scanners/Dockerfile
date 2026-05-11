FROM python:3.12-slim

RUN groupadd -r cbom && useradd -r -g cbom cbom

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ ./src/

RUN pip install --no-cache-dir -e ".[dev]"

USER cbom

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8001/health || exit 1
