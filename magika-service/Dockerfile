FROM python:3.12-slim

RUN groupadd -r cbom && useradd -r -g cbom cbom

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ ./src/

RUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN d=RUN pip instaRUN pip instaRUN pip instalocRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN d=RUN pip instaRUN pip instaRUN pip instalocRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN d=RUN pip instaRUN pip instaRUN pip instalocRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN d=RUN pip instaRUN pip instaRUN pip instalocRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRUN pip instaRU .RUN pip instaRUN pip instaRUN pip instahe-dir -e ".[dev]"

USER cbom

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8080/ || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
