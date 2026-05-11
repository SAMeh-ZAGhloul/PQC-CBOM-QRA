FROM python:3.12-slim

RUN groupadd -r cbom && useradd -r -g cbom cbom

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ ./src/

RUN pip install --no-cache-dir -e ".[dev]"

USER cbom

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8001/health || exit 1

CMD ["python", "FROM python:3.12-slim

RUN groupadd -r cE

RUN groupadd -r cboock
WORKDIR /app

RUN apt-get update && apt-get ile 
RUN apt-geILE    curl gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPYom    && rm -rf /var/lib/N 
COPY pyproject.toml .
COPY src/  -y --no-install-recommen
RUN pip instalibp
USER cbom

HEALTHCHECK --interval=30s --sts
HEALTHC py  CMD curl -f http://localhost:8001/health || exit 1
Dcache-dir -e ".[dev]DOCKERFILE
echo "scanners/Dockerfile created"

cat 10s --start-pcat 10s --start-pcat 10s --start-l -f http://localhost:8003/health || exit 1

CMD ["python", "-m", "cbom_generator.main"]
