# 02 — Docker Compose

> Read `00_MASTER_SPEC.md` and `01_PROJECT_STRUCTURE.md` first.

---

## Full docker-compose.yml

```yaml
version: "3.9"

# ── Networks ────────────────────────────────────────────────────────────────
networks:
  cbom-frontend:
    driver: bridge
    name: cbom-frontend
  cbom-backend:
    driver: bridge
    name: cbom-backend

# ── Volumes ─────────────────────────────────────────────────────────────────
volumes:
  postgres-data:
  redis-data:
  minio-data:
  ollama-models:
  portainer-data:
  zeek-logs:         # shared between zeek (rw) and orchestrator (ro)

# ── Secrets ─────────────────────────────────────────────────────────────────
secrets:
  jwt_private_key:
    file: ./secrets/jwt_private_key.pem
  jwt_public_key:
    file: ./secrets/jwt_public_key.pem
  db_password:
    file: ./secrets/db_password.txt
  redis_password:
    file: ./secrets/redis_password.txt
  rabbitmq_password:
    file: ./secrets/rabbitmq_password.txt
  minio_password:
    file: ./secrets/minio_password.txt

# ── Services ────────────────────────────────────────────────────────────────
services:

  # ── Traefik ───────────────────────────────────────────────────────────────
  traefik:
    image: traefik:v3.0
    container_name: cbom-traefik
    restart: unless-stopped
    networks: [cbom-frontend]
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./traefik/dynamic.yml:/etc/traefik/dynamic.yml:ro
      - ./traefik/certs:/certs:ro
    healthcheck:
      test: ["CMD", "traefik", "healthcheck", "--ping"]
      interval: 30s
      timeout: 10s
      retries: 3
    labels:
      - "traefik.enable=true"

  # ── Frontend ──────────────────────────────────────────────────────────────
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: cbom-frontend
    restart: unless-stopped
    networks: [cbom-frontend]
    depends_on:
      api:
        condition: service_healthy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.frontend.rule=PathPrefix(`/`)"
      - "traefik.http.routers.frontend.entrypoints=websecure"
      - "traefik.http.routers.frontend.tls=true"
      - "traefik.http.routers.frontend.priority=1"
      - "traefik.http.services.frontend.loadbalancer.server.port=3000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ── API ───────────────────────────────────────────────────────────────────
  api:
    build:
      context: ./api
      dockerfile: Dockerfile
    container_name: cbom-api
    restart: unless-stopped
    networks: [cbom-frontend, cbom-backend]
    env_file: .env
    secrets:
      - jwt_private_key
      - jwt_public_key
      - db_password
      - redis_password
      - rabbitmq_password
      - minio_password
    environment:
      - JWT_PRIVATE_KEY_FILE=/run/secrets/jwt_private_key
      - JWT_PUBLIC_KEY_FILE=/run/secrets/jwt_public_key
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - REDIS_PASSWORD_FILE=/run/secrets/redis_password
      - RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password
      - MINIO_PASSWORD_FILE=/run/secrets/minio_password
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.api.rule=PathPrefix(`/api`) || PathPrefix(`/auth`) || PathPrefix(`/health`) || PathPrefix(`/metrics`)"
      - "traefik.http.routers.api.entrypoints=websecure"
      - "traefik.http.routers.api.tls=true"
      - "traefik.http.routers.api.priority=10"
      - "traefik.http.services.api.loadbalancer.server.port=8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      start_period: 30s
      retries: 3

  # ── Orchestrator ──────────────────────────────────────────────────────────
  orchestrator:
    build:
      context: ./orchestrator
      dockerfile: Dockerfile
    container_name: cbom-orchestrator
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    secrets:
      - db_password
      - redis_password
      - rabbitmq_password
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - REDIS_PASSWORD_FILE=/run/secrets/redis_password
      - RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password
    volumes:
      - zeek-logs:/app/zeek-logs:ro
    depends_on:
      rabbitmq:
        condition: service_healthy
      postgres:
        condition: service_healthy

  # ── Scanner Workers ───────────────────────────────────────────────────────
  worker-ast:
    build:
      context: ./scanners
      dockerfile: Dockerfile
    container_name: cbom-worker-ast
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    secrets: [rabbitmq_password]
    environment:
      - RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password
      - WORKER_TYPE=ast
    command: celery -A cbom_scanners.tasks worker -Q scanner.ast --concurrency=2 --loglevel=info
    depends_on:
      rabbitmq:
        condition: service_healthy
      worker-magika:
        condition: service_healthy
      ollama:
        condition: service_started

  worker-binary:
    build:
      context: ./scanners
      dockerfile: Dockerfile
    container_name: cbom-worker-binary
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    secrets: [rabbitmq_password]
    environment:
      - RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password
      - WORKER_TYPE=binary
    command: celery -A cbom_scanners.tasks worker -Q scanner.binary --concurrency=2 --loglevel=info
    depends_on:
      rabbitmq:
        condition: service_healthy

  worker-cert:
    build:
      context: ./scanners
      dockerfile: Dockerfile
    container_name: cbom-worker-cert
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    secrets: [rabbitmq_password]
    environment:
      - RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password
      - WORKER_TYPE=cert
    command: celery -A cbom_scanners.tasks worker -Q scanner.cert --concurrency=4 --loglevel=info
    depends_on:
      rabbitmq:
        condition: service_healthy

  worker-db:
    build:
      context: ./scanners
      dockerfile: Dockerfile
    container_name: cbom-worker-db
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    secrets: [rabbitmq_password]
    environment:
      - RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password
      - WORKER_TYPE=db
    command: celery -A cbom_scanners.tasks worker -Q scanner.db --concurrency=2 --loglevel=info
    depends_on:
      rabbitmq:
        condition: service_healthy

  # ── Magika File Router ────────────────────────────────────────────────────
  worker-magika:
    build:
      context: ./magika-service
      dockerfile: Dockerfile
    container_name: cbom-magika
    restart: unless-stopped
    networks: [cbom-backend]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8002/health"]
      interval: 20s
      timeout: 5s
      retries: 3

  # ── CBOM Generator ────────────────────────────────────────────────────────
  cbom-generator:
    build:
      context: ./cbom-generator
      dockerfile: Dockerfile
    container_name: cbom-generator
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    secrets:
      - rabbitmq_password
      - db_password
      - minio_password
    environment:
      - RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - MINIO_PASSWORD_FILE=/run/secrets/minio_password
    depends_on:
      rabbitmq:
        condition: service_healthy
      postgres:
        condition: service_healthy
      minio:
        condition: service_healthy

  # ── Scoring Engine ────────────────────────────────────────────────────────
  scoring-engine:
    build:
      context: ./scoring-engine
      dockerfile: Dockerfile
    container_name: cbom-scoring
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    secrets:
      - rabbitmq_password
      - db_password
    environment:
      - RABBITMQ_PASSWORD_FILE=/run/secrets/rabbitmq_password
      - DB_PASSWORD_FILE=/run/secrets/db_password
    depends_on:
      rabbitmq:
        condition: service_healthy
      postgres:
        condition: service_healthy

  # ── Ollama SLM ────────────────────────────────────────────────────────────
  ollama:
    image: ollama/ollama:latest
    container_name: cbom-ollama
    restart: unless-stopped
    networks: [cbom-backend]
    volumes:
      - ollama-models:/root/.ollama
    environment:
      - OLLAMA_NUM_PARALLEL=2
      - OLLAMA_MAX_LOADED_MODELS=1
    # GPU support (optional — remove if no NVIDIA GPU)
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      start_period: 60s
      retries: 5

  # ── RabbitMQ ─────────────────────────────────────────────────────────────
  rabbitmq:
    image: rabbitmq:3.13-management-alpine
    container_name: cbom-rabbitmq
    restart: unless-stopped
    networks: [cbom-backend]
    secrets: [rabbitmq_password]
    environment:
      - RABBITMQ_DEFAULT_USER=cbom
      - RABBITMQ_DEFAULT_PASS_FILE=/run/secrets/rabbitmq_password
      - RABBITMQ_DEFAULT_VHOST=/
    volumes:
      - ./rabbitmq/rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
      - ./rabbitmq/definitions.json:/etc/rabbitmq/definitions.json:ro
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "ping"]
      interval: 30s
      timeout: 10s
      start_period: 30s
      retries: 5

  # ── PostgreSQL ────────────────────────────────────────────────────────────
  postgres:
    image: postgres:16-alpine
    container_name: cbom-postgres
    restart: unless-stopped
    networks: [cbom-backend]
    secrets: [db_password]
    environment:
      - POSTGRES_DB=cbom
      - POSTGRES_USER=cbom
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
      - PGDATA=/var/lib/postgresql/data/pgdata
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/01_init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cbom -d cbom"]
      interval: 10s
      timeout: 5s
      retries: 5
    command: >
      postgres
      -c ssl=on
      -c ssl_cert_file=/var/lib/postgresql/data/server.crt
      -c ssl_key_file=/var/lib/postgresql/data/server.key
      -c log_connections=on
      -c log_duration=on
      -c shared_preload_libraries=pg_stat_statements

  # ── Redis ─────────────────────────────────────────────────────────────────
  redis:
    image: redis:7-alpine
    container_name: cbom-redis
    restart: unless-stopped
    networks: [cbom-backend]
    secrets: [redis_password]
    volumes:
      - redis-data:/data
    command: >
      sh -c "redis-server
      --requirepass $$(cat /run/secrets/redis_password)
      --appendonly yes
      --appendfsync everysec
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru"
    healthcheck:
      test: ["CMD", "redis-cli", "--no-auth-warning", "-a", "$$(cat /run/secrets/redis_password)", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ── MinIO ─────────────────────────────────────────────────────────────────
  minio:
    image: minio/minio:latest
    container_name: cbom-minio
    restart: unless-stopped
    networks: [cbom-frontend, cbom-backend]
    secrets: [minio_password]
    volumes:
      - minio-data:/data
    environment:
      - MINIO_ROOT_USER=cbomadmin
      - MINIO_ROOT_PASSWORD_FILE=/run/secrets/minio_password
      - MINIO_BROWSER_REDIRECT_URL=https://localhost/minio
    command: server /data --console-address ":9001"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.minio.rule=PathPrefix(`/minio`)"
      - "traefik.http.routers.minio.entrypoints=websecure"
      - "traefik.http.routers.minio.tls=true"
      - "traefik.http.routers.minio.priority=5"
      - "traefik.http.services.minio.loadbalancer.server.port=9001"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ── Zeek Network Sensor ───────────────────────────────────────────────────
  zeek:
    image: zeek/zeek:6
    container_name: cbom-zeek
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - zeek-logs:/zeek/logs
      - ./zeek/scripts:/zeek/scripts:ro
      - ./zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro
    env_file: .env
    command: >
      sh -c "mkdir -p /zeek/logs &&
             cd /zeek/logs &&
             zeek -i ${ZEEK_INTERFACE:-eth0} -C local /zeek/scripts/crypto-detection.zeek"

  # ── Traffic Simulation ────────────────────────────────────────────────────
  traffic-sim:
    build:
      context: ./traffic-sim
      dockerfile: Dockerfile
    container_name: cbom-traffic-sim
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ── Portainer ─────────────────────────────────────────────────────────────
  portainer:
    image: portainer/portainer-ce:latest
    container_name: cbom-portainer
    restart: unless-stopped
    networks: [cbom-frontend]
    ports:
      - "9443:9443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - portainer-data:/data

  # ── Backup Cron ───────────────────────────────────────────────────────────
  backup-cron:
    image: alpine:3.19
    container_name: cbom-backup
    restart: unless-stopped
    networks: [cbom-backend]
    env_file: .env
    secrets:
      - db_password
      - minio_password
    volumes:
      - ./scripts/backup.sh:/backup.sh:ro
    command: >
      sh -c "apk add --no-cache postgresql-client aws-cli curl &&
             echo '${BACKUP_CRON_SCHEDULE:-0 2 * * *} /backup.sh' | crontab - &&
             crond -f"
```

---

## docker-compose.override.yml (Development)

```yaml
# Dev overrides — hot reload, exposed debug ports
version: "3.9"

services:
  api:
    command: uvicorn cbom_api.main:app --host 0.0.0.0 --port 8000 --reload
    volumes:
      - ./api/src:/app/src:ro
    environment:
      - APP_ENV=development
      - LOG_LEVEL=DEBUG

  frontend:
    build:
      target: dev
    command: npm run dev -- --host 0.0.0.0 --port 3000
    volumes:
      - ./frontend/src:/app/src:ro

  rabbitmq:
    ports:
      - "15672:15672"    # Expose management UI in dev

  postgres:
    ports:
      - "5432:5432"      # Expose DB in dev for migrations

  redis:
    ports:
      - "6379:6379"      # Expose Redis in dev

  ollama:
    ports:
      - "11434:11434"    # Expose Ollama in dev
```

---

## Makefile

```makefile
.PHONY: setup up down logs status backup pull-model reset \
        migrate test lint build clean

# ── Setup ──────────────────────────────────────────────────────────────────
setup:
	@echo "==> Generating TLS certificates and JWT keys..."
	@bash scripts/gen-certs.sh
	@echo "==> Starting infrastructure services..."
	@docker compose up -d postgres redis rabbitmq minio
	@sleep 10
	@echo "==> Seeding database..."
	@bash scripts/seed-db.sh
	@echo "==> Initializing MinIO buckets..."
	@bash scripts/init-minio.sh
	@echo "==> Setup complete. Run: make pull-model"

pull-model:
	@echo "==> Pulling Gemma 2 2B model (~3 GB)..."
	@docker compose up -d ollama
	@sleep 10
	@docker exec cbom-ollama ollama pull gemma2:2b
	@echo "==> Model ready."

# ── Lifecycle ─────────────────────────────────────────────────────────────
up:
	docker compose up -d --build

down:
	docker compose down

restart:
	docker compose restart $(SERVICE)

# ── Observability ──────────────────────────────────────────────────────────
logs:
	docker compose logs -f --tail=100

logs-api:
	docker compose logs -f api

logs-scanner:
	docker compose logs -f worker-ast worker-binary worker-cert worker-db

logs-zeek:
	docker compose logs -f zeek

status:
	@docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# ── Database ───────────────────────────────────────────────────────────────
migrate:
	docker compose exec api alembic upgrade head

migrate-new:
	docker compose exec api alembic revision --autogenerate -m "$(MSG)"

# ── Backup ─────────────────────────────────────────────────────────────────
backup:
	@docker compose exec backup-cron /backup.sh

# ── Scaling ────────────────────────────────────────────────────────────────
scale-scanners:
	docker compose scale worker-ast=$(N) worker-binary=$(N) worker-cert=$(N) worker-db=$(N)

# ── Development ────────────────────────────────────────────────────────────
build:
	docker compose build

lint:
	@for dir in api orchestrator scanners magika-service cbom-generator scoring-engine traffic-sim; do \
	  echo "==> Linting $$dir..."; \
	  docker compose run --rm --no-deps $$dir ruff check src/ || exit 1; \
	done

test:
	@for dir in api orchestrator scanners magika-service cbom-generator scoring-engine; do \
	  echo "==> Testing $$dir..."; \
	  docker compose run --rm --no-deps $$dir pytest tests/ -v || exit 1; \
	done

# ── Cleanup ────────────────────────────────────────────────────────────────
clean:
	docker compose down --rmi local --volumes --remove-orphans

reset:
	@echo "WARNING: This deletes ALL data volumes. Press Ctrl+C to cancel."
	@sleep 5
	docker compose down -v
	@echo "All volumes deleted."
```
