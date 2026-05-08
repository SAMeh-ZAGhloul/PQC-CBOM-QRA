.PHONY: setup pull-model up down restart logs logs-api logs-scanner \
        logs-zeek logs-workers status migrate migrate-new backup \
        scale-scanners build lint test type-check clean reset \
        shell-api shell-db shell-rabbitmq open-portainer trust-cert

# ── Variables ──────────────────────────────────────────────────────────────
COMPOSE       := docker compose
API_CONTAINER := cbom-api
DB_CONTAINER  := cbom-postgres
MQ_CONTAINER  := cbom-rabbitmq

# ── Setup ──────────────────────────────────────────────────────────────────

## First-time setup: generate certs, secrets, start infra, seed DB, init MinIO
setup:
	@echo "==> [1/5] Generating TLS certificates and JWT keys..."
	@bash scripts/gen-certs.sh
	@echo ""
	@echo "==> [2/5] Starting infrastructure services..."
	@$(COMPOSE) up -d postgres redis rabbitmq minio
	@echo "==> Waiting 15s for services to initialize..."
	@sleep 15
	@echo ""
	@echo "==> [3/5] Running database migrations..."
	@$(COMPOSE) run --rm --no-deps api alembic upgrade head
	@echo ""
	@echo "==> [4/5] Seeding database with admin user and default groups..."
	@bash scripts/seed-db.sh
	@echo ""
	@echo "==> [5/5] Initializing MinIO buckets..."
	@$(COMPOSE) up -d minio
	@sleep 5
	@bash scripts/init-minio.sh
	@echo ""
	@echo "==> Setup complete!"
	@echo "    Next step: make pull-model  (downloads Gemma 2 2B, ~3 GB)"

## Pull Gemma 2 2B model into Ollama (run once, ~3 GB download)
pull-model:
	@echo "==> Starting Ollama container..."
	@$(COMPOSE) up -d ollama
	@echo "==> Waiting for Ollama to be ready..."
	@sleep 15
	@bash scripts/model-pull.sh
	@echo "==> Model ready. Run: make up"

# ── Lifecycle ──────────────────────────────────────────────────────────────

## Start all 19 containers (build images if needed)
up:
	@$(COMPOSE) up -d --build
	@echo ""
	@echo "==> Platform started."
	@echo "    Dashboard:  https://localhost"
	@echo "    Portainer:  https://localhost:9443"
	@echo "    Traffic sim: http://localhost:8080"
	@echo ""
	@make status

## Stop all containers (data preserved in volumes)
down:
	@$(COMPOSE) down

## Restart a specific service: make restart SERVICE=api
restart:
	@$(COMPOSE) restart $(SERVICE)

## Restart all scanner workers
restart-workers:
	@$(COMPOSE) restart worker-ast worker-binary worker-cert worker-db

## Restart the full platform (down + up)
bounce:
	@$(COMPOSE) down
	@$(COMPOSE) up -d --build

# ── Observability ──────────────────────────────────────────────────────────

## Tail all container logs (Ctrl+C to stop)
logs:
	@$(COMPOSE) logs -f --tail=100

## Tail API logs only
logs-api:
	@$(COMPOSE) logs -f --tail=100 api

## Tail all scanner worker logs
logs-scanner:
	@$(COMPOSE) logs -f --tail=100 worker-ast worker-binary worker-cert worker-db

## Tail Zeek logs
logs-zeek:
	@$(COMPOSE) logs -f --tail=100 zeek

## Tail all worker-type containers
logs-workers:
	@$(COMPOSE) logs -f --tail=100 worker-ast worker-binary worker-cert worker-db \
	    worker-magika cbom-generator scoring-engine orchestrator

## Show container status table
status:
	@echo ""
	@$(COMPOSE) ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
	@echo ""

## Show resource usage per container
resources:
	@docker stats --no-stream --format \
	    "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# ── Database ───────────────────────────────────────────────────────────────

## Apply all pending Alembic migrations
migrate:
	@$(COMPOSE) exec $(API_CONTAINER) alembic upgrade head

## Create a new Alembic migration: make migrate-new MSG="add scan config column"
migrate-new:
	@$(COMPOSE) exec $(API_CONTAINER) alembic revision --autogenerate -m "$(MSG)"

## Show current migration revision
migrate-status:
	@$(COMPOSE) exec $(API_CONTAINER) alembic current

## Downgrade one migration step
migrate-down:
	@$(COMPOSE) exec $(API_CONTAINER) alembic downgrade -1

## Open interactive psql shell
shell-db:
	@DB_PASS=$$(cat secrets/db_password.txt); \
	 $(COMPOSE) exec $(DB_CONTAINER) psql -U cbom -d cbom

## Dump full schema
db-schema:
	@DB_PASS=$$(cat secrets/db_password.txt); \
	 $(COMPOSE) exec $(DB_CONTAINER) pg_dump -U cbom -d cbom --schema-only

# ── Backup ─────────────────────────────────────────────────────────────────

## Run manual backup (pg_dump -> MinIO)
backup:
	@$(COMPOSE) exec backup-cron /backup.sh

## List all backups in MinIO
backup-list:
	@$(COMPOSE) exec minio mc ls cbom/backups/postgres/ 2>/dev/null || \
	 echo "MinIO client not configured. Check init-minio.sh."

## Restore from a specific backup: make restore BACKUP=cbom-20250101-020000.sql.gz
restore:
	@echo "==> Restoring from: $(BACKUP)"
	@$(COMPOSE) exec backup-cron bash -c \
	    "aws s3 cp s3://backups/postgres/$(BACKUP) /tmp/restore.sql.gz \
	     --endpoint-url http://minio:9000 --no-verify-ssl && \
	     gunzip /tmp/restore.sql.gz && \
	     psql -h postgres -U cbom -d cbom < /tmp/restore.sql && \
	     rm /tmp/restore.sql"

# ── Scaling ────────────────────────────────────────────────────────────────
SCA_WORKERS := worker-ast worker-binary worker-cert worker-db

## Scale scanner workers: make scale-scanners N=4
scale-scanners:
	@$(COMPOSE) scale $(SCA_WORKERS)=$(N)
	@echo "==> Scaled all scanner workers to $(N) replicas"

## Scale only AST workers: make scale-ast N=6
scale-ast:
	@$(COMPOSE) scale worker-ast=$(N)

# ── Development ────────────────────────────────────────────────────────────

## Build all Docker images (no cache)
build:
	@$(COMPOSE) build --no-cache

## Build a specific service image: make build-svc SVC=api
build-svc:
	@$(COMPOSE) build --no-cache $(SVC)

## Run ruff linter on all Python services
lint:
	@for svc in api orchestrator scanners magika-service cbom-generator scoring-engine traffic-sim; do \
	    echo "==> Linting $$svc..."; \
	    $(COMPOSE) run --rm --no-deps $$svc ruff check src/ || exit 1; \
	done

## Run mypy type checker on all Python services
type-check:
	@for svc in api orchestrator scanners magika-service cbom-generator scoring-engine; do \
	    echo "==> Type checking $$svc..."; \
	    $(COMPOSE) run --rm --no-deps $$svc mypy src/ || exit 1; \
	done

## Run all tests
test:
	@for svc in api orchestrator scanners magika-service cbom-generator scoring-engine; do \
	    echo "==> Testing $$svc..."; \
	    $(COMPOSE) run --rm --no-deps $$svc pytest tests/ -v --tb=short || exit 1; \
	done

## Run tests for a specific service: make test-svc SVC=api
test-svc:
	@$(COMPOSE) run --rm --no-deps $(SVC) pytest tests/ -v --tb=short

## Run tests with coverage report
test-coverage:
	@$(COMPOSE) run --rm --no-deps api \
	    pytest tests/ --cov=cbom_api --cov-report=html --cov-report=term-missing

# ── Shells ─────────────────────────────────────────────────────────────────

## Open shell in API container
shell-api:
	@$(COMPOSE) exec $(API_CONTAINER) bash

## Open shell in RabbitMQ container
shell-rabbitmq:
	@$(COMPOSE) exec $(MQ_CONTAINER) bash

## Open Ollama shell
shell-ollama:
	@$(COMPOSE) exec cbom-ollama bash

## List loaded Ollama models
ollama-models:
	@$(COMPOSE) exec cbom-ollama ollama list

## Run CBOM platform CLI (when implemented)
cbom-cli:
	@$(COMPOSE) exec $(API_CONTAINER) python -m cbom_api.cli $(ARGS)

# ── Browser shortcuts ──────────────────────────────────────────────────────

## Open Portainer in default browser
open-portainer:
	@echo "Opening https://localhost:9443"
	@(which xdg-open && xdg-open https://localhost:9443) || \
	 (which open && open https://localhost:9443) || \
	 echo "Navigate to: https://localhost:9443"

## Open CBOM dashboard
open-dashboard:
	@(which xdg-open && xdg-open https://localhost) || \
	 (which open && open https://localhost) || \
	 echo "Navigate to: https://localhost"

## Open Traffic sim UI
open-traffic:
	@(which xdg-open && xdg-open http://localhost:8080) || \
	 (which open && open http://localhost:8080) || \
	 echo "Navigate to: http://localhost:8080"

# ── Trust self-signed certificate ─────────────────────────────────────────

## Add self-signed CA to system trust store
trust-cert:
	@echo "==> Adding CBOM CA to system trust store..."
	@if [ "$$(uname)" = "Darwin" ]; then \
	    sudo security add-trusted-cert -d -r trustRoot \
	        -k /Library/Keychains/System.keychain traefik/certs/ca.crt; \
	    echo "==> Added to macOS Keychain."; \
	elif [ "$$(uname)" = "Linux" ]; then
	    sudo cp traefik/certs/ca.crt /usr/local/share/ca-certificates/cbom-ca.crt; \
	    sudo update-ca-certificates; \
	    echo "==> Added to Linux CA store."; \
	else
	    echo "==> Windows: Import traefik/certs/ca.crt into Trusted Root CAs via certmgr.msc"; \
	fi

# ── Cleanup ────────────────────────────────────────────────────────────────
clean:
	@$(COMPOSE) down --rmi local --remove-orphans

## DESTRUCTIVE: Stop and delete ALL data volumes
reset:
	@echo ""
	@echo "WARNING: This will DELETE all databases, logs, and stored data."
	@echo "Press Ctrl+C to cancel. Proceeding in 5 seconds..."
	@sleep 5
	@$(COMPOSE) down -v --remove-orphans
	@echo "==> All volumes deleted. Run 'make setup' to start fresh."

## Remove generated certs and secrets (re-run gen-certs.sh to regenerate)
clean-secrets:
	@rm -f traefik/certs/ca.crt traefik/certs/ca.key \
	         traefik/certs/server.crt traefik/certs/server.key traefik/certs/ca.srl
	@rm -f secrets/jwt_private_key.pem secrets/jwt_public_key.pem \
	         secrets/db_password.txt secrets/redis_password.txt \
	         secrets/rabbitmq_password.txt secrets/minio_password.txt
	@echo "==> Certs and secrets removed. Run 'make setup' to regenerate."

# ── Help ───────────────────────────────────────────────────────────────────

## Show this help
help:
	@echo ""
	@echo "CBOM Discovery Platform -- Make Targets"
	@echo "========================================"
	@grep -E '^##' Makefile | sed 's/## /  /'
	@echo ""
