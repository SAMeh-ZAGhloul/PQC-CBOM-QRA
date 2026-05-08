#!/usr/bin/env bash
# Pull Gemma 2 2B into the ollama-models Docker volume.
# Run after: docker compose up -d ollama

set -euo pipefail

CONTAINER="cbom-ollama"
MODEL="gemma2:2b"
MAX_WAIT=120
WAIT=0

echo "==> Waiting for Ollama container to be ready (max ${MAX_WAIT}s)..."
until docker exec "$CONTAINER" curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; do
    if [[ $WAIT -ge $MAX_WAIT ]]; then
        echo "ERROR: Ollama did not become ready within ${MAX_WAIT}s"
        echo "Check: docker logs $CONTAINER"
        exit 1
    fi
    sleep 3
    WAIT=$((WAIT + 3))
done

echo "==> Ollama ready. Pulling model: $MODEL"
echo "    This will download approximately 2.7 GB..."
docker exec "$CONTAINER" ollama pull "$MODEL"

echo ""
echo "==> Verifying model..."
docker exec "$CONTAINER" ollama list

echo ""
echo "==> Model pull complete. $MODEL is ready."
echo "    GPU support: $(docker exec $CONTAINER nvidia-smi -L 2>/dev/null | head -1 || echo 'Not available (CPU mode)')"
