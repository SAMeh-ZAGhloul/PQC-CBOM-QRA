#!/usr/bin/env bash
set -euo pipefail

echo "==> Waiting for Ollama..."
until curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; do sleep 2; done

echo "==> Pulling tomng/lfm2.5-instruct:1.2b (~2.7 GB)..."
docker exec cbom-ollama ollama pull tomng/lfm2.5-instruct:1.2b

echo "==> Verifying model..."
docker exec cbom-ollama ollama list
echo "==> Done."
