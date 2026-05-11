#!/usr/bin/env bash
set -euo pipefail

echo "==> Waiting for llama.cpp to finish loading its model..."
until curl -sf http://localhost:11434/health > /dev/null 2>&1; do sleep 2; done

echo "==> Verifying model..."
curl -sf http://localhost:11434/v1/models
echo "==> Done."
