# 10 -- llama.cpp SLM Service

> Read `00_MASTER_SPEC.md` first.

---

## Overview

The platform uses **llama.cpp** running in server mode as its SLM (Small Language Model) for crypto detection fallback when AST/regex scanning cannot classify a file. The server runs inside a Docker container using the `ghcr.io/ggml-org/llama.cpp:server` image and loads a GGUF-quantized model from HuggingFace Hub.

---

## Model Specifications

| Property       | Value                                                                 |
| -------------- | --------------------------------------------------------------------- |
| Model          | LiquidAI/LFM2.5-1.2B-Instruct-GGUF:Q4_K_M                            |
| Quantization   | Q4_K_M (4-bit, small+accurate)                                        |
| On-disk size   | ~1.2 GB                                                              |
| RAM CPU-only   | ~2 GB                                                                 |
| RAM GPU        | N/A                                                                   |
| Inference CPU  | 2-5 seconds per request                                               |
| Inference GPU  | < 500 ms                                                              |
| Context window | 4096 tokens                                                           |
| API            | llama.cpp native `/completion` + OpenAI-compatible `/v1/chat/completions` |

---

## Docker Compose Service Definition

```yaml
  # ── llama.cpp SLM ─────────────────────────────────────────────────────────
  llama-cpp:
    image: ghcr.io/ggml-org/llama.cpp:server
    container_name: cbom-llama-cpp
    restart: unless-stopped
    networks: [cbom-backend]
    volumes:
      - llama-models:/models
    environment:
      - HF_HOME=/models/hf-cache
      - LLAMA_CACHE=/models/hf-cache
    command:
      - -hf
      - LiquidAI/LFM2.5-1.2B-Instruct-GGUF:Q4_K_M
      - --alias
      - cbom-slm
      - --host
      - 0.0.0.0
      - --port
      - "11434"
      - --ctx-size
      - "4096"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/health"]
      interval: 30s
      timeout: 10s
      start_period: 60s
      retries: 5
```

**How it works:**
1. The container starts and loads the GGUF model from HuggingFace Hub using the `-hf` flag
2. The model weights are cached in the `llama-models` volume at `/models/hf-cache`
3. The model is aliased as `cbom-slm` for easy identification
4. The server listens on port 11434 (same port as Ollama for drop-in compatibility)
5. A health check pings `/health` to confirm the server is ready (model may take 30-60s to load on first start)

---

## scripts/model-pull.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "==> Waiting for llama.cpp to finish loading its model..."
until curl -sf http://localhost:11434/health > /dev/null 2>&1; do sleep 2; done

echo "==> Verifying model..."
curl -sf http://localhost:11434/v1/models
echo "==> Done."
```

> **Note:** Unlike Ollama, llama.cpp auto-downloads the model from HuggingFace Hub on first start. The `model-pull.sh` script simply waits for the model to load and then verifies it. There is no separate `ollama pull` step.

---

## Prompt Templates

### Crypto Detection Prompt

```python
CRYPTO_DETECTION_PROMPT = (
    "You are a cryptographic security analyst.\n"
    "Analyze the code or configuration below for cryptographic operations.\n\n"
    "Rules:\n"
    "- Look for: algorithm names, key sizes, hash functions, cipher modes, crypto API calls\n"
    "- Include: hardcoded values, config strings, import statements, function calls\n"
    "- Skip: comments that only mention crypto without using it\n\n"
    "Return JSON ONLY -- no markdown, no explanation, no backticks:\n"
    '{\n'
    '  "findings": [\n'
    '    {\n'
    '      "algorithm": "exact algorithm name (e.g. RSA, AES-256, SHA-1, ECDSA)",\n'
    '      "quantum_vulnerable": true or false,\n'
    '      "confidence": "high or medium or low",\n'
    '      "reason": "one sentence explaining where and why",\n'
    '      "line_number": integer or null\n'
    '    }\n'
    '  ]\n'
    '}\n\n'
    'If no cryptographic operations found, return: {"findings": []}\n\n'
    "Code to analyze:\n<code>\n{content}\n</code>"
)
```

### Homegrown Crypto Detection Prompt

```python
HOMEGROWN_CRYPTO_PROMPT = (
    "You are a cryptographic security expert specializing in detecting "
    "non-standard and custom cryptographic implementations.\n\n"
    "Analyze the code below. Look specifically for:\n"
    "- Custom XOR-based encryption\n"
    "- Homebrew block ciphers or stream ciphers\n"
    "- Custom hash functions\n"
    "- Feistel network implementations\n"
    "- Any numeric operations that appear to implement crypto primitives\n\n"
    "Return JSON ONLY:\n"
    '{\n'
    '  "homegrown_crypto_detected": true or false,\n'
    '  "confidence": "high or medium or low",\n'
    '  "description": "one sentence",\n'
    '  "risk": "critical or high or medium or low",\n'
    '  "recommendation": "one sentence remediation advice"\n'
    '}\n\n'
    "Code:\n<code>\n{content}\n</code>"
)
```

---

## Rate-Limited Async Client

```python
from __future__ import annotations
import asyncio, json, os
from pathlib import Path
from typing import Any
import httpx, structlog

logger = structlog.get_logger()

# Primary: LLM_* vars; fallback: OLLAMA_* vars for migration compatibility
LLM_HOST = os.environ.get("LLM_HOST", os.environ.get("OLLAMA_HOST", "llama-cpp"))
LLM_PORT = os.environ.get("LLM_PORT", os.environ.get("OLLAMA_PORT", "11434"))
LLM_MODEL = os.environ.get("LLM_MODEL", os.environ.get("OLLAMA_MODEL", "cbom-slm"))
LLM_BASE_URL = f"http://{LLM_HOST}:{LLM_PORT}"
LLM_MAX_CONCURRENT = int(
    os.environ.get("LLM_MAX_CONCURRENT", os.environ.get("OLLAMA_MAX_CONCURRENT", "10"))
)
LLM_TIMEOUT = int(
    os.environ.get("LLM_TIMEOUT_SECONDS", os.environ.get("OLLAMA_TIMEOUT_SECONDS", "60"))
)

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(LLM_MAX_CONCURRENT)
    return _semaphore


async def analyze_file_async(file_path: str, prompt_template: str) -> list[dict[str, Any]]:
    path = Path(file_path)
    if not path.exists():
        return []
    content = path.read_text(errors="ignore")[:2000]
    prompt = prompt_template.format(content=content)

    async with _get_semaphore():
        try:
            async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
                response = await client.post(
                    f"{LLM_BASE_URL}/completion",
                    json={
                        "prompt": prompt,
                        "temperature": 0.1,
                        "n_predict": 800,
                    },
                )
                response.raise_for_status()
                raw = response.json().get("content", "").strip()
                # Strip accidental markdown fences
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                raw = raw.strip().rstrip("```").strip()
                data = json.loads(raw)
                return data.get("findings", [])
        except json.JSONDecodeError as e:
            logger.warning("llm_json_parse_failed", file=file_path, error=str(e))
        except httpx.TimeoutException:
            logger.warning("llm_timeout", file=file_path)
        except Exception as e:
            logger.error("llm_request_failed", file=file_path, error=str(e))
    return []


async def check_llm_health() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            health = await client.get(f"{LLM_BASE_URL}/health")
            if health.status_code != 200:
                return False
            models_response = await client.get(f"{LLM_BASE_URL}/v1/models")
            models = models_response.json().get("data", [])
            return any(LLM_MODEL == m.get("id") for m in models)
    except Exception:
        return False
```

---

## API Differences: llama.cpp vs Ollama

| Feature | Ollama | llama.cpp |
|---------|--------|-----------|
| Endpoint | `/api/generate` | `/completion` |
| Response field | `response` | `content` |
| Model param | `"model"` | `--alias` (at startup) |
| Model download | `ollama pull` | Auto-downloads from HuggingFace via `-hf` |
| Health check | `/api/tags` | `/health` |
| OpenAI compatible | `/v1/chat/completions` | `/v1/chat/completions` (both) |
| Image | `ollama/ollama:latest` | `ghcr.io/ggml-org/llama.cpp:server` |

---

## Model Upgrade Reference

```bash
# Switch to a different HuggingFace GGUF model (update docker-compose.yml):
# Change the -hf argument and restart:
docker compose down llama-cpp
# Edit docker-compose.yml: change -hf model path
# Example: -hf QuantFactory/Meta-Llama-3-8B-Instruct-GGUF:Q4_K_M
docker compose up -d llama-cpp
```

GPU acceleration is automatic via the `deploy.resources.reservations.devices`
block in docker-compose.yml. llama.cpp auto-detects NVIDIA GPUs via CUDA at startup.