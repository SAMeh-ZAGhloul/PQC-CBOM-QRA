from __future__ import annotations
import asyncio, json, os
from pathlib import Path
from typing import Any
import httpx, structlog

logger = structlog.get_logger()

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

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "ollama")
OLLAMA_PORT = os.environ.get("OLLAMA_PORT", "11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma2:2b")
OLLAMA_BASE_URL = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"
OLLAMA_MAX_CONCURRENT = int(os.environ.get("OLLAMA_MAX_CONCURRENT", "10"))
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "60"))

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(OLLAMA_MAX_CONCURRENT)
    return _semaphore


async def analyze_file_async(file_path: str, prompt_template: str) -> list[dict[str, Any]]:
    path = Path(file_path)
    if not path.exists():
        return []
    content = path.read_text(errors="ignore")[:2000]
    prompt = prompt_template.format(content=content)

    async with _get_semaphore():
        try:
            async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
                response = await client.post(
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
                          "options": {"temperature": 0.1, "num_predict": 800}},
                )
                response.raise_for_status()
                raw = response.json().get("response", "").strip()
                # Strip accidental markdown fences
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                raw = raw.strip().rstrip("```").strip()
                data = json.loads(raw)
                return data.get("findings", [])
        except json.JSONDecodeError as e:
            logger.warning("ollama_json_parse_failed", file=file_path, error=str(e))
        except httpx.TimeoutException:
            logger.warning("ollama_timeout", file=file_path)
        except Exception as e:
            logger.error("ollama_request_failed", file=file_path, error=str(e))
    return []


async def check_ollama_health() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            models = r.json().get("models", [])
            return any(OLLAMA_MODEL in m.get("name","") for m in models)
    except Exception:
        return False
