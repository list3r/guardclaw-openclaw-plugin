#!/usr/bin/env python3
"""
GuardClaw injection classifier service.

Runs a FastAPI server at http://127.0.0.1:8404 with two endpoints:

  POST /classify  { "content": "..." }
    → { "label": 0|1, "score": float, "injection": bool }

  POST /reload    { "model": "protectai/deberta-v3-base-prompt-injection-v3" }
    → { "ok": true, "model": "..." }
    Hot-swaps the classifier in-place. In-flight /classify requests complete
    against the old model; new requests pick up the new one atomically.

  GET  /health    → { "ok": true, "model": "..." }

The service also watches ~/.openclaw/guardclaw.json every 60 s. If
injection.deberta_model changes it triggers the same hot-swap automatically,
so a GuardClaw auto-update takes full effect without any manual step.

Start:
  pip install fastapi uvicorn torch transformers
  python scripts/injection_classifier.py

Or with a custom port / model:
  GUARDCLAW_DEBERTA_PORT=8404 \\
  GUARDCLAW_DEBERTA_MODEL=protectai/deberta-v3-base-prompt-injection-v2 \\
  python scripts/injection_classifier.py
"""

import asyncio
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    import uvicorn
except ImportError as e:
    print(json.dumps({"error": f"Missing dependency: {e}. Run: pip install fastapi uvicorn"}))
    sys.exit(1)

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
    import torch
except ImportError as e:
    print(json.dumps({"error": f"Missing dependency: {e}. Run: pip install torch transformers"}))
    sys.exit(1)

# ── Config ──────────────────────────────────────────────────────────────────

PORT = int(os.environ.get("GUARDCLAW_DEBERTA_PORT", "8404"))
# GCF-019: Explicitly bind to 127.0.0.1 (loopback only) to prevent the service
# from being accessible on any other network interface. The env var allows
# operators to override only to other loopback addresses (e.g. ::1 for IPv6).
_HOST_ENV = os.environ.get("GUARDCLAW_DEBERTA_HOST", "127.0.0.1")
# Reject non-loopback hosts for safety
HOST = _HOST_ENV if _HOST_ENV in ("127.0.0.1", "::1", "localhost") else "127.0.0.1"
DEFAULT_MODEL = os.environ.get(
    "GUARDCLAW_DEBERTA_MODEL",
    "protectai/deberta-v3-base-prompt-injection-v2",
)
GUARDCLAW_CONFIG = Path.home() / ".openclaw" / "guardclaw.json"
CONFIG_POLL_INTERVAL = 60  # seconds

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("guardclaw-deberta")

# ── Classifier state ─────────────────────────────────────────────────────────

_classifier = None
_current_model: str = DEFAULT_MODEL
_reload_lock = asyncio.Lock()   # prevents concurrent reloads
_ready = False                  # True once first model is loaded


# GCF-022: Pinned revision SHAs for known-good model versions.
# These are verified commit hashes from HuggingFace Hub; pinning prevents a
# mutable model update from silently introducing a backdoored classifier.
# Update after verifying a new release at:
#   https://huggingface.co/<model_id>/commit/<sha>
PINNED_REVISIONS: dict = {
    "protectai/deberta-v3-base-prompt-injection-v2": "e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5",
    "protectai/deberta-v3-base-prompt-injection":    "main",  # add SHA when pinning
    "laiyer/deberta-v3-base-prompt-injection":       "main",  # add SHA when pinning
}


def _load_model(model_id: str):
    """Synchronous model load — call from thread pool to avoid blocking event loop."""
    # GCF-022: Use pinned revision so HuggingFace model updates can't silently
    # swap in a backdoored classifier. Falls back to "main" for unknown models.
    revision = PINNED_REVISIONS.get(model_id, "main")
    log.info(f"Loading model: {model_id} (revision={revision})")
    tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision)
    model = AutoModelForSequenceClassification.from_pretrained(model_id, revision=revision)
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    log.info(f"Using device: {device}")
    clf = pipeline(
        "text-classification",
        model=model,
        tokenizer=tokenizer,
        truncation=True,
        max_length=512,
        device=device,
    )
    log.info(f"Model ready: {model_id}")
    return clf


async def _hot_swap(new_model_id: str) -> dict:
    """
    Download and swap in a new model without dropping the service.
    Uses _reload_lock so concurrent reload requests queue up safely.
    In-flight /classify calls against the old _classifier complete normally
    because Python's GIL and the reference swap are effectively atomic for
    simple attribute assignment at this granularity.
    """
    global _classifier, _current_model, _ready

    async with _reload_lock:
        if new_model_id == _current_model and _ready:
            return {"ok": True, "model": _current_model, "note": "already loaded"}

        loop = asyncio.get_running_loop()
        try:
            new_clf = await loop.run_in_executor(None, _load_model, new_model_id)
        except Exception as e:
            log.error(f"Failed to load {new_model_id}: {e}")
            raise RuntimeError(str(e))

        # Atomic swap — old classifier stays alive until GC collects it
        _classifier = new_clf
        _current_model = new_model_id
        _ready = True
        return {"ok": True, "model": _current_model}


# ── Config file watcher ──────────────────────────────────────────────────────

def _read_config_model() -> Optional[str]:
    """Read injection.deberta_model from guardclaw.json, return None if absent."""
    try:
        cfg = json.loads(GUARDCLAW_CONFIG.read_text())
        privacy = cfg.get("privacy", {})
        injection = privacy.get("injection", cfg.get("injection", {}))
        return injection.get("deberta_model")
    except Exception:
        return None


def _config_watcher(loop: asyncio.AbstractEventLoop):
    """Background thread: polls guardclaw.json and triggers hot-swap on change."""
    log.info(f"Config watcher started (polling {GUARDCLAW_CONFIG} every {CONFIG_POLL_INTERVAL}s)")
    last_model: Optional[str] = None

    while True:
        time.sleep(CONFIG_POLL_INTERVAL)
        try:
            model_in_cfg = _read_config_model()
            if model_in_cfg and model_in_cfg != last_model and model_in_cfg != _current_model:
                log.info(f"Config watcher detected model change: {_current_model} → {model_in_cfg}")
                last_model = model_in_cfg
                future = asyncio.run_coroutine_threadsafe(_hot_swap(model_in_cfg), loop)
                try:
                    result = future.result(timeout=300)  # 5 min timeout for large model downloads
                    log.info(f"Config watcher hot-swap complete: {result}")
                except Exception as e:
                    log.error(f"Config watcher hot-swap failed: {e}")
            elif model_in_cfg:
                last_model = model_in_cfg
        except Exception as e:
            log.warning(f"Config watcher error: {e}")


# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="GuardClaw DeBERTa Classifier", version="1.0.0")


class ClassifyRequest(BaseModel):
    content: str


class ReloadRequest(BaseModel):
    model: str


@app.on_event("startup")
async def startup():
    global _ready
    # Load initial model (honoring guardclaw.json if present)
    cfg_model = _read_config_model()
    initial_model = cfg_model or DEFAULT_MODEL
    try:
        await _hot_swap(initial_model)
    except Exception as e:
        log.error(f"Failed to load initial model {initial_model}: {e}")
        # Service starts anyway — /classify will 503 until a /reload succeeds
    _ready = True

    # Start config watcher thread
    loop = asyncio.get_running_loop()
    watcher = threading.Thread(target=_config_watcher, args=(loop,), daemon=True)
    watcher.start()


@app.post("/classify")
async def classify(req: ClassifyRequest):
    if not _ready or _classifier is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")

    content = req.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="content is required")

    loop = asyncio.get_running_loop()
    try:
        # Run inference in thread pool — transformers pipeline is not async-safe
        clf = _classifier  # local ref so a concurrent reload doesn't affect us
        result = await loop.run_in_executor(None, lambda: clf(content)[0])
    except Exception as e:
        log.error(f"Inference error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    raw_label = result["label"]
    parts = raw_label.split("_")
    if len(parts) >= 2 and parts[-1].isdigit():
        label = int(parts[-1])
    else:
        # Handle descriptive labels (e.g. "INJECTION", "SAFE", "BENIGN")
        label = 1 if raw_label.upper() in ("INJECTION", "MALICIOUS", "POSITIVE") else 0
    score = round(float(result["score"]), 4)
    return {"label": label, "score": score, "injection": label == 1 and score > 0.5}


@app.post("/reload")
async def reload_model(req: ReloadRequest):
    model_id = req.model.strip()
    if not model_id:
        raise HTTPException(status_code=400, detail="model is required")

    log.info(f"Hot-reload requested: {model_id}")
    try:
        result = await _hot_swap(model_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"ok": _ready, "model": _current_model}


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info(f"Starting GuardClaw DeBERTa service on {HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
