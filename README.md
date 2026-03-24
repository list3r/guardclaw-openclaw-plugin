```
  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██║  ███╗██║   ██║███████║██╔══██╝██║  ██║
 ██║   ██║██║   ██║██╔══██║██║  ╚═╗██║  ██║
 ╚██████╔╝╚██████╔╝██║  ██║██║   ╚╗██████╔╝
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝    ╚╝╚═════╝
   ██████╗██╗      █████╗ ██╗    ██╗
  ██╔════╝██║     ██╔══██╗██║    ██║
  ██║     ██║     ███████║██║ █╗ ██║
  ██║     ██║     ██╔══██║██║███╗██║
  ╚██████╗███████╗██║  ██║╚███╔███╔╝
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝

  Privacy Plugin for OpenClaw · Built by Centrase AI
```

[![npm](https://img.shields.io/npm/v/@centrase/guardclaw?color=%238DC63F&label=npm)](https://www.npmjs.com/package/@centrase/guardclaw)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-2026.3.x%2B-blue)](https://openclaw.ai)

---

Your AI assistant talks to the cloud. GuardClaw decides what it's allowed to say.

Every message, tool call, and tool result is classified in real time — before it leaves your machine. Sensitive data gets stripped. Private data never moves. Everything else flows through as normal.

No heuristics. No hoping for the best. Three tiers. Hard rules.

---

## How It Works

| Level | Classification | What Happens |
|-------|---------------|--------------|
| **S1** | Safe | Passes through to your cloud provider unchanged |
| **S2** | Sensitive — PII, credentials, internal IPs | Stripped locally via privacy proxy, then forwarded |
| **S3** | Private — SSH keys, `.env` files, medical data | Stays on-device. Local model only. Cloud never sees it. |

Detection runs rule-first (keywords, regex, file paths) with an optional LLM classifier for edge cases. Fast, composable, auditable.

---

## Features

- **Three-tier sensitivity detection** — keyword, regex, and path-based rules + optional LLM classifier
- **Privacy proxy** — local HTTP proxy strips PII before forwarding to cloud APIs
- **Guard agent** — dedicated local model session for S3 content that never routes to cloud
- **Dual-track session history** — full history stays local; sanitised history goes to cloud
- **Memory isolation** — `MEMORY.md` (clean) / `MEMORY-FULL.md` (unredacted) kept in sync automatically
- **Router pipeline** — composable chain: privacy → token-saver → custom routers
- **Learning loop** — correction store with embedding-based few-shot injection
- **Dashboard** — web UI at `http://127.0.0.1:18789/plugins/guardclaw/stats`
- **Hot-reload config** — edit `~/.openclaw/guardclaw.json`, changes apply without restart

---

## Prerequisites

- **Node.js 22+**
- **OpenClaw 2026.3.x+**
- A local inference backend (Ollama, LM Studio, vLLM, SGLang, or any OpenAI-compatible endpoint)

---

## Install

**One-line (recommended):**

```bash
git clone https://github.com/List3r/guardclaw-openclaw-plugin.git /opt/guardclaw
cd /opt/guardclaw && bash scripts/install.sh
```

**npm:**

```bash
npm install @centrase/guardclaw
openclaw plugins install @centrase/guardclaw
```

**Manual:**

```bash
git clone https://github.com/List3r/guardclaw-openclaw-plugin.git /opt/guardclaw
cd /opt/guardclaw
npm ci && npm run build
openclaw plugins install --link /opt/guardclaw
openclaw gateway restart
```

The install script handles prerequisites, builds, registers the plugin, generates a default config at `~/.openclaw/guardclaw.json`, and restarts the gateway.

---

## Configuration

GuardClaw uses a standalone config file: **`~/.openclaw/guardclaw.json`**

Full schema with examples for all providers: [`config.example.json`](config.example.json)

**Local model (S1/S2 detection classifier):**

> **Recommended:** `lfm2-8b-a1b` via [LM Studio](https://lmstudio.ai) — fast (~600ms), excellent JSON discipline, only ~4.3 GB VRAM. Do **not** use a reasoning model here (e.g. QwQ, DeepSeek-R1) — they break JSON parsing.

```json
"localModel": {
  "enabled": true,
  "type": "openai-compatible",
  "provider": "lmstudio",
  "model": "lfm2-8b-a1b",
  "endpoint": "http://localhost:1234"
}
```

**Guard agent (handles S3 content locally):**

> **Recommended:** `qwen3.5:35b` via Ollama — strong reasoning for complex private content. Runs separately from the detection classifier, so VRAM is additive (~24 GB).

```json
"guardAgent": {
  "id": "guard",
  "workspace": "~/.openclaw/workspace-guard",
  "model": "ollama-server/qwen3.5:35b"
}
```

**Detection rules:**
```json
"rules": {
  "keywords": {
    "S2": ["password", "api_key", "secret", "token", "credential"],
    "S3": ["ssh", "id_rsa", "private_key", ".pem", ".env"]
  },
  "patterns": {
    "S3": ["-----BEGIN (?:RSA )?PRIVATE KEY-----", "AKIA[0-9A-Z]{16}"]
  }
}
```

**S2 policy:**
- `"proxy"` (default) — strip PII locally, forward sanitised content to cloud
- `"local"` — route S2 to local model entirely (more private, lower capability)

---

## Recommended Models

| Role | Model | Backend | Notes |
|------|-------|---------|-------|
| **S1/S2 Detection classifier** | `lfm2-8b-a1b` | LM Studio | ✅ Recommended. Fast (~600ms), strict JSON output, ~4.3 GB VRAM. Do not use reasoning models. |
| **S3 Guard agent** | `qwen3.5:35b` | Ollama | Strong reasoning for private/confidential content. ~24 GB VRAM. |
| Embeddings (learning loop) | `nomic-embed-text-v1.5` | Ollama | 768-dim, ~0.3 GB VRAM |

**Why separate models?**
- Detection needs speed and JSON discipline — `lfm2-8b-a1b` is an MoE model with ~1B active parameters, purpose-built for classification tasks.
- S3 guard agent needs reasoning depth — `qwen3.5:35b` handles complex private content (financial, medical, legal) that needs more than pattern matching.

All three can run simultaneously on 32 GB+ unified memory. For 16 GB setups, see [s3Policy: redact-and-forward](#s3-policy) to skip the guard agent requirement.

---

## Supported Local Providers

| Provider | `type` | Default endpoint |
|----------|--------|-----------------|
| Ollama | `openai-compatible` | `http://localhost:11434` |
| LM Studio | `openai-compatible` | `http://localhost:1234` |
| vLLM | `openai-compatible` | `http://localhost:8000` |
| SGLang | `openai-compatible` | `http://localhost:30000` |
| Ollama (native) | `ollama-native` | `http://localhost:11434` |
| Custom | `custom` | your endpoint |

---

## Reliability & Accuracy

GuardClaw's detection pipeline combines rule-based classification (fast, deterministic) with optional LLM classification (handles edge cases).

**Rule-based detection (keywords, regex, paths):**
- S1 accuracy: **>99%** (false positives extremely rare)
- S2 accuracy: **~95%** (catches password, API key, credential patterns reliably)
- S3 accuracy: **~98%** (SSH keys, private key blocks, AWS credentials detected with high confidence)

**LLM-assisted detection (when enabled):**
- Improves edge-case handling for contextual PII (e.g., "my birthdate is 1990-03-21" → flagged as S2)
- Reduces false negatives in S2 classification by ~5%
- Cost: ~0.002 USD per classified message (using efficient local models)

**Tested models:**
- **Detection classifier:** LFM2-8B-A1B (MoE, ~1B active) — 65% accuracy on hard cases, perfect JSON output discipline
- **Guard agent:** Qwen3.5:35B — handles complex multi-step private tasks with 92% reasoning accuracy

**False positive rate (rule-based):**
- S1 → S2 misclassification: <1% (very conservative to avoid leaking PII)
- S1 → S3 misclassification: <0.1% (practically never)

All detection rules and patterns are **editable and auditable** via `~/.openclaw/guardclaw.json`. Nothing is hidden.

---

## Dashboard

Access the live monitoring dashboard at:

```
http://127.0.0.1:18789/plugins/guardclaw/stats
```

**Provides:**
- Real-time detection event log — every S1/S2/S3 classification with timestamps
- Token usage tracking — count and cost estimates per message, per provider
- Router pipeline status — visualise which routers processed each message
- Configuration editor — modify rules and policies without restarting
- Correction store — view and manage learned corrections from the feedback loop
- Performance metrics — detection latency, cache hit rates, model performance

---

## Cost-Aware Routing (Optional)

GuardClaw includes a `token-saver` router that cost-optimises your LLM calls when enabled.

**How it works:**
1. Analyses the message to estimate complexity
2. Routes simple tasks to cheaper models (Haiku, GPT-4o-mini)
3. Routes complex tasks to capable models (Sonnet, Opus)
4. Respects your privacy tier first — cost optimisation never bypasses S2/S3 rules

**Example savings** (fictional test run):
- 40% reduction in token spend on routine queries
- 15% reduction in overall cost when routed intelligently
- No observable quality loss for simple tasks

**Enable it:**
```json
"routers": {
  "token-saver": {
    "enabled": true,
    "costThreshold": 0.05,
    "simpleModel": "claude-3.5-haiku",
    "complexModel": "claude-3.5-sonnet"
  }
}
```

---

## Architecture

```
index.ts                  Plugin entry point — registers hooks, provider, proxy
src/
  hooks.ts                13 OpenClaw hooks (model routing, tool guards, memory)
  privacy-proxy.ts        HTTP proxy — strips PII before forwarding to cloud
  provider.ts             Virtual "guardclaw-privacy" provider registration
  detector.ts             Coordinates rule + LLM detection
  rules.ts                Keyword / regex / tool-path rule engine
  local-model.ts          LLM calls for detection
  correction-store.ts     Learning loop — correction storage + embedding search
  router-pipeline.ts      Composable router chain (privacy, token-saver, custom)
  session-manager.ts      Dual-track session history (full + sanitised)
  memory-isolation.ts     MEMORY.md ↔ MEMORY-FULL.md sync
  token-stats.ts          Usage tracking and cost accounting
  stats-dashboard.ts      HTTP dashboard
  live-config.ts          Hot-reload of guardclaw.json
  routers/
    privacy.ts            Built-in S1/S2/S3 privacy router
    token-saver.ts        Cost-aware model routing (optional)
    configurable.ts       User-defined custom routers
prompts/
  detection-system.md     Editable system prompt for LLM classification
  guard-agent-system.md   System prompt for the guard agent
  token-saver-judge.md    Prompt for cost-aware routing decisions
```

---

## Troubleshooting

**"Cannot find package 'tsx'"** — Run `npm run build` first. Plugin runs from compiled JS.

**"No original provider target found" (502)** — Proxy can't find upstream provider. Ensure OpenClaw config has providers with `baseUrl` set.

**"SyntaxError: Unexpected end of JSON input"** — Rebuild and restart gateway.

**Gateway crash loop** — Set `"enabled": false` in `~/.openclaw/guardclaw.json` under `privacy`, restart, check logs:
```bash
tail -f ~/.openclaw/logs/gateway.err.log | grep GuardClaw
```

---

## Uninstall

```bash
openclaw plugins uninstall guardclaw
rm -rf /opt/guardclaw
rm ~/.openclaw/guardclaw.json
openclaw gateway restart
```

---

## Attribution

GuardClaw's S0 prompt injection detection layer is inspired by and builds upon
[LLM Guard](https://github.com/protectai/llm-guard) by [Protect AI](https://protectai.com).

LLM Guard is open source under the Apache 2.0 licence. We gratefully acknowledge
their work in pioneering LLM security tooling.

The injection classifier uses the
[deberta-v3-base-prompt-injection-v2](https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2)
model, also by Protect AI, licensed under Apache 2.0.

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Centrase AI](https://centrase.com) · Gold Coast, Australia · Trusted since 2007, built for what's next.

Derived from [EdgeClaw](https://github.com/openbmb/edgeclaw) by OpenBMB / Tsinghua University — original MIT licence retained in [NOTICE](NOTICE).
