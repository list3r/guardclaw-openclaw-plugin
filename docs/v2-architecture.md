# GuardClaw v2 — Architecture Specification

**Status:** Approved
**Version:** 2.0.0
**Approved by:** Kevin Whitmore
**Date:** 2026-04-18
**Upgrade path:** Clean install only. No drop-in upgrade from v1.

---

## Overview

GuardClaw is an OpenClaw plugin that provides two independent privacy protection layers:

- **Inbound (S0):** Detects prompt injection and jailbreak attempts before they reach the model
- **Outbound (S1–S3):** Classifies outbound content by sensitivity level and routes accordingly

These pipelines operate independently. S0 runs on every inbound message. S1–S3 runs on every outbound message.

---

## 1. Privacy Levels

| Level | Direction | Meaning | Default action |
|---|---|---|---|
| S0 | Inbound | Injection / jailbreak detection | Allow / flag / block (configurable threshold) |
| S1 | Outbound | Public / non-sensitive | Passthrough — OpenClaw routes normally |
| S2 | Outbound | Sensitive (PII, credentials, health data) | Redact detectable patterns, forward sanitised |
| S3 | Outbound | Highly sensitive (financial, legal, medical records) | Block — or route to local provider |

**Important:** If all configured OpenClaw providers are local (e.g. Ollama on LAN), S2/S3 outbound routing protection is largely redundant — content never leaves the local network anyway. S0 inbound protection still runs regardless.

---

## 2. S0 — Inbound Injection Detection

Runs on every inbound message (user → model) before S1–S3 classification.

- **Model:** DeBERTa-v3 (local, lightweight, purpose-built for injection detection)
- **Detects:** Prompt injection, jailbreak patterns, indirect injection via tool results
- **Actions:** `allow` / `flag` (annotate and continue) / `block` (reject message)
- **Threshold:** Configurable confidence score (default: 0.85)
- **Independent of S1–S3** — a message can be S0-clean and S3-sensitive simultaneously

---

## 3. S1–S3 — Outbound Sensitivity Classification

### Detection pipeline

**Stage 1 — Rules (always runs, zero latency):**
- Keyword lists per sensitivity level (configurable)
- Regex patterns per sensitivity level (configurable)
- Tool-call inspection (file read, shell exec → elevates level)
- If result is unambiguously S2 or S3 → skip Stage 2

**Stage 2 — Local model classifier (runs when Stage 1 result is S1 or ambiguous):**
- Configured via `classifier` block
- Must resolve to a local endpoint — never cloud
- Warnings emitted at startup for undersized or thinking models (see Section 6)

Final level = max(Stage 1 result, Stage 2 result).

### S1 handling
Passthrough. GuardClaw does nothing. OpenClaw routes normally to whatever provider is configured.

### S2 handling
Rule-based redaction (regex + keyword patterns) strips detectable PII. Sanitised version forwarded to `s2ForwardTo` (default: OpenClaw default provider). Best-effort — not a guarantee. Every S2 forward is logged.

### S3 handling — decision tree

```
S3 detected
    │
    ├─ Local provider configured and healthy?
    │       │
    │       Yes → s3Mode: "respond"   → local model handles full response (cloud never sees content)
    │             s3Mode: "filter"    → local model sanitises → forward to cloud provider
    │             s3Mode: "synthesise"→ [BETA] local abstracts → cloud frameworks → local synthesises
    │
    └─ No local provider available
            │
            ├─ allowNonLocalForS3: false (default)
            │       → Redact with rules → forward to cloud + dashboard warning logged
            │
            └─ allowNonLocalForS3: true (explicit opt-in via dashboard)
                    → Redact with rules → forward to cloud
                    → ⚠️  WARNING logged every time: "S3 content forwarded to cloud provider"
```

---

## 4. S3 Modes

### `respond` (default when local provider available)
Local guard agent receives the full unredacted message and generates the complete response. Cloud never sees the content. Response quality depends entirely on the local model.

**Best for:** Strong privacy guarantee. Recommended when a 7B+ local model is available.

### `filter`
Local guard agent sanitises the message first. Sanitised version (with [REDACTED:TOKEN]) forwarded to the cloud provider. Cloud responds to the sanitised version. Tokens swapped back in the response where possible.

**Limitation:** If the specific sensitive value changes the meaning of the answer (e.g. $340k vs $3k tax liability), the cloud response will be less useful.

**Best for:** Situations where cloud response quality is required but some sanitisation is better than none.

### `synthesise` ⚠️ BETA
Three-step flow:
1. Local model abstracts the question — strips PII, preserves intent, generates a general version
2. Cloud model receives the abstract question and returns a reasoning framework
3. Local model synthesises a final response using the framework + full unredacted original message

Cloud never sees PII. User gets a response informed by cloud reasoning applied to their actual context.

**Requirement:** Local model must be ≥ 7B for acceptable synthesis quality.
**Toggle:** Enabled/disabled in dashboard. Off by default. Logs all three steps for inspection.

---

## 5. Provider System

### Base providers
GuardClaw references providers by alias from `openclaw.json`. Any inference backend OpenClaw supports works: Ollama, LM Studio, vLLM, any OpenAI-compatible endpoint. GuardClaw never needs updating when the inference stack changes.

### Additional providers
`guardclaw.json` can define providers not in `openclaw.json` — dedicated machines or models reserved exclusively for privacy inference. Registered at GuardClaw startup, never exposed to OpenClaw's general routing.

### Priority chain
`providers[]` is an ordered list. GuardClaw tries each in sequence, uses the first healthy one. Fallback is automatic and logged.

### Provider overrides
Per-alias model overrides without duplicating full provider config.

---

## 6. Health Checking

Runs at startup and every `healthCheck.intervalMs` (default: 30s).

Each provider is pinged with a lightweight endpoint check. Result: `healthy` or `unhealthy`.

- Only healthy providers are used for S3 routing
- If primary fails mid-session, falls to next in list immediately
- If all providers unhealthy → S3 falls to the no-local-provider path (redact-and-forward with warning)
- Health state is in-memory only — no persistence in v2

**Latency decomposition per provider:**
- `timeToFirstToken` — network + queue time (spiky vs baseline = busy; stable = slow model)
- `tokensPerSecond` — model throughput once responding
- If all providers on the same host slow simultaneously → network issue, not model issue

---

## 7. Locality Validation

A provider endpoint is **local** if it matches any of:
- `localhost`, `127.0.0.1`, `::1`
- RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Any CIDR in `localNetwork.trustedCidrs` (e.g. Tailscale `100.64.0.0/10`, WireGuard subnets)

Non-local providers cannot be used for S3 unless `allowNonLocalForS3: true` is set via the dashboard. When set, locality is no longer checked — the user has explicitly accepted the risk. Every S3 forward under this flag is audit-logged.

**GuardClaw appliance path:** A dedicated appliance on a LAN IP passes locality validation automatically. Add its subnet to `trustedCidrs` if it's on a non-RFC1918 range.

---

## 8. Classifier Quality Warnings

At startup, GuardClaw inspects the classifier model name and emits advisory warnings:

| Condition | Warning |
|---|---|
| Param count < 7B (inferred from name) | `"Classifier may misclassify — recommend 7B–14B non-thinking model"` |
| Thinking model pattern (`-r1`, `-thinking`, `qwq`, `-o1`, `deepseek-r`) | `"Thinking models not recommended for classification — high latency, no accuracy benefit"` |
| No classifier configured | `"No classifier set — rule-based detection only"` |

Optional benchmark (`classifier.runBenchmark: true`): ~20 labelled test messages run against the configured classifier at startup, accuracy score reported. Advisory only — does not block startup.

**Recommended classifier size:** 7B–14B, non-thinking, instruction-tuned. Sweet spot for accuracy vs latency.

---

## 9. Adaptive Provider Intelligence

### Metrics collected per provider (in-memory ring buffer, last 1000 events):

| Metric | What it tells you |
|---|---|
| `timeToFirstToken` | Network + queue latency |
| `tokensPerSecond` | Model throughput |
| `overrideRate` | % of classifications user corrected — quality proxy |
| `fallbackRate` | % of requests where this provider wasn't first choice |
| `classificationDist` | S1/S2/S3 ratio over time — drift detection |

### Provider scoring (advisory only in v2 — no auto-reorder):

```
score = (quality_weight   × (1 - override_rate))
      + (speed_weight     × normalized_latency_score)
      + (availability_weight × (1 - fallback_rate))
```

Default weights: quality 0.5 / availability 0.3 / speed 0.2. Configurable.

Scores surfaced in startup logs. Suggestions emitted when a lower-priority provider consistently outscores the primary. User decides whether to reorder — GuardClaw never auto-reorders in v2.

---

## 10. Learning Classifier

### Phase 1 — Passive logging (v2)

Every classification event logged locally:

```typescript
{
  timestamp: string,
  contentFingerprint: string,  // SimHash of classified segments — NOT raw content
  provider: string,
  model: string,
  classifierResult: "S1" | "S2" | "S3",
  stageReached: "rule" | "rule+model",
  latencyMs: number,
  userOverride: "S1" | "S2" | "S3" | null,  // ground truth when present
  ruleMatches: string[]                       // which rule names fired
}
```

**Content fingerprint:** SimHash applied to classified segments only (not full message). Enables pattern clustering without storing reconstructable content. All data stays local.

**User overrides are ground truth.** When a user corrects a classification, that signal is captured. This is the seed for future learning.

### Phase 2 — Rule refinement suggestions (v3)
Analyse override patterns against fingerprint clusters. Surface: *"Messages matching [pattern] are overridden S1→S3 in 80% of cases — add as S3 rule?"* User approves. Classifier improves through rule additions — interpretable, instant, no GPU required.

### Phase 3 — Fine-tuning (v4)
Use accumulated labelled data (classifications + user overrides) to fine-tune the local classifier. Organisation-specific sensitivity patterns outperform generic models. Data stays local. Fine-tuned model stays local.

**The Phase 1 logging that ships in v2 is the prerequisite for everything in v3 and v4.**

---

## 11. Dashboard

Dashboard references throughout this spec are **UI placeholders for a future workstream**.

v2 ships:
- Config file equivalents for all settings (see Section 12)
- Startup log output for all status, warnings, and provider health
- Structured log output for classification events, S3 forwards, and overrides

The config file is designed to be the source of truth that a future dashboard reads from and writes to. Every dashboard action maps to a config field — no dashboard-only state.

`allowNonLocalForS3` and `synthesise` beta toggle are config fields. The dashboard warning for `allowNonLocalForS3` is a v2.1 UI concern; in v2 the risk is documented in the config file comments.

---

## 12. Version Roadmap

| Feature | Version |
|---|---|
| Alias-only provider references + additionalProviders | v2 |
| Priority chain with health checking | v2 |
| Locality validation + allowNonLocalForS3 | v2 |
| S3 modes: respond, filter, synthesise (beta) | v2 |
| Classifier size + thinking model warnings | v2 |
| Phase 1 classification logging (SimHash + override capture) | v2 |
| Per-provider metrics + advisory scoring | v2 |
| Rule refinement suggestions from override patterns | v3 |
| Score-based auto-reorder (opt-in, stability-gated) | v3 |
| guardclaw-core extraction (appliance prereq) | v3 |
| GuardClaw appliance (standalone HTTP server) | v3/v4 |
| Phase 3 fine-tuning from local labelled data | v4 |
| Dashboard UI | v2.1+ |
| mTLS, central policy push | v4+ |

---

## 13. Breaking Changes from v1

| v1 | v2 |
|---|---|
| `guardAgent.model = "ollama/qwen3:14b"` | `providers[]` + `providerOverrides` |
| `guardAgent.provider = "ollama-remote"` | Single entry in `providers[]` |
| Hardcoded `"ollama"` fallback | No fallback — unconfigured = redact-and-forward with warning |
| Single provider, no priority chain | Ordered `providers[]` with health checking |
| No locality validation | Locality checked at startup against RFC1918 + trustedCidrs |
| No classification logging | Phase 1 logging enabled by default |
| S0 undefined | S0 = DeBERTa inbound injection classifier |
| No S3 modes | respond / filter / synthesise (beta) |

**Migration:** Translate old `guardAgent.provider` + `guardAgent.model` into a single-entry `providers[]` with an optional `providerOverrides` entry.
