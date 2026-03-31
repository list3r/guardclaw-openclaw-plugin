# Changelog

All notable changes to GuardClaw are documented here.

---

## [1.6.0] — 2026-03-31

### Added

**Value-based taint tracking (`src/taint-store.ts`)**
- New `TaintStore` module tracks exact secret values across all tool results in a session
- `registerTaint(sessionKey, value, source, sensitivity)` — registers a literal string as sensitive
- `redactTainted(sessionKey, text)` — replaces all tainted occurrences with `[REDACTED:TAINT]`
- `extractTaintValues(content)` — extracts individual values from multi-line secrets (env-var, bare-value, mixed formats)
- `isSecretsMountPath(filePath)` — detects `/run/secrets/*` and `/var/run/secrets/*` paths
- `markPendingTaint` / `consumePendingTaint` — bridge mechanism across `before_tool_call` → `tool_result_persist` hook boundary
- Per-session in-memory store, cleared on `session_end`. Toggle via `privacy.taintTracking.enabled`
- Cap: 200 tainted values per session, minimum length 8 chars (prevents false positives on short strings)

**Docker/Kubernetes secrets path detection (`src/rules.ts`)**
- Any tool parameter path matching `/run/secrets/*` or `/var/run/secrets/*` → auto-classified as S2
- Integrated with taint store: values from secrets mounts are extracted and registered automatically
- Covers both Docker (`/run/secrets/`) and Kubernetes (`/var/run/secrets/`) mount conventions
- Hard-coded rule (not config-dependent) — always on when GuardClaw is enabled

**Behavioural attestation (`src/behavioral-attestation.ts`, `src/behavioral-log.ts`)**
- Per-session tool call logging with redaction of sensitive parameters
- Attestation records tool name, sensitivity level, and sanitised parameters
- Used by stats dashboard and audit trail — never sent to cloud

**S3 content synthesis (`src/synthesis.ts`)**
- When `s3Policy: "synthesize"`, S3 tool results are summarised by the local model before cloud routing
- Produces a natural-language description instead of `[REDACTED]` placeholders
- Prompts: `prompts/s3-synthesis.md` (generate), `prompts/s3-verify.md` (verify quality)

**Model Advisor (`src/model-advisor.ts`)**
- Periodic checks (configurable, default 2 weeks) for cheaper OpenRouter alternatives
- Local model quality suggestions via LLMFit
- DeBERTa injection classifier auto-updates with hot-reload (no service restart)
- Dashboard Advisor tab with accept/dismiss, benchmark comparisons, and savings estimates

**Budget guardrails (`src/budget-guard.ts`)**
- Daily and monthly spend caps with live tracking
- Pre-request check in `before_model_resolve` blocks requests when cap is exceeded
- Post-request check in `llm_output` fires warning webhooks at configurable threshold %
- Dashboard Budget tab with progress bars and cost history

**Secret operations (`src/secret-ops.ts`)**
- `use_secret` tool handler — allows agents in guard sessions to retrieve and use secrets locally
- Integrated with macOS Keychain via `security find-generic-password`
- Auto-registers retrieved values in taint store to prevent any leakage

**Webhook support (`src/webhook.ts`)**
- Outbound webhooks for detection events, budget warnings, and response scan hits
- Configurable per-event type with optional shared secret signing

**Response scanning**
- Scans cloud LLM responses for accidentally echoed secrets, API keys, and PII
- Configurable action: `redact` (strip value) or `block` (replace entire response)

**Config schema (`src/config-schema.ts`)**
- Formal JSON schema for `~/.openclaw/guardclaw.json`
- Used by install script for validation and config migration

**FEATURE_REQUESTS.md**
- Tracks backlog: `guardclaw secrets get` CLI, value-based taint improvements, future roadmap

### Changed

- `src/hooks.ts` — 13 hooks now cover taint registration, behavioural logging, synthesis, budget checks, and response scanning
- `src/stats-dashboard.ts` — major dashboard expansion: Advisor tab, Budget tab, Attestation log, Access Control
- `src/types.ts` — extended with taint, synthesis, model advisor, and budget config types
- `src/injection/deberta.ts` — hot-reload support for auto-updates
- `scripts/injection_classifier.py` / `injection_server.py` — updated DeBERTa service with reload endpoint
- `scripts/install.sh` — config migration, OS service setup for DeBERTa, validation improvements
- `README.md` — Docker Secrets Integration section, Model Advisor docs, Budget guardrails, full architecture update
- `package.json` — version 1.6.0

### Fixed

- Taint values shorter than 8 characters are ignored (prevents false positives on common short strings)
- Pending taint state is always consumed (cleared) even when no values are extracted, preventing stale flags across tool calls

---

## [1.5.2] — 2026-03-27

- Response scanning, webhooks, and budget caps (initial implementation)

## [1.4.2] — 2026-03-26

- Token-saver: two-mode OpenRouter support

## [1.3.3] — 2026-03-24

- Security hardening, Discord false-positive fix, Access Control dashboard
- Guard Agent Keychain access with anti-exfiltration controls
- Block outbound network commands in guard session bash
- CVE-2026-33672 (picomatch) patched via overrides
