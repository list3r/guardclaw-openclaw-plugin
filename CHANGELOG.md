# Changelog

All notable changes to GuardClaw are documented here.

---

## [1.7.0] — 2026-03-31

### Security — 19 audit findings resolved (all remaining open issues from v1.6.1 GCF audit)

**Group 1 — Critical/High**

- **GCF-003** *(High)*: Fixed async injection detection race. Injection enforcement moved into synchronous `tool_result_persist` via `runHeuristics()`. DeBERTa in `after_tool_call` retained for enhanced audit logging only.
- **GCF-014** *(High)*: Fixed pending-taint single-slot race. `_pending` in `taint-store.ts` changed from `Map<string, PendingTaint>` to `Map<string, PendingTaint[]>` (queue per session); concurrent secrets-mount reads no longer overwrite each other.
- **GCF-022** *(High)*: Pinned HuggingFace classifier model to verified commit SHA in `injection_classifier.py`. `PINNED_REVISIONS` dict prevents silent supply-chain substitution via mutable model updates.
- **GCF-015** *(High)*: Extended `GUARD_BASH_NETWORK_PATTERNS` to cover `aws`, `gsutil`, `az`, `docker push`, `git push` with remote URL, `ruby -e`, `php -r`, `nslookup`, `dig`.
- **GCF-016** *(Medium, Group 1 companion)*: `eval`, `exec`, `source` now blocked entirely in guard bash sessions — these builtins enable full bypass of all static network patterns.
- **GCF-004** *(Critical)*: `before_tool_call` now blocks tool execution when a cloud-model session parameter matches a secrets-mount path (`/run/secrets/`, `/var/run/secrets/`) or any configured S3 path pattern. Prevents cloud model from reading S3 content before taint/redaction can fire.

**Group 2 — Medium/High**

- **GCF-001** *(High)*: Added NFKD Unicode normalization and leet-speak substitution (`normalizeForDetection()`) in `rules.ts`. Applied to all keyword and regex pattern checks. Defeats homoglyph, fullwidth, combining-diacritic, and `p@ssw0rd`-style bypasses.
- **GCF-002** *(High)*: Added per-session 500-char rolling buffer (`appendToRollingBuffer`) in `session-state.ts`. `tool_result_persist` appends each result and re-runs `detectByRules` on the buffer, catching secrets chunked across consecutive tool results.
- **GCF-012** *(High)*: Taint store now uses LRU eviction instead of silent drop. On cap hit, oldest non-secrets-mount taint is evicted with a WARN log. Secrets-mount taints (higher trust) are never evicted.
- **GCF-006** *(Medium)*: Added modern credential patterns to `config.example.json` default S2/S3 rules: GitHub PAT (`ghp_`, `github_pat_`), Slack bot token (`xoxb-`), npm token (`npm_`), PyPI token (`pypi-`), Stripe live key (`sk_live_`, `rk_live_`), Azure SAS (`sv=20YY-`), AWS session token (`ASIA`).
- **GCF-008** *(Medium)*: All memory dual-write routing decisions in `hooks.ts` now use `isVerifiedGuardSession()` (registry check) instead of `isGuardSessionKey()` (pattern-only, spoofable).
- **GCF-024** *(Medium)*: `withConfigWriteLock()` Promise-chaining mutex moved to `live-config.ts` and exported. All `guardclaw.json` read-modify-write operations in both `hooks.ts` and `privacy-proxy.ts` are now serialized through it.
- **GCF-019** *(Medium)*: DeBERTa service host validated to loopback-only in `injection_classifier.py`. `--host 127.0.0.1` / `GUARDCLAW_DEBERTA_HOST=127.0.0.1` added to generated launchd plist and systemd unit in `install.sh`.
- **GCF-025** *(Medium)*: `syncAllMemoryToClean()` in `memory-isolation.ts` acquires an O_EXCL advisory lock (`~/.openclaw/memory-sync.lock`) before running. Concurrent callers skip the sync cycle and log a warning rather than racing.

**Group 3 — Low**

- **GCF-005** *(Low)*: Extended `isDangerousRegex()` in `rules.ts` to catch additional catastrophic-backtracking patterns: unbounded dot-repeat `(.*)+`, empty string alternation `(a|)+`, and non-capturing group alternation `(?:a|b*)+`.
- **GCF-011** *(Low)*: Injection log preview strings now pass through `redactSensitiveInfo()` before being written to the log file in both `appendInjectionLog` (hooks.ts) and `appendProxyInjectionLog` (privacy-proxy.ts).
- **GCF-013** *(Low)*: `MIN_TAINT_LENGTH` lowered from 8 to 4 in `taint-store.ts`, consistent with `secret-manager.ts`. Accepts marginally higher false-positive risk to prevent sub-8-char secrets (e.g. short API tokens, PINs) from bypassing taint tracking.
- **GCF-023** *(Medium)*: `npm audit --audit-level=high` added after `npm ci` in `install.sh`. Install fails if any high or critical vulnerabilities are found.
- **GCF-026** *(Low)*: Memory write Promises are now tracked per session in `_pendingMemoryWrites`. `session_end` and `before_reset` call `awaitPendingMemoryWrites()` before proceeding, ensuring no memory writes are lost on clean session teardown.

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
