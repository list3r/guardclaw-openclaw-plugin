# GuardClaw Feature Requests

## High Priority

### Docker `/run/secrets/` Path Detection (S2/S3 Auto-Classification)
**Status:** ✅ DONE | **Date:** 2026-03-31 | **Suggested by:** Kevin | **Completed:** 2026-03-31

**What was built:**
- Added path detection to `checkToolParams()` in `src/rules.ts`
- Any tool parameter matching `/run/secrets/*` or `/var/run/secrets/*` is now classified as S2 automatically
- Values from these paths are registered as tainted for the session (via existing taint store)
- All occurrences of tainted values are redacted in subsequent tool results before reaching the LLM
- Added "Docker Secrets Integration" section to README.md with Docker Compose and Kubernetes examples

**How it works:**
1. Agent runs tool with path `/run/secrets/db_password` → GuardClaw detects S2 immediately
2. Tool result value is extracted and registered in taint store
3. Future tool results: any occurrence of that value → `[REDACTED:TAINT]`
4. LLM never sees the actual secret value, even if it appears elsewhere in the session

**Files modified:**
- `src/rules.ts` — added Docker secrets path detection (lines in `checkToolParams()`)
- `README.md` — Docker Secrets Integration section with Docker Compose and Kubernetes examples

---

## Medium Priority

### `guardclaw secrets get` CLI — Owned Secret Retrieval
**Status:** Open | **Date:** 2026-03-31 | **Suggested by:** Kevin

A CLI tool where apps call `guardclaw secrets get --key db_password` instead of reading `/run/secrets/` directly. GuardClaw owns the retrieval, so it knows *exactly* which values are sensitive from the moment they're read — no path inference required.

**Why this is stronger than path-based detection:**
- Tracks sensitive values from first read, not from pattern matching after the fact
- Enables precise redaction: GuardClaw knows the exact string to suppress, not just "anything from this path"
- Works outside Docker too (keychain, Vault, env vars) — not tied to a specific secret storage mechanism

**Trade-off:** Requires GuardClaw to be a runtime dependency inside the container, not just an OpenClaw-level plugin. Adds coupling. Better suited to v2 when GuardClaw has a standalone binary.

---

### Value-Based Tracking (Taint Propagation)
**Status:** Open | **Date:** 2026-03-31 | **Suggested by:** Kevin (derived from secrets architecture discussion)

Once a secret value is known (via path rule or `guardclaw secrets get`), track that *value* across all subsequent tool results — not just the path it came from.

**Why:** If an app reads `/run/secrets/db_password` and the value is `hunter2`, GuardClaw should suppress `hunter2` wherever it appears in tool output — not just flag tool calls that reference the original path.

**Implementation:** Maintain a per-session "tainted values" set. Any tool result containing a tainted string → redact. Clear on session end.

---

## Backlog

### Prompt Caching / Session Cost Control
**Status:** Open | **Date:** 2026-03-31 | **Suggested by:** Kevin | **Reference:** messkan/prompt-cache

Two related concerns — cache LLM prompts to reduce costs, AND enforce hard session limits so a misconfigured agent can't run up a $400 bill.

**Prompt cache proxy (messkan/prompt-cache pattern):**
- HTTP proxy that caches identical LLM prompts and serves them from local storage
- Eliminates re-billing for repeated system prompts, static context, and repeating tool descriptions
- Natural fit for GuardClaw: already sits in the request path via privacy-proxy.ts — the token-saver router could incorporate this
- Cache key: hash of (model + system prompt + last N messages). Only cache deterministic responses (temp=0 or near-0)
- Estimated savings: 30–60% on session costs for heavy build sessions with stable system prompts

**Session cost limits (baked into client config):**
- Hard daily/monthly caps already exist in GuardClaw (budget-guard.ts), but LibreChat and other OpenClaw UIs don't enforce limits at the connection level
- Need: per-session token budget in the OpenClaw config (`agents.defaults.maxTokensPerSession`) so runaway cron agents or stuck loops can't burn through budget
- The $400 bill scenario: cron agent stuck in retry loop, no per-session cap, no circuit breaker
- Circuit breaker: if a session exceeds N tokens in M minutes (configurable), pause + alert rather than just block

**Implementation notes:**
- Cache store: SQLite or Redis (Redis preferred for multi-instance deployments)
- Privacy concern: cached prompts may contain S2/S3 content → cache must be encrypted at rest
  - Cache key: HMAC of content, cache value: AES-GCM encrypted with session-derived key
  - Never cache S3 content at all (only S1/S2 with encryption)
- GuardClaw integration: add cache check step in router-pipeline.ts before hitting the upstream provider
- Invalidation: TTL-based (24h default) + explicit invalidation on memory reset

**References:**
- messkan/prompt-cache — lightweight prompt caching proxy
- Notes 34 + 57 in Kevin's AI notes folder
- budget-guard.ts (existing spend tracking — extend with per-session limits)
