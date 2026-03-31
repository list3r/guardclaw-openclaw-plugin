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

_(None yet)_
