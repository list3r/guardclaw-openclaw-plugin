# GuardClaw — Claude Code Brief

## Working Rules

- **Read before editing:** Always read a file fully before modifying it. Before changing a function, grep for all callers first. Research before you edit.
- **Exact locations:** When referencing code, use file + line numbers (e.g. `src/index.ts:42`). Do not re-read files you already have in context.

## What You're Working On

GuardClaw is a production TypeScript privacy plugin for OpenClaw (an AI assistant framework).
It intercepts LLM tool calls and classifies/redacts sensitive data (S1/S2/S3 tiers) before
content reaches cloud providers. Published at `@centrase/guardclaw` on npm.

**Repo:** `/Users/centraseai/guardclaw-plugin/`
**Language:** TypeScript (Node.js 22, ESM, tsup build)
**Build:** `npm run build` — must pass before any commit
**Security gate:** `bash scripts/security-check.sh` — must pass before any commit
**Commit:** `git commit --no-verify -F /tmp/msg.txt` (pre-commit hook runs security-check — use --no-verify only after manually running the check and confirming it passes)

## Your Task: Fix All Remaining Security Findings

A white-hat security audit identified 26 findings. 6 were fixed in v1.6.1. You need to fix
all remaining open ones. The full audit is in `SECURITY-REVIEW.md`.

**Work in priority order. Fix, test, commit each group before moving to the next.**

---

## Open Findings — Work These in Order

### GROUP 1 — Short-term (fix first)

**GCF-003 — High | Async injection detection race**
- File: `src/hooks.ts`
- Problem: `after_tool_call` handlers (3b synthesis, 3c injection) are async and stash results
  into `_synthesisPendingQueue` / `_injectionPendingQueue`. `tool_result_persist` (sync) pops
  from these queues. No ordering guarantee — if `tool_result_persist` fires before the async
  handlers complete, injection detection is silently skipped.
- Fix: Move injection detection into `tool_result_persist` directly using `syncDetectByLocalModel`
  (already exists — it's a synchronous worker call). Remove the async injection stash pattern.

**GCF-014 — High | Pending-taint single-slot race**
- File: `src/taint-store.ts`
- Problem: `_pending` is `Map<string, PendingTaint>` — one slot per session. Concurrent tool
  calls both writing to `/run/secrets/` overwrite each other. Second tool result's values are
  never tainted.
- Fix: Change `_pending` to `Map<string, PendingTaint[]>` (queue per session). `markPendingTaint`
  pushes; `consumePendingTaint` shifts.

**GCF-022 — High | HuggingFace model not hash-pinned**
- File: `src/injection/deberta.ts`, `scripts/injection_classifier.py`
- Problem: Model downloaded from HuggingFace without pinning to a commit SHA. A mutable model
  update could introduce a backdoored classifier.
- Fix: Pin model to a specific revision SHA in the Python loader:
  `AutoModelForSequenceClassification.from_pretrained("protectai/deberta-v3-base-prompt-injection-v2", revision="<sha>")`
  Get current SHA from HuggingFace Hub API or model card.

**GCF-015 — High | Guard bash missing network patterns**
- File: `src/hooks.ts` — `GUARD_BASH_NETWORK_PATTERNS`
- Missing: `git push` with remote URL, `aws`, `gsutil`, `az`, `docker push`, `ruby -e`, `php -r`,
  DNS exfiltration via `nslookup`/`dig`, `eval`, `source`, `exec` builtins.
- Fix: Add regex patterns for each. Also block `eval`, `source`, `exec` entirely in guard sessions.

**GCF-004 — Critical | S3 late detection — add before_tool_call path checks**
- File: `src/hooks.ts` — `before_tool_call`
- Problem: S3 detection at `tool_result_persist` is too late — cloud model already active.
  Best mitigation: block tool execution when cloud-model session attempts to read S3 paths.
- Fix: In `before_tool_call`, check ALL tool params (not just exec tools) against S3 path patterns
  and secrets-mount paths. If S3 path found in a cloud-session tool param, block execution and
  return an error to the model instead of letting the read happen.

---

### GROUP 2 — Medium-term (fix second)

**GCF-001 — High | Unicode/homoglyph bypass**
- File: `src/rules.ts` — `checkKeywords()`, `checkPatterns()`
- Fix: `text.normalize('NFKD')` before all keyword and pattern matching. Add leet-speak
  normalisation: `@→a`, `0→o`, `3→e`, `1→i`.

**GCF-002 — High | Cross-turn secret chunking**
- File: `src/hooks.ts`, `src/session-state.ts`
- Fix: Maintain a per-session rolling buffer of last 500 chars of tool result text. On each
  `tool_result_persist`, append current content, trim to 500 chars, run full pattern detection
  on the buffer. Store buffer in session-state.ts.

**GCF-012 — High | Taint store flood (200-cap → false negatives)**
- File: `src/taint-store.ts`
- Fix: Change from silent drop to LRU eviction. When cap is hit: log WARN, evict the oldest
  entry. Separate cap for secrets-mount taints (higher-trust, never evict) vs S2/S3 tool-result
  taints (evictable).

**GCF-006 — Medium | Missing modern credential patterns**
- File: `config.example.json` — default S2/S3 patterns
- Missing patterns to add:
  - GitHub PAT: `ghp_[a-zA-Z0-9]{36}` and `github_pat_[a-zA-Z0-9_]{82}`
  - AWS session token: `ASIA[A-Z0-9]{16}`
  - Slack bot token: `xoxb-[0-9]+-[a-zA-Z0-9]+`
  - npm token: `npm_[a-zA-Z0-9]{36}`
  - Stripe live key: `sk_live_[a-zA-Z0-9]{24}`
  - Azure SAS: `sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&`
  - PyPI token: `pypi-[a-zA-Z0-9_-]{64,}`

**GCF-008 — Medium | isGuardSessionKey() spoofable**
- File: `src/hooks.ts` — search for `isGuardSessionKey(` calls
- Fix: Replace every remaining `isGuardSessionKey(sessionKey)` call used for trust decisions
  with `isVerifiedGuardSession(sessionKey)`. The latter checks the registry, not just the key pattern.

**GCF-024 — Medium | Config RMW race on guardclaw.json**
- File: `src/hooks.ts`, `src/privacy-proxy.ts` — auto-ban write
- Fix: Use `proper-lockfile` npm package (already likely available, or add it) to wrap all
  read-modify-write operations on `guardclaw.json`. Or centralise config mutation in a single
  module with an async queue/mutex.

**GCF-016 — Medium | Bash obfuscation bypasses guard patterns**
- File: `src/hooks.ts` — `isGuardNetworkCommand()`
- Fix: Block `eval`, `exec`, `source` entirely in guard bash sessions — these enable arbitrary
  code bypass of all static patterns. Add common base64-encoded tool names to patterns.

**GCF-019 — Medium | DeBERTa no explicit 127.0.0.1 bind in launchd/systemd**
- File: `scripts/install.sh` — launchd plist and systemd unit generation
- Fix: Add `--host 127.0.0.1` to uvicorn startup command in both plist and systemd unit.
  Also add API key env var to the service definition.

**GCF-025 — Medium | Memory sync TOCTOU (concurrent sessions)**
- File: `src/memory-isolation.ts` — `syncMemoryToClean()`
- Fix: Use `proper-lockfile` to create an exclusive lock (`~/.openclaw/memory-sync.lock`) around
  the full `syncAllMemoryToClean()` operation. Non-blocking: if lock is held, skip sync and log.

---

### GROUP 3 — Low priority (fix last)

**GCF-005 — Low | Incomplete ReDoS checker**
- File: `src/rules.ts` — `isDangerousRegex()`
- Fix: Add `safe-regex` npm package: `import safeRegex from 'safe-regex'`. Replace `isDangerousRegex`
  heuristic with `!safeRegex(pattern)` check.

**GCF-011 — Low | Plaintext previews in injection logs**
- File: `src/hooks.ts` — `appendInjectionLog()`, `src/privacy-proxy.ts` — `appendProxyInjectionLog()`
- Fix: Apply `redactSensitiveInfo(preview, config.redaction)` before writing the preview to the log.

**GCF-013 — Low | Min-length inconsistency (taint=8 vs secret-manager=4)**
- File: `src/taint-store.ts` — `MIN_TAINT_LENGTH`
- Fix: Lower `MIN_TAINT_LENGTH` from 8 to 4. Accept slightly higher false-positive risk from
  common short values. Document the decision.

**GCF-023 — Low | npm audit not in install.sh**
- File: `scripts/install.sh`
- Fix: Add `npm audit --audit-level=high` after `npm ci`. Fail install if high/critical found.

**GCF-026 — Low | Fire-and-forget memory write**
- File: `src/hooks.ts` — `syncMemoryWrite` call in `tool_result_persist`
- Fix: Track pending writes in a per-session Set. On `session_end` and `before_reset`, await
  any pending writes before proceeding. Log if any were still pending at that point.

---

## After All Fixes

1. Run `bash scripts/security-check.sh` — must show 0 failures
2. Run `npm run build` — must succeed
3. Run `npm test` if tests exist — must pass
4. Update `SECURITY-REVIEW.md` — mark each finding as FIXED with the fix description
5. Bump version to `1.7.0` in `package.json`
6. Update `CHANGELOG.md` with the security fixes
7. Commit with `git commit --no-verify -F /tmp/msg.txt`
8. Tag: `git tag v1.7.0`
9. Push: `git push origin main && git push origin v1.7.0`
10. Publish: `npm publish --access public`

---

## Architecture Reference

```
src/
  hooks.ts          — 13 OpenClaw hooks (main interception logic)
  rules.ts          — keyword/regex/path classification engine
  taint-store.ts    — value-based secret taint tracking
  guard-agent.ts    — S3 session isolation logic
  session-state.ts  — per-session state store
  memory-isolation.ts — MEMORY.md ↔ MEMORY-FULL.md sync
  injection/
    deberta.ts      — DeBERTa classifier client
    index.ts        — injection detection coordinator
  privacy-proxy.ts  — HTTP proxy for S2 desensitisation
  secret-manager.ts — macOS Keychain secret tracking
config.example.json — default rule config (update credential patterns here)
scripts/
  install.sh              — install script (fix service binding, add npm audit)
  install-hooks.sh        — git hook installer
  security-check.sh       — pre-commit security gate
  injection_classifier.py — DeBERTa FastAPI service (fix HuggingFace pin here)
  requirements.txt        — pinned Python deps
SECURITY-REVIEW.md        — full audit findings (update as you fix)
```

## Important Rules

- **Build must pass** before any commit: `npm run build`
- **Security check must pass** before any commit: `bash scripts/security-check.sh`
- **Never commit secrets, API keys, or guardclaw.json**
- Write short, targeted commits — one group of related fixes per commit
- Keep TypeScript strict — no `any` without a comment explaining why
- All new file writes must use `{ encoding: 'utf-8', mode: 0o600 }`
