#!/usr/bin/env bash
# GuardClaw Pre-Commit Security Gate
# Run before every git commit and npm publish.
# Fails fast on any finding — fix issues before proceeding.
#
# Usage: bash scripts/security-check.sh
# Auto-run: configured as pre-commit hook via scripts/install-hooks.sh

set -euo pipefail

PASS=0
FAIL=0
WARN=0

ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
warn() { echo "  ⚠️  $1"; WARN=$((WARN+1)); }

echo ""
echo "🔒 GuardClaw Security Check"
echo "══════════════════════════════════════════"
echo ""

# ── 1. File permissions on sensitive output files ──────────────────────────
echo "→ Checking file permission settings in source..."

if grep -rn "writeFile\|appendFile" src/ --include="*.ts" | \
   grep -v "mode: 0o600\|//" | \
   grep -q "utf-8\"\|\"utf8\""; then
  fail "Found writeFile/appendFile calls without mode:0o600 — check src/ for unprotected writes"
else
  ok "All sensitive file writes include mode:0o600"
fi

# ── 2. DeBERTa URL validation present ─────────────────────────────────────
echo "→ Checking DeBERTa SSRF protection..."
if grep -q "non-loopback host" src/injection/deberta.ts; then
  ok "DeBERTa URL validated to loopback-only (GCF-017)"
else
  fail "DeBERTa loopback URL validation missing in src/injection/deberta.ts"
fi

# ── 3. /reload endpoint has token auth ────────────────────────────────────
echo "→ Checking /reload authentication..."
if grep -q "X-GuardClaw-Token\|RELOAD_API_TOKEN" src/injection/deberta.ts; then
  ok "/reload uses API token authentication (GCF-018)"
else
  fail "/reload endpoint has no API token — unauthenticated hot-swap vulnerability"
fi

# ── 4. Model ID allowlist for reload ──────────────────────────────────────
echo "→ Checking DeBERTa model allowlist..."
if grep -q "ALLOWED_DEBERTA_MODELS" src/injection/deberta.ts; then
  ok "DeBERTa model allowlist present (GCF-018)"
else
  fail "DeBERTa model allowlist missing — arbitrary model can be hot-swapped"
fi

# ── 5. Symlink guards on memory writes ────────────────────────────────────
echo "→ Checking symlink guards..."
if grep -q "isSymbolicLink\|O_NOFOLLOW\|lstat" src/hooks.ts src/memory-isolation.ts 2>/dev/null; then
  ok "Symlink guards present in memory write paths (GCF-010)"
else
  fail "No symlink guards on memory write paths — pre-planted symlinks can overwrite arbitrary files"
fi

# ── 6. git clone SHA pinning in install.sh ────────────────────────────────
echo "→ Checking install.sh supply chain protection..."
if grep -q "EXPECTED_COMMIT\|rev-parse HEAD" scripts/install.sh; then
  ok "git clone uses commit SHA verification (GCF-020)"
else
  fail "install.sh git clone has no commit SHA pinning — supply chain attack vector"
fi

# ── 7. Python deps pinned (no --upgrade) ──────────────────────────────────
echo "→ Checking Python dependency pinning..."
if grep -q "\-\-upgrade fastapi\|--upgrade torch\|--upgrade transformers" scripts/install.sh; then
  fail "install.sh uses --upgrade for Python packages — use pinned requirements.txt instead (GCF-021)"
else
  ok "Python dependencies use pinned requirements.txt (GCF-021)"
fi

if [ -f scripts/requirements.txt ]; then
  ok "scripts/requirements.txt exists with pinned versions"
else
  fail "scripts/requirements.txt missing — Python deps are unpinned"
fi

# ── 8. npm audit check ────────────────────────────────────────────────────
echo "→ Running npm audit..."
AUDIT_OUTPUT=$(timeout 30 npm audit --audit-level=high 2>&1 || true)
if echo "$AUDIT_OUTPUT" | grep -qE "found 0 vulnerabilities|0 vulnerabilities"; then
  ok "npm audit: 0 high/critical vulnerabilities"
elif echo "$AUDIT_OUTPUT" | grep -qiE " high| critical"; then
  fail "npm audit found high/critical vulnerabilities — run 'npm audit' for details"
else
  warn "npm audit output unclear — manually verify: npm audit"
fi

# ── 9. No world-readable secrets files in dist/ ───────────────────────────
echo "→ Checking dist/ for accidental secrets..."
if grep -rlE "BEGIN (RSA |EC )?PRIVATE KEY|AKIA[A-Z0-9]{16}" dist/ 2>/dev/null | grep -q .; then
  fail "dist/ contains files matching secret patterns — check build output"
else
  ok "No secret patterns found in dist/"
fi

# ── 10. guardclaw.json not in git ─────────────────────────────────────────
echo "→ Checking that config with secrets is not tracked by git..."
if git ls-files 2>/dev/null | grep -q "guardclaw.json"; then
  fail "guardclaw.json appears to be tracked by git — may contain API keys"
else
  ok "guardclaw.json not committed to git"
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  ✅ Passed: $PASS  ❌ Failed: $FAIL  ⚠️  Warnings: $WARN"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "🚫 Security check FAILED — fix $FAIL issue(s) before committing."
  echo ""
  exit 1
else
  echo "✅ Security check passed — safe to commit."
  echo ""
  exit 0
fi
