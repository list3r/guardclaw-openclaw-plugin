#!/usr/bin/env bash
set -euo pipefail

# GuardClaw — Post-Update Recovery Script
# Usage: bash ~/guardclaw-plugin/scripts/recover.sh
#
# Fixes broken state after OpenClaw updates that may:
#   - Delete /opt/edgeclaw or /opt/guardclaw
#   - Remove bundled extensions and leave stale config references
#   - Break the gateway startup

PLUGIN_DIR="${PLUGIN_DIR:-$HOME/guardclaw-plugin}"
OPENCLAW_CONFIG="$HOME/.openclaw/openclaw.json"
GUARDCLAW_CONFIG="$HOME/.openclaw/guardclaw.json"

echo "🛡️  GuardClaw Recovery"
echo ""

FIXES=0

# ── 1. Verify plugin source exists ──
if [[ ! -f "$PLUGIN_DIR/index.ts" ]]; then
  echo "✗ Plugin source not found at $PLUGIN_DIR"
  echo "  Clone it: git clone https://github.com/List3r/guardclaw-openclaw-plugin.git $PLUGIN_DIR"
  exit 1
fi
echo "✓ Plugin source: $PLUGIN_DIR"

# ── 2. Ensure dist/ exists ──
if [[ ! -f "$PLUGIN_DIR/dist/index.js" ]]; then
  echo "→ dist/ missing — rebuilding..."
  cd "$PLUGIN_DIR"
  npm ci --include=dev 2>&1 | tail -2
  npm run build
  echo "  ✓ Build complete"
  FIXES=$((FIXES + 1))
else
  echo "✓ Build: dist/index.js exists"
fi

# ── 3. Fix openclaw.json plugin paths ──
if [[ -f "$OPENCLAW_CONFIG" ]]; then
  # Remove stale paths and ensure ~/guardclaw-plugin is registered
  python3 -c "
import json, sys, os

f = '$OPENCLAW_CONFIG'
d = json.load(open(f))
plugins = d.setdefault('plugins', {})
load = plugins.setdefault('load', {})
paths = load.get('paths', [])
original = list(paths)

# Remove paths that don't exist on disk
valid = []
for p in paths:
    expanded = os.path.expanduser(p)
    if os.path.exists(expanded):
        valid.append(p)
    else:
        print(f'  Removed stale path: {p}')

# Ensure guardclaw-plugin is in the list
plugin_dir = '$PLUGIN_DIR'
if plugin_dir not in valid:
    valid.append(plugin_dir)
    print(f'  Added: {plugin_dir}')

if valid != original:
    load['paths'] = valid
    json.dump(d, open(f, 'w'), indent=2)
    print('  ✓ openclaw.json updated')
    sys.exit(1)  # signal that fixes were made
else:
    sys.exit(0)
" && echo "✓ Plugin paths: OK" || { echo "✓ Plugin paths: fixed"; FIXES=$((FIXES + 1)); }
else
  echo "✗ openclaw.json not found at $OPENCLAW_CONFIG"
fi

# ── 4. Verify guardclaw.json exists ──
if [[ ! -f "$GUARDCLAW_CONFIG" ]]; then
  echo "→ guardclaw.json missing — generating defaults..."
  cp "$PLUGIN_DIR/config.example.json" "$GUARDCLAW_CONFIG" 2>/dev/null || true
  echo "  ✓ Default config written (edit localModel settings)"
  FIXES=$((FIXES + 1))
else
  echo "✓ Config: guardclaw.json exists"
fi

# ── 5. Recreate /opt symlinks (convenience, not required) ──
if [[ ! -L "/opt/edgeclaw/extensions/guardclaw" ]] && [[ ! -d "/opt/edgeclaw/extensions/guardclaw" ]]; then
  echo "→ Recreating /opt/edgeclaw symlink (may need sudo)..."
  sudo mkdir -p /opt/edgeclaw/extensions 2>/dev/null && \
  sudo ln -sf "$PLUGIN_DIR" /opt/edgeclaw/extensions/guardclaw 2>/dev/null && \
  echo "  ✓ /opt/edgeclaw/extensions/guardclaw → $PLUGIN_DIR" || \
  echo "  ⚠ Skipped (no sudo). Not required — plugin loads from $PLUGIN_DIR"
  FIXES=$((FIXES + 1))
else
  echo "✓ Symlink: /opt/edgeclaw/extensions/guardclaw"
fi

# ── 6. Restart gateway ──
echo ""
if [[ $FIXES -gt 0 ]]; then
  echo "→ $FIXES fix(es) applied. Restarting gateway..."
  if [[ "$(uname)" == "Darwin" ]]; then
    launchctl kickstart -k "gui/$(id -u)/ai.openclaw.gateway" 2>/dev/null || \
    openclaw gateway restart 2>/dev/null || true
  else
    openclaw gateway restart 2>/dev/null || true
  fi
  echo "  ✓ Gateway restarted"
else
  echo "No fixes needed — everything looks good."
fi

echo ""
echo "Done. Dashboard: http://127.0.0.1:18789/plugins/guardclaw/stats"
