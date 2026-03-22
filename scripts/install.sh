#!/usr/bin/env bash
set -euo pipefail

# GuardClaw Install Script
# Usage: bash scripts/install.sh [--install-dir /path] [--no-restart]
#
# Default install dir: /opt/guardclaw
# The script expects to be run from the cloned repo root:
#   git clone https://github.com/list3r/guardclaw-openclaw-plugin /opt/guardclaw
#   cd /opt/guardclaw && bash scripts/install.sh

INSTALL_DIR="${INSTALL_DIR:-/opt/guardclaw}"
RESTART_GATEWAY=true

while [[ $# -gt 0 ]]; do
  case $1 in
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --no-restart) RESTART_GATEWAY=false; shift ;;
    --help) echo "Usage: bash scripts/install.sh [--install-dir /path] [--no-restart]"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

OPENCLAW_DIR="$HOME/.openclaw"
GUARDCLAW_CONFIG="$OPENCLAW_DIR/guardclaw.json"

echo "╔══════════════════════════════════════════════════╗"
echo "║  🛡️  GuardClaw Installer                         ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Prerequisites ──
echo "→ Checking prerequisites..."

if ! command -v node &>/dev/null; then
  echo "✗ Node.js not found. Install Node.js 22+ first."
  exit 1
fi

NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [[ "$NODE_MAJOR" -lt 22 ]]; then
  echo "✗ Node.js $NODE_MAJOR found, but 22+ is required."
  exit 1
fi
echo "  ✓ Node.js $(node --version)"

if ! command -v npm &>/dev/null; then
  echo "✗ npm not found."
  exit 1
fi
echo "  ✓ npm $(npm --version)"

if ! command -v openclaw &>/dev/null; then
  echo "✗ openclaw CLI not found. Install OpenClaw first: https://openclaw.ai"
  exit 1
fi
echo "  ✓ openclaw CLI found"
echo ""

# ── Detect run location ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$REPO_ROOT/package.json" ]] && grep -q "@centrase/guardclaw" "$REPO_ROOT/package.json" 2>/dev/null; then
  # Running from inside the cloned repo — install in-place
  PLUGIN_DIR="$REPO_ROOT"
  echo "→ Running from repo root: $PLUGIN_DIR"
else
  # Running standalone — clone to INSTALL_DIR
  echo "→ Install directory: $INSTALL_DIR"
  if [[ -d "$INSTALL_DIR" && -f "$INSTALL_DIR/package.json" ]]; then
    echo "  Directory exists — skipping clone"
    PLUGIN_DIR="$INSTALL_DIR"
  else
    echo "→ Cloning guardclaw-openclaw-plugin..."
    git clone --depth 1 https://github.com/list3r/guardclaw-openclaw-plugin "$INSTALL_DIR"
    PLUGIN_DIR="$INSTALL_DIR"
    echo "  ✓ Cloned to $INSTALL_DIR"
  fi
fi
echo ""

# ── Install dependencies ──
echo "→ Installing dependencies..."
cd "$PLUGIN_DIR"
npm ci --include=dev 2>&1 | tail -3
echo "  ✓ Dependencies installed"
echo ""

# ── Build ──
echo "→ Building..."
npm run build
echo "  ✓ Build complete (output: dist/)"
echo ""

# ── Register plugin ──
echo "→ Registering plugin with OpenClaw..."
openclaw plugins install --link "$PLUGIN_DIR" 2>&1 | tail -3 || true
echo "  ✓ Plugin registered"
echo ""

# ── Generate default config if missing ──
if [[ ! -f "$GUARDCLAW_CONFIG" ]]; then
  echo "→ Generating default guardclaw.json..."
  cat > "$GUARDCLAW_CONFIG" << 'CONFIGEOF'
{
  "privacy": {
    "enabled": true,
    "s2Policy": "proxy",
    "s3Policy": "local-only",
    "proxyPort": 8403,
    "checkpoints": {
      "onUserMessage": ["ruleDetector"],
      "onToolCallProposed": ["ruleDetector"],
      "onToolCallExecuted": ["ruleDetector"]
    },
    "rules": {
      "keywords": {
        "S2": ["password", "api_key", "secret", "credential", "auth_token"],
        "S3": ["ssh", "id_rsa", "private_key", ".pem", ".key", ".env", "master_password"]
      },
      "patterns": {
        "S2": [
          "\\b(?:10|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168)\\.\\d{1,3}\\.\\d{1,3}\\b",
          "(?:mysql|postgres|mongodb|redis)://[^\\s]+",
          "\\b(?:sk|key)-[A-Za-z0-9]{16,}\\b"
        ],
        "S3": [
          "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
          "AKIA[0-9A-Z]{16}"
        ]
      }
    },
    "localModel": {
      "enabled": true,
      "type": "openai-compatible",
      "provider": "ollama",
      "model": "qwen3.5:35b",
      "endpoint": "http://localhost:11434"
    },
    "guardAgent": {
      "id": "guard",
      "workspace": "~/.openclaw/workspace-guard",
      "model": "ollama-server/qwen3.5:35b"
    },
    "session": {
      "isolateGuardHistory": true,
      "baseDir": "~/.openclaw",
      "injectDualHistory": true,
      "historyLimit": 20
    }
  }
}
CONFIGEOF
  echo "  ✓ Config written to $GUARDCLAW_CONFIG"
  echo "  ⚠ Edit localModel.endpoint if Ollama is not on localhost"
else
  echo "→ Config exists at $GUARDCLAW_CONFIG (preserved)"
fi
echo ""

# ── Restart gateway ──
if $RESTART_GATEWAY; then
  echo "→ Restarting OpenClaw gateway..."
  if [[ "$(uname)" == "Darwin" ]]; then
    launchctl kickstart -k "gui/$(id -u)/ai.openclaw.gateway" 2>/dev/null || openclaw gateway restart 2>/dev/null || true
  else
    openclaw gateway restart 2>/dev/null || true
  fi
  echo "  ✓ Gateway restarted"
else
  echo "→ Skipping gateway restart (--no-restart)"
  echo "  Run: openclaw gateway restart"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  ✅ GuardClaw installed successfully!                            ║"
echo "║                                                                  ║"
echo "║  Config:    ~/.openclaw/guardclaw.json                           ║"
echo "║  Dashboard: http://127.0.0.1:18789/plugins/guardclaw/stats       ║"
echo "║  Docs:      https://github.com/list3r/guardclaw-openclaw-plugin  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
