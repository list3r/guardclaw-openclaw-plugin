#!/usr/bin/env bash
set -euo pipefail

# GuardClaw Install Script
# Usage: bash scripts/install.sh [--install-dir /path] [--no-restart] [--recover]
#
# Default install dir: ~/guardclaw-plugin (safe from OpenClaw updates)
# The script expects to be run from the cloned repo root:
#   git clone https://github.com/list3r/guardclaw-openclaw-plugin ~/guardclaw-plugin
#   cd ~/guardclaw-plugin && bash scripts/install.sh

INSTALL_DIR="${INSTALL_DIR:-$HOME/guardclaw-plugin}"
RESTART_GATEWAY=true

while [[ $# -gt 0 ]]; do
  case $1 in
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --no-restart) RESTART_GATEWAY=false; shift ;;
    --recover)
      # Shortcut: run the recovery script instead
      SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
      exec bash "$SCRIPT_DIR/recover.sh"
      ;;
    --help)
      echo "Usage: bash scripts/install.sh [--install-dir /path] [--no-restart] [--recover]"
      echo ""
      echo "Options:"
      echo "  --install-dir DIR   Install location (default: ~/guardclaw-plugin)"
      echo "  --no-restart        Skip gateway restart after install"
      echo "  --recover           Fix broken state after an OpenClaw update"
      exit 0
      ;;
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
    # GCF-020: Pin to a specific commit SHA to prevent supply-chain attacks.
    # Update EXPECTED_COMMIT when releasing a new version.
    EXPECTED_COMMIT="728f95361391c5bd6e18df87cf75e2b54a41e20a"
    git clone --depth 1 https://github.com/list3r/guardclaw-openclaw-plugin "$INSTALL_DIR"
    ACTUAL_COMMIT=$(git -C "$INSTALL_DIR" rev-parse HEAD)
    if [ "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT" ]; then
      echo ""
      echo "  ⚠️  SECURITY WARNING: Cloned commit does not match expected SHA."
      echo "     Expected: $EXPECTED_COMMIT"
      echo "     Got:      $ACTUAL_COMMIT"
      echo "     This may indicate the repository has been updated since this installer was built."
      echo "     Verify the new commit at: https://github.com/list3r/guardclaw-openclaw-plugin/commit/$ACTUAL_COMMIT"
      echo ""
      read -p "  Continue anyway? [y/N] " -n 1 -r
      echo ""
      if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "  Install aborted."
        rm -rf "$INSTALL_DIR"
        exit 1
      fi
    else
      echo "  ✓ Commit SHA verified: $ACTUAL_COMMIT"
    fi
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
# GCF-023: Fail install if any high/critical npm vulnerabilities are found.
echo "→ Running npm audit..."
if npm audit --audit-level=high 2>&1 | tail -5; then
  echo "  ✓ npm audit passed"
else
  echo "  ✗ npm audit found high/critical vulnerabilities. Review above and update deps, then re-run install."
  exit 1
fi
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

# ── Setup wizard ──
if [[ ! -f "$GUARDCLAW_CONFIG" ]]; then

  echo "╔══════════════════════════════════════════════════╗"
  echo "║  ⚙  Setup Wizard                                 ║"
  echo "╚══════════════════════════════════════════════════╝"
  echo ""

  # ── Detect Python early (needed for config writing) ──
  PYTHON_CMD_CFG=""
  for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
      PY_VER=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "0")
      if [[ "$PY_VER" -ge 3 ]]; then
        PYTHON_CMD_CFG="$cmd"
        break
      fi
    fi
  done

  # ── Detect RAM ──
  RAM_GB=0
  if [[ "$(uname)" == "Darwin" ]]; then
    RAM_GB=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 ))
  else
    MEM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
    RAM_GB=$(( MEM_KB / 1048576 ))
  fi
  [[ "$RAM_GB" -gt 0 ]] && echo "  System RAM: ${RAM_GB} GB"
  echo ""

  # ── Probe local model backends ──
  echo "→ Scanning for local model backends..."
  LOCAL_ENDPOINT=""
  LOCAL_PROVIDER=""

  _probe_url() { curl -sf --max-time 2 "$1" >/dev/null 2>&1; }

  if _probe_url "http://localhost:11434/api/tags"; then
    LOCAL_ENDPOINT="http://localhost:11434"
    LOCAL_PROVIDER="ollama"
    echo "  ✓ Ollama detected (port 11434)"
  elif _probe_url "http://localhost:1234/v1/models"; then
    LOCAL_ENDPOINT="http://localhost:1234"
    LOCAL_PROVIDER="lmstudio"
    echo "  ✓ LM Studio detected (port 1234)"
  elif _probe_url "http://localhost:8000/v1/models"; then
    LOCAL_ENDPOINT="http://localhost:8000"
    LOCAL_PROVIDER="vllm"
    echo "  ✓ vLLM detected (port 8000)"
  elif _probe_url "http://localhost:30000/v1/models"; then
    LOCAL_ENDPOINT="http://localhost:30000"
    LOCAL_PROVIDER="sglang"
    echo "  ✓ SGLang detected (port 30000)"
  else
    echo "  ⚠ No local backend detected."
    echo "  Supported: Ollama (:11434), LM Studio (:1234), vLLM (:8000), SGLang (:30000)"
    LOCAL_ENDPOINT="http://localhost:11434"
    LOCAL_PROVIDER="ollama"
  fi
  echo ""

  # ── List available Ollama models if present ──
  AVAILABLE_MODELS=""
  if [[ "$LOCAL_PROVIDER" == "ollama" ]] && _probe_url "http://localhost:11434/api/tags" && [[ -n "$PYTHON_CMD_CFG" ]]; then
    AVAILABLE_MODELS=$(curl -sf --max-time 3 "http://localhost:11434/api/tags" | \
      "$PYTHON_CMD_CFG" -c "
import sys, json
try:
  d = json.load(sys.stdin)
  print('\n'.join(m['name'] for m in d.get('models', [])))
except: pass
" 2>/dev/null)
    if [[ -n "$AVAILABLE_MODELS" ]]; then
      echo "  Available Ollama models:"
      echo "$AVAILABLE_MODELS" | while read -r m; do echo "    - $m"; done
      echo ""
    fi
  fi

  # ── Confirm / override endpoint ──
  read -r -p "  Local model endpoint [$LOCAL_ENDPOINT]: " _ep
  [[ -n "$_ep" ]] && LOCAL_ENDPOINT="$_ep"
  echo ""

  # ── Detection classifier model ──
  DEFAULT_DETECT_MODEL="qwen3.5:35b"
  if [[ "$RAM_GB" -gt 0 && "$RAM_GB" -lt 16 ]]; then
    DEFAULT_DETECT_MODEL="qwen3:8b"
    echo "  ⚠ Under 16 GB RAM — suggesting smaller detection model."
  fi
  echo "  Detection classifier: small, fast model for real-time S1/S2/S3 classification."
  echo "  Recommended: lfm2-8b-a1b (LM Studio) or a small Ollama model."
  echo "  Do NOT use a reasoning model here (e.g. QwQ, DeepSeek-R1) — they break JSON parsing."
  read -r -p "  Detection model [$DEFAULT_DETECT_MODEL]: " _dm
  DETECT_MODEL="${_dm:-$DEFAULT_DETECT_MODEL}"
  echo ""

  # ── Guard agent model ──
  DEFAULT_GUARD_MODEL="qwen3.5:35b"
  [[ "$RAM_GB" -gt 0 && "$RAM_GB" -lt 16 ]] && DEFAULT_GUARD_MODEL="qwen3:8b"
  echo "  Guard agent: handles S3 (private) tasks entirely on-device."
  echo "  Use your best available local model — it handles sensitive/confidential content."
  read -r -p "  Guard agent model [$DEFAULT_GUARD_MODEL]: " _gm
  GUARD_MODEL="${_gm:-$DEFAULT_GUARD_MODEL}"
  GUARD_AGENT_MODEL="${LOCAL_PROVIDER}-server/${GUARD_MODEL}"
  echo ""

  # ── S2 policy ──
  echo "  S2 policy — how sensitive-but-not-private data is handled:"
  echo "    proxy  (recommended) — strip PII locally, then forward sanitised content to cloud"
  echo "    local  — route S2 entirely to local model (more private, uses more VRAM)"
  read -r -p "  S2 policy [proxy]: " _s2
  case "${_s2:-proxy}" in
    local) S2_POLICY="local" ;;
    *)     S2_POLICY="proxy" ;;
  esac
  echo ""

  # ── OpenRouter API key ──
  echo "  OpenRouter API key enables model cost suggestions in the Advisor tab."
  read -r -p "  OpenRouter API key (press Enter to skip): " OR_KEY
  echo ""

  # ── Budget caps ──
  echo "  Set spend caps to get warnings when cloud API costs approach your limits."
  read -r -p "  Daily spend cap in USD, e.g. 5.00 (press Enter to skip): " DAILY_CAP
  read -r -p "  Monthly spend cap in USD, e.g. 50.00 (press Enter to skip): " MONTHLY_CAP
  echo ""

  echo "→ Writing guardclaw.json..."

  if [[ -n "$PYTHON_CMD_CFG" ]]; then
    export DETECT_MODEL GUARD_AGENT_MODEL LOCAL_ENDPOINT LOCAL_PROVIDER S2_POLICY OR_KEY DAILY_CAP MONTHLY_CAP GUARDCLAW_CONFIG
    "$PYTHON_CMD_CFG" -c "
import json, os

detect_model      = os.environ.get('DETECT_MODEL',      'qwen3.5:35b')
guard_agent_model = os.environ.get('GUARD_AGENT_MODEL', 'ollama-server/qwen3.5:35b')
endpoint          = os.environ.get('LOCAL_ENDPOINT',    'http://localhost:11434')
provider          = os.environ.get('LOCAL_PROVIDER',    'ollama')
s2_policy         = os.environ.get('S2_POLICY',         'proxy')
or_key            = os.environ.get('OR_KEY',            '')
daily_cap         = os.environ.get('DAILY_CAP',         '')
monthly_cap       = os.environ.get('MONTHLY_CAP',       '')
config_path       = os.environ.get('GUARDCLAW_CONFIG',  os.path.expanduser('~/.openclaw/guardclaw.json'))

advisor = {
  'enabled': True, 'checkIntervalWeeks': 2, 'minSavingsPercent': 20, 'minDiskSpaceGb': 10,
  'openrouter': {'enabled': True}, 'llmfit': {'enabled': True},
  'deberta': {'enabled': True, 'autoUpdate': True},
}
if or_key:
  advisor['openrouterApiKey'] = or_key

budget = {'enabled': False}
if daily_cap or monthly_cap:
  budget = {'enabled': True, 'warnAt': 80, 'action': 'warn'}
  if daily_cap:
    try: budget['dailyCap'] = float(daily_cap)
    except: pass
  if monthly_cap:
    try: budget['monthlyCap'] = float(monthly_cap)
    except: pass

cfg = {'privacy': {
  'enabled': True, 's2Policy': s2_policy, 's3Policy': 'local-only', 'proxyPort': 8403,
  'checkpoints': {
    'onUserMessage': ['ruleDetector'],
    'onToolCallProposed': ['ruleDetector'],
    'onToolCallExecuted': ['ruleDetector'],
  },
  'rules': {
    'keywords': {
      'S2': ['password', 'api_key', 'secret', 'credential', 'auth_token'],
      'S3': ['ssh', 'id_rsa', 'private_key', '.pem', '.key', '.env', 'master_password'],
    },
    'patterns': {
      'S2': [
        r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
        r'(?:mysql|postgres|mongodb|redis)://[^\s]+',
        r'\b(?:sk|key)-[A-Za-z0-9]{16,}\b',
      ],
      'S3': [
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        r'AKIA[0-9A-Z]{16}',
      ],
    },
  },
  'localModel': {'enabled': True, 'type': 'openai-compatible', 'provider': provider, 'model': detect_model, 'endpoint': endpoint},
  'guardAgent': {'id': 'guard', 'workspace': '~/.openclaw/workspace-guard', 'model': guard_agent_model},
  'session': {'isolateGuardHistory': True, 'baseDir': '~/.openclaw', 'injectDualHistory': True, 'historyLimit': 20},
  'modelAdvisor': advisor,
  'budget': budget,
}}
os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
with open(config_path, 'w') as f:
  json.dump(cfg, f, indent=2)
"
  else
    # Fallback: static config when Python is not available
    echo "  ⚠ Python 3 not found — using static defaults. Customise $GUARDCLAW_CONFIG after install."
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
    },
    "modelAdvisor": {
      "enabled": true,
      "checkIntervalWeeks": 2,
      "minSavingsPercent": 20,
      "minDiskSpaceGb": 10,
      "openrouter": { "enabled": true },
      "llmfit": { "enabled": true },
      "deberta": { "enabled": true, "autoUpdate": true }
    },
    "budget": { "enabled": false }
  }
}
CONFIGEOF
  fi

  echo "  ✓ Config written to $GUARDCLAW_CONFIG"

else
  echo "→ Config exists at $GUARDCLAW_CONFIG (preserved)"
fi
echo ""

# ── Injection classifier service ──
echo "╔══════════════════════════════════════════════════╗"
echo "║  🧠 DeBERTa Injection Classifier Service         ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  GuardClaw's S0 injection detection uses a local DeBERTa"
echo "  model (protectai/deberta-v3-base-prompt-injection-v2) running"
echo "  as a FastAPI service on port 8404."
echo ""
echo "  This is a small model (~180 MB) and is critical for catching"
echo "  prompt injection attacks before they reach the LLM."
echo ""

SETUP_CLASSIFIER=true
PYTHON_CMD=""
for cmd in python3 python; do
  if command -v "$cmd" &>/dev/null; then
    PY_VER=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "0")
    if [[ "$PY_VER" -ge 3 ]]; then
      PYTHON_CMD="$cmd"
      break
    fi
  fi
done

if [[ -z "$PYTHON_CMD" ]]; then
  echo "  ⚠ Python 3 not found — skipping injection classifier setup."
  echo "  Install Python 3.9+ and re-run: bash scripts/install.sh"
  SETUP_CLASSIFIER=false
else
  echo "  ✓ Python found: $($PYTHON_CMD --version)"
  echo ""
  read -r -p "  Set up DeBERTa injection classifier service? (recommended) [Y/n] " answer
  answer="${answer:-Y}"
  if [[ ! "$answer" =~ ^[Yy] ]]; then
    SETUP_CLASSIFIER=false
    echo "  Skipped. You can set it up later with:"
    echo "    bash $PLUGIN_DIR/scripts/install.sh --classifier-only"
  fi
fi

if $SETUP_CLASSIFIER; then
  echo ""
  echo "→ Installing Python dependencies (pinned versions — see scripts/requirements.txt)..."
  echo "  This may take a few minutes on first install (PyTorch is ~200 MB)."
  echo ""

  # GCF-021: Use pinned requirements file instead of --upgrade to prevent supply-chain attacks.
  if "$PYTHON_CMD" -m pip install --quiet -r "$PLUGIN_DIR/scripts/requirements.txt"; then
    echo "  ✓ Dependencies installed"
  else
    echo "  ✗ pip install failed. Try manually:"
    echo "    $PYTHON_CMD -m pip install fastapi uvicorn torch transformers"
    SETUP_CLASSIFIER=false
  fi
fi

if $SETUP_CLASSIFIER; then
  CLASSIFIER_SCRIPT="$PLUGIN_DIR/scripts/injection_classifier.py"

  # ── Create OS service ──
  if [[ "$(uname)" == "Darwin" ]]; then
    PLIST="$HOME/Library/LaunchAgents/ai.guardclaw.deberta.plist"
    echo "→ Installing launchd service → $PLIST"
    mkdir -p "$(dirname "$PLIST")"
    cat > "$PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>ai.guardclaw.deberta</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON_CMD</string>
    <string>$CLASSIFIER_SCRIPT</string>
  </array>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>        <true/>
  <key>StandardOutPath</key>  <string>$HOME/.openclaw/deberta.log</string>
  <key>StandardErrorPath</key><string>$HOME/.openclaw/deberta.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>GUARDCLAW_DEBERTA_PORT</key><string>8404</string>
    <key>GUARDCLAW_DEBERTA_HOST</key><string>127.0.0.1</string>
  </dict>
</dict>
</plist>
PLISTEOF
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load -w "$PLIST"
    echo "  ✓ Service installed and started (auto-starts on login)"
    echo "  Log: ~/.openclaw/deberta.log"

  else
    # Linux — systemd user service
    SVCDIR="$HOME/.config/systemd/user"
    SVCFILE="$SVCDIR/guardclaw-deberta.service"
    mkdir -p "$SVCDIR"
    echo "→ Installing systemd user service → $SVCFILE"
    cat > "$SVCFILE" << SVCEOF
[Unit]
Description=GuardClaw DeBERTa injection classifier
After=network.target

[Service]
ExecStart=$PYTHON_CMD $CLASSIFIER_SCRIPT
Restart=on-failure
RestartSec=5
Environment=GUARDCLAW_DEBERTA_PORT=8404
Environment=GUARDCLAW_DEBERTA_HOST=127.0.0.1
StandardOutput=append:$HOME/.openclaw/deberta.log
StandardError=append:$HOME/.openclaw/deberta.log

[Install]
WantedBy=default.target
SVCEOF
    systemctl --user daemon-reload
    systemctl --user enable --now guardclaw-deberta.service
    echo "  ✓ Service installed and started (auto-starts on login)"
    echo "  Log: ~/.openclaw/deberta.log"
    echo "  Manage: systemctl --user [status|restart|stop] guardclaw-deberta"
  fi

  # ── Wait for service to be ready ──
  echo ""
  echo "→ Waiting for classifier to come online (first run downloads the model)..."
  READY=false
  for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:8404/health >/dev/null 2>&1; then
      READY=true
      break
    fi
    printf "  [%d/60] waiting...\r" "$i"
    sleep 3
  done
  echo ""
  if $READY; then
    MODEL=$(curl -sf http://127.0.0.1:8404/health | "$PYTHON_CMD" -c "import sys,json; print(json.load(sys.stdin).get('model','?'))" 2>/dev/null || echo "?")
    echo "  ✓ Classifier ready (model: $MODEL)"
  else
    echo "  ⚠ Service did not respond within 3 minutes."
    echo "  It may still be downloading the model. Check: ~/.openclaw/deberta.log"
  fi
fi

echo ""

# ── Handle --classifier-only mode ──
if [[ "${1:-}" == "--classifier-only" ]]; then
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║  ✅ Injection classifier setup complete!                         ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  exit 0
fi

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
