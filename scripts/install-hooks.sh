#!/usr/bin/env bash
# Install GuardClaw git pre-commit hook
# Runs security-check.sh before every commit and npm publish

set -euo pipefail

HOOK_FILE=".git/hooks/pre-commit"

cat > "$HOOK_FILE" << 'EOF'
#!/usr/bin/env bash
# GuardClaw pre-commit security gate
bash "$(git rev-parse --show-toplevel)/scripts/security-check.sh"
EOF

chmod +x "$HOOK_FILE"
echo "✅ GuardClaw pre-commit security hook installed at $HOOK_FILE"
echo "   Runs scripts/security-check.sh before every 'git commit'."
echo ""
echo "   To run manually: bash scripts/security-check.sh"
echo "   To bypass (emergency only): git commit --no-verify"
