#!/bin/zsh
set -e
cd "$(dirname "$0")"
echo "=== npm run build ==="
npm run build
echo ""
echo "=== npm test ==="
npm test
