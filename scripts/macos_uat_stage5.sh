#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

echo "== Stage 3-5 automated regression =="
GATEWAY_INSTALLED_UAT=1 ./scripts/test_stage5.sh
echo "== Configuration and database preflight =="
.venv/bin/python scripts/preflight.py
echo "== LaunchAgents =="
launchctl print "gui/$(id -u)/com.yuanqilu.webui-home-gateway" >/dev/null
launchctl print "gui/$(id -u)/com.yuanqilu.webui-home-gateway.desktop-approver" >/dev/null
echo "== Loopback readiness =="
curl --fail --show-error http://127.0.0.1:8081/readyz
echo
echo "== HTTPS acceptance =="
.venv/bin/python scripts/macos_uat.py
echo "Stage 5 Mac acceptance passed. Recovery drills remain explicit administrator actions."
