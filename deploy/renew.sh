#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="com.yuanqilu.webui-home-gateway"
HELPER_LABEL="com.yuanqilu.webui-home-gateway.desktop-approver"
cd "$PROJECT_DIR"

if [[ ! -x .venv/bin/python ]]; then
  echo "Virtual environment missing; run deploy/install_launchd.sh" >&2
  exit 1
fi

.venv/bin/python deploy/ensure_stage5_secrets.py
.venv/bin/python scripts/preflight.py
launchctl kickstart -k "gui/$(id -u)/$LABEL"
launchctl kickstart -k "gui/$(id -u)/$HELPER_LABEL"

for _ in {1..20}; do
  if curl --silent --fail --max-time 2 http://127.0.0.1:8081/readyz >/dev/null; then
    echo "Gateway is ready on loopback."
    exit 0
  fi
  sleep 1
done

echo "Gateway did not become ready; recent stderr:" >&2
tail -n 40 "$PROJECT_DIR/logs/launchd.stderr.log" 2>/dev/null || true
exit 1
