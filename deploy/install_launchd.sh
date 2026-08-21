#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLIST_TEMPLATE="$PROJECT_DIR/deploy/com.yuanqilu.webui-home-gateway.plist"
PLIST_TARGET="$HOME/Library/LaunchAgents/com.yuanqilu.webui-home-gateway.plist"
LABEL="com.yuanqilu.webui-home-gateway"
HELPER_TEMPLATE="$PROJECT_DIR/deploy/com.yuanqilu.webui-home-gateway.desktop-approver.plist"
HELPER_TARGET="$HOME/Library/LaunchAgents/com.yuanqilu.webui-home-gateway.desktop-approver.plist"
HELPER_LABEL="com.yuanqilu.webui-home-gateway.desktop-approver"

cd "$PROJECT_DIR"
umask 077
mkdir -p "$HOME/Library/LaunchAgents" runtime logs logs/apps
chmod 700 runtime logs

python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required")
print("Using Python", sys.version.split()[0])
PY

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install --requirement requirements.lock.txt
.venv/bin/python deploy/setup_secrets.py
.venv/bin/python scripts/preflight.py
.venv/bin/python scripts/configure_recovery_codes.py --ensure
GATEWAY_UPGRADE_SOURCE="${GATEWAY_UPGRADE_SOURCE:-}" .venv/bin/python scripts/record_deployment.py

PROJECT_DIR="$PROJECT_DIR" PLIST_TEMPLATE="$PLIST_TEMPLATE" PLIST_TARGET="$PLIST_TARGET" \
  .venv/bin/python - <<'PY'
import os
from pathlib import Path

source = Path(os.environ["PLIST_TEMPLATE"]).read_text(encoding="utf-8")
project = os.environ["PROJECT_DIR"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
Path(os.environ["PLIST_TARGET"]).write_text(source.replace("__PROJECT_DIR__", project), encoding="utf-8")
PY

PROJECT_DIR="$PROJECT_DIR" PLIST_TEMPLATE="$HELPER_TEMPLATE" PLIST_TARGET="$HELPER_TARGET" \
  .venv/bin/python - <<'PY'
import os
from pathlib import Path
source = Path(os.environ["PLIST_TEMPLATE"]).read_text(encoding="utf-8")
project = os.environ["PROJECT_DIR"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
Path(os.environ["PLIST_TARGET"]).write_text(source.replace("__PROJECT_DIR__", project), encoding="utf-8")
PY

chmod 700 deploy/run_gateway.sh
chmod 644 "$PLIST_TARGET" "$HELPER_TARGET"
plutil -lint "$PLIST_TARGET" "$HELPER_TARGET"
xattr -dr com.apple.quarantine "$PROJECT_DIR" 2>/dev/null || true
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootout "gui/$(id -u)" "$PLIST_TARGET" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_TARGET"
launchctl enable "gui/$(id -u)/$LABEL"
launchctl kickstart -k "gui/$(id -u)/$LABEL"
launchctl bootout "gui/$(id -u)/$HELPER_LABEL" 2>/dev/null || true
launchctl bootout "gui/$(id -u)" "$HELPER_TARGET" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$HELPER_TARGET"
launchctl enable "gui/$(id -u)/$HELPER_LABEL"
launchctl kickstart -k "gui/$(id -u)/$HELPER_LABEL"

echo "Installed and started: $LABEL"
echo "Local readiness: http://127.0.0.1:8081/readyz"
echo "Status: launchctl print gui/$(id -u)/$LABEL"
