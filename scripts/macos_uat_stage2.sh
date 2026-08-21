#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This acceptance script must run on the target Mac." >&2
  exit 1
fi
if [[ ! -x .venv/bin/python ]]; then
  echo "Run deploy/install_launchd.sh first." >&2
  exit 1
fi

echo "== Automated regression =="
GATEWAY_INSTALLED_UAT=1 ./scripts/test_stage2.sh

echo "== Config, Keychain, and database preflight =="
.venv/bin/python scripts/preflight.py

echo "== Local Mailer boundary =="
test -x /usr/bin/python3
test -f /Users/yuanqilu/dev/Local_Mailer/send_mail.py
echo "Local Mailer executable and script are present; no email was sent by this check."

echo "== Loopback binding =="
LISTENERS="$(lsof -nP -iTCP:8081 -sTCP:LISTEN 2>/dev/null || true)"
echo "$LISTENERS"
if [[ -z "$LISTENERS" ]]; then
  echo "Nothing is listening on TCP 8081." >&2
  exit 1
fi
if echo "$LISTENERS" | grep -Eq '\*:8081|0\.0\.0\.0:8081'; then
  echo "Gateway is exposed beyond loopback." >&2
  exit 1
fi
if ! echo "$LISTENERS" | grep -Eq '127\.0\.0\.1:8081'; then
  echo "Could not prove a loopback-only listener." >&2
  exit 1
fi

echo "== Local readiness =="
curl --silent --show-error --fail --max-time 5 http://127.0.0.1:8081/readyz
echo

echo "== HTTPS read-only acceptance =="
.venv/bin/python scripts/macos_uat.py "$@"

echo "Stage 2 Mac acceptance passed. Send a real test email explicitly from Settings → Notifications."
