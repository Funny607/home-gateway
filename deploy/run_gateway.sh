#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENV_PYTHON="$PROJECT_DIR/.venv/bin/python"

cd "$PROJECT_DIR"
umask 077
mkdir -p runtime logs logs/apps

if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "Gateway virtual environment is missing; run deploy/install_launchd.sh" >&2
  exit 1
fi

exec "$VENV_PYTHON" -m uvicorn app.main:app \
  --host 127.0.0.1 \
  --port 8081 \
  --no-access-log \
  --proxy-headers \
  --forwarded-allow-ips 127.0.0.1,::1
