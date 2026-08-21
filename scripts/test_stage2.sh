#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
export PYTHONDONTWRITEBYTECODE=1

PYTHON="${PYTHON:-$PROJECT_DIR/.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  echo "Missing .venv; run: python3 -m venv .venv && .venv/bin/pip install -r requirements.lock.txt" >&2
  exit 1
fi

"$PYTHON" -m unittest discover -s tests -p 'test_*.py' -v
