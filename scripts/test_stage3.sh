#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests -v
