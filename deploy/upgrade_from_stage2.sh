#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec "$PROJECT_DIR/deploy/upgrade_to_stage5.sh" "${1:-$HOME/dev/gateway-releases/2.0.0/webui_home_gateway_stage2_uiux_v3}"
