#!/bin/bash
set -euo pipefail

CURRENT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MARKER="$CURRENT_DIR/runtime/previous_release_path.txt"
LABEL="com.yuanqilu.webui-home-gateway"
HELPER_LABEL="com.yuanqilu.webui-home-gateway.desktop-approver"

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [previous-release-directory]" >&2
  exit 2
fi
if [[ $# -eq 1 ]]; then
  PREVIOUS_DIR="$(cd "$1" && pwd)"
elif [[ -f "$MARKER" ]]; then
  PREVIOUS_DIR="$(sed -n '1p' "$MARKER")"
else
  echo "缺少上一版本路径；请显式传入旧版本目录。" >&2
  exit 1
fi
if [[ ! -x "$PREVIOUS_DIR/deploy/install_launchd.sh" || ! -f "$PREVIOUS_DIR/runtime/gateway.sqlite3" ]]; then
  echo "上一版本目录不完整: $PREVIOUS_DIR" >&2
  exit 1
fi

echo "将切回保留在旧目录中的原始数据库；Stage 5 之后产生的数据不会自动回写。"
launchctl bootout "gui/$(id -u)/$HELPER_LABEL" 2>/dev/null || true
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
if ! "$PREVIOUS_DIR/deploy/install_launchd.sh"; then
  echo "旧版重启失败，正在恢复 Stage 5 LaunchAgent…" >&2
  "$CURRENT_DIR/deploy/install_launchd.sh" || true
  exit 1
fi
