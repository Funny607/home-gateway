#!/bin/bash
set -euo pipefail

NEW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="com.yuanqilu.webui-home-gateway"

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [previous-release-directory]" >&2
  exit 2
fi

if [[ $# -eq 1 ]]; then
  OLD_DIR="$(cd "$1" && pwd)"
else
  CANDIDATES=(
    "$HOME/dev/gateway-releases/3.0.0/webui_home_gateway_stage3_security_v1"
    "$HOME/dev/gateway-releases/2.0.0/webui_home_gateway_stage2_uiux_v3"
  )
  OLD_DIR=""
  for candidate in "${CANDIDATES[@]}"; do
    if [[ -f "$candidate/runtime/gateway.sqlite3" ]]; then
      OLD_DIR="$candidate"
      break
    fi
  done
fi

if [[ -z "${OLD_DIR:-}" || ! -f "$OLD_DIR/runtime/gateway.sqlite3" || ! -x "$OLD_DIR/deploy/install_launchd.sh" ]]; then
  echo "找不到旧版 Gateway 数据库；请把旧版本目录作为参数传入。" >&2
  exit 1
fi
if [[ "$OLD_DIR" == "$NEW_DIR" ]]; then
  echo "旧目录和新目录不能相同。" >&2
  exit 1
fi
if [[ -e "$NEW_DIR/runtime/gateway.sqlite3" ]]; then
  echo "Stage 5 数据库已存在，拒绝覆盖: $NEW_DIR/runtime/gateway.sqlite3" >&2
  exit 1
fi

restore_previous_on_error() {
  status=$?
  trap - ERR
  echo "Stage 5 升级未完成，正在尝试重新启动旧版…" >&2
  "$OLD_DIR/deploy/install_launchd.sh" || true
  exit "$status"
}
trap restore_previous_on_error ERR

echo "停止当前 Gateway，并从只读旧目录创建一致性副本…"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
mkdir -p "$NEW_DIR/runtime" "$NEW_DIR/logs"

OLD_DB="$OLD_DIR/runtime/gateway.sqlite3" NEW_DB="$NEW_DIR/runtime/gateway.sqlite3" python3 - <<'PY'
import os
import sqlite3

source = sqlite3.connect(f"file:{os.environ['OLD_DB']}?mode=ro", uri=True, timeout=10)
target = sqlite3.connect(os.environ["NEW_DB"], timeout=10)
try:
    source.backup(target)
finally:
    target.close()
    source.close()
print("SQLite 一致性副本已创建。旧目录和旧数据库保持不变。")
PY

if [[ -f "$OLD_DIR/logs/events.jsonl" ]]; then
  cp -p "$OLD_DIR/logs/events.jsonl" "$NEW_DIR/logs/events.jsonl"
fi
printf '%s\n' "$OLD_DIR" > "$NEW_DIR/runtime/previous_release_path.txt"

echo "安装并启动 Stage 5…"
GATEWAY_UPGRADE_SOURCE="$OLD_DIR" "$NEW_DIR/deploy/install_launchd.sh"
trap - ERR
echo "升级完成。回滚命令: $NEW_DIR/deploy/rollback_to_previous.sh"
