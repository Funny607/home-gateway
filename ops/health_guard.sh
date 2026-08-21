#!/bin/bash
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="$PROJECT_DIR/runtime/guard"
LOG_FILE="$PROJECT_DIR/logs/health-guard.log"
LOCK_DIR="$STATE_DIR/lock"
FAIL_FILE="$STATE_DIR/tunnel-failures"
RESTART_FILE="$STATE_DIR/tunnel-last-restart"
DOMAIN="gui/$(id -u)"
GATEWAY_LABEL="com.yuanqilu.webui-home-gateway"
TUNNEL_LABEL="com.cloudflare.cloudflared"
LOCAL_URL="http://127.0.0.1:8081/readyz"
PUBLIC_URL="https://dev.lu607.com/healthz"

/bin/mkdir -p "$STATE_DIR" "$PROJECT_DIR/logs"
if ! /bin/mkdir "$LOCK_DIR" 2>/dev/null; then
  exit 0
fi
trap '/bin/rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

log_event() {
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"
}

if [[ -f "$LOG_FILE" ]] && \
  [[ "$(/usr/bin/stat -f %z "$LOG_FILE" 2>/dev/null || printf 0)" -gt 1048576 ]]; then
  /usr/bin/tail -n 1000 "$LOG_FILE" > "$LOG_FILE.tmp"
  /bin/mv "$LOG_FILE.tmp" "$LOG_FILE"
fi

if ! /usr/bin/curl --silent --fail --connect-timeout 2 --max-time 4 \
  "$LOCAL_URL" >/dev/null 2>&1; then
  log_event "8081 健康检查失败，重启 Gateway"
  /bin/launchctl kickstart -k "$DOMAIN/$GATEWAY_LABEL" >/dev/null 2>&1 || \
    log_event "Gateway 重启命令失败"
  exit 0
fi

if /usr/bin/curl --silent --fail --connect-timeout 3 --max-time 8 \
  "$PUBLIC_URL" >/dev/null 2>&1; then
  printf '0\n' > "$FAIL_FILE"
  exit 0
fi

failures="$(/bin/cat "$FAIL_FILE" 2>/dev/null || printf 0)"
case "$failures" in
  ''|*[!0-9]*) failures=0 ;;
esac
failures=$((failures + 1))
printf '%s\n' "$failures" > "$FAIL_FILE"

if [[ "$failures" -lt 3 ]]; then
  exit 0
fi

now="$(date +%s)"
last_restart="$(/bin/cat "$RESTART_FILE" 2>/dev/null || printf 0)"
case "$last_restart" in
  ''|*[!0-9]*) last_restart=0 ;;
esac

# 最多每十分钟重启一次隧道，避免公网故障期间反复重启。
if ((now - last_restart < 600)); then
  exit 0
fi

log_event "公网连续 $failures 次检查失败，重启 Cloudflare Tunnel"
if /bin/launchctl kickstart -k "$DOMAIN/$TUNNEL_LABEL" >/dev/null 2>&1; then
  printf '%s\n' "$now" > "$RESTART_FILE"
  printf '0\n' > "$FAIL_FILE"
else
  log_event "Cloudflare Tunnel 重启命令失败"
fi
