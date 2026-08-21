#!/bin/bash
set -euo pipefail

PLIST_TARGET="$HOME/Library/LaunchAgents/com.yuanqilu.webui-home-gateway.plist"
LABEL="com.yuanqilu.webui-home-gateway"
HELPER_TARGET="$HOME/Library/LaunchAgents/com.yuanqilu.webui-home-gateway.desktop-approver.plist"
HELPER_LABEL="com.yuanqilu.webui-home-gateway.desktop-approver"

launchctl bootout "gui/$(id -u)/$HELPER_LABEL" 2>/dev/null || true
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$PLIST_TARGET" "$HELPER_TARGET"

echo "Uninstalled: $LABEL"
