from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request

SERVICE = "com.yuanqilu.webui-home-gateway"
BASE = "http://127.0.0.1:8081"


def secret() -> str:
    return subprocess.check_output([
        "/usr/bin/security", "find-generic-password", "-w", "-s", SERVICE,
        "-a", "desktop-approver-secret",
    ], text=True).strip()


def call(path: str, key: str, payload: dict | None = None) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        BASE + path, data=body,
        headers={"X-Desktop-Approver-Secret": key, "Content-Type": "application/json"},
        method="GET" if payload is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def decide(item: dict) -> str:
    if item.get("approval_type") == "action":
        title = "Home Gateway 高风险操作"
        detail = (
            f"应用: {item.get('target_app')}\n能力: {item.get('capability')}\n"
            f"操作: {item.get('action_method')} {item.get('action_path')}\n\n"
            f"预览:\n{item.get('payload_preview') or '（无）'}\n\n"
            f"请求体 SHA-256:\n{item.get('body_sha256')}"
        )
    else:
        title = "Home Gateway 安全审批"
        capabilities = ", ".join(item.get("requested_capabilities") or []) or "（无）"
        detail = (
            f"类型: {item.get('approval_type')}\n目标: {item.get('target_app') or item.get('device_id')}\n"
            f"风险: {item.get('risk_level')}\n能力: {capabilities}\n原因: {item.get('reason') or '（无）'}"
        )
    script = """on run argv
display dialog (item 1 of argv) with title (item 2 of argv) buttons {"拒绝", "批准"} default button "拒绝" with icon caution
end run"""
    result = subprocess.run(
        ["/usr/bin/osascript", "-e", script, detail, title], capture_output=True, text=True
    )
    return "approve" if result.returncode == 0 and "批准" in result.stdout else "deny"


def main() -> None:
    key = secret()
    while True:
        try:
            for item in call("/api/approvals/v1/desktop-pending", key).get("approvals", []):
                call(
                    f"/api/approvals/v1/{item['approval_id']}/desktop-decision",
                    key, {"decision": decide(item)},
                )
        except (OSError, urllib.error.URLError, ValueError):
            pass
        time.sleep(3)


if __name__ == "__main__":
    main()
