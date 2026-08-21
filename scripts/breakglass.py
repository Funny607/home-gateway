from __future__ import annotations

import argparse
import getpass
import json
import subprocess
import urllib.request

SERVICE = "com.yuanqilu.webui-home-gateway"
BASE = "http://127.0.0.1:8081"


def verifier() -> str:
    return subprocess.check_output([
        "/usr/bin/security", "find-generic-password", "-w", "-s", SERVICE,
        "-a", "breakglass-secret",
    ], text=True).strip()


def call(path: str, payload: dict, headers: dict[str, str]) -> dict:
    request = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="Constrained local Gateway break-glass client")
    parser.add_argument("action", choices=["create-backup", "disable-external-api", "revoke-all-access"])
    parser.add_argument("--reason", default="local emergency operation")
    args = parser.parse_args()
    code = getpass.getpass("输入一个未使用的恢复码: ").strip().upper()
    activated = call(
        "/api/emergency/v1/activate", {"recovery_code": code, "reason": args.reason},
        {"X-Breakglass-Secret": verifier()},
    )
    token = activated["emergency_token"]
    result = call(
        f"/api/emergency/v1/{args.action}", {}, {"Authorization": f"BreakGlass {token}"}
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
