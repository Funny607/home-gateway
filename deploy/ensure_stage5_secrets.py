from __future__ import annotations

import secrets
import subprocess
import sys
from pathlib import Path

SERVICE = "com.yuanqilu.webui-home-gateway"
ACCOUNTS = ("desktop-approver-secret", "breakglass-secret")
ROOT = Path(__file__).resolve().parent.parent


def exists(account: str) -> bool:
    return subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", SERVICE, "-a", account],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def read(account: str) -> str:
    return subprocess.check_output(
        ["/usr/bin/security", "find-generic-password", "-w", "-s", SERVICE, "-a", account],
        text=True,
    ).strip()


def store(account: str, value: str) -> None:
    subprocess.run([
        "/usr/bin/security", "add-generic-password", "-U", "-s", SERVICE,
        "-a", account, "-w", value,
    ], check=True, stdout=subprocess.DEVNULL)


def main() -> None:
    if sys.platform != "darwin":
        raise SystemExit("ensure_stage5_secrets.py must run on macOS")
    for account in ACCOUNTS:
        if not exists(account):
            store(account, secrets.token_urlsafe(48))
            print(f"已生成 {account}。")
    if not exists("database-pepper"):
        if (ROOT / "runtime" / "gateway.sqlite3").exists() and exists("session-secret"):
            store("database-pepper", read("session-secret"))
            print("已从现有 session secret 初始化独立 database pepper。")
        else:
            store("database-pepper", secrets.token_urlsafe(48))
            print("已生成独立 database pepper。")


if __name__ == "__main__":
    main()
