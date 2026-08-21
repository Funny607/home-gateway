from __future__ import annotations

import getpass
import argparse
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.security.auth import PasswordService


SERVICE = "com.yuanqilu.webui-home-gateway"
RESET_EXISTING = False


def keychain_exists(account: str) -> bool:
    result = subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", SERVICE, "-a", account],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def store(account: str, value: str) -> None:
    subprocess.run(
        ["/usr/bin/security", "add-generic-password", "-U", "-s", SERVICE, "-a", account, "-w", value],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def read(account: str) -> str:
    return subprocess.check_output(
        ["/usr/bin/security", "find-generic-password", "-w", "-s", SERVICE, "-a", account],
        text=True,
    ).strip()


def password_hash(account: str, label: str) -> None:
    if keychain_exists(account):
        if not RESET_EXISTING:
            print(f"{label} 已存在，保持不变。")
            return
    while True:
        first = getpass.getpass(f"输入 {label}（至少 12 位）: ")
        second = getpass.getpass("再次输入: ")
        if first != second:
            print("两次输入不一致。")
            continue
        try:
            encoded = PasswordService.hash_password(first)
        except ValueError as exc:
            print(exc)
            continue
        store(account, encoded)
        return


def value_secret(account: str, prompt: str, default: str = "") -> None:
    if keychain_exists(account):
        if not RESET_EXISTING:
            print(f"{prompt} 已存在，保持不变。")
            return
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip() or default
    if not value:
        raise SystemExit(f"{prompt} 不能为空")
    store(account, value)


def main() -> None:
    global RESET_EXISTING
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset-existing", action="store_true")
    RESET_EXISTING = parser.parse_args().reset_existing
    if sys.platform != "darwin":
        raise SystemExit("setup_secrets.py must run on macOS")
    if not keychain_exists("session-secret"):
        store("session-secret", secrets.token_urlsafe(48))
        print("已生成 Gateway session secret。")
    if not keychain_exists("database-pepper"):
        if (ROOT / "runtime" / "gateway.sqlite3").exists():
            store("database-pepper", read("session-secret"))
            print("已从现有 session secret 初始化独立 database pepper，以保持旧设备凭据有效。")
        else:
            store("database-pepper", secrets.token_urlsafe(48))
            print("已生成独立 database pepper。")
    if not keychain_exists("desktop-approver-secret"):
        store("desktop-approver-secret", secrets.token_urlsafe(48))
        print("已生成本机批准器密钥。")
    if not keychain_exists("breakglass-secret"):
        store("breakglass-secret", secrets.token_urlsafe(48))
        print("已生成本机 break-glass 验证密钥。")
    password_hash("admin-password-hash", "管理员密码")
    password_hash("guest-password-hash", "guest 密码")
    value_secret("qbt-host", "qBittorrent 本地地址", "http://127.0.0.1:8080")
    value_secret("qbt-username", "qBittorrent 用户名")
    if not keychain_exists("qbt-password") or RESET_EXISTING:
        password = getpass.getpass("qBittorrent 密码: ")
        if not password:
            raise SystemExit("qBittorrent 密码不能为空")
        store("qbt-password", password)
    print("所有秘密均已写入登录用户的 macOS Keychain。")


if __name__ == "__main__":
    main()
