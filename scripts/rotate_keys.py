from __future__ import annotations

import argparse
import getpass
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config.loader import load_configs
from app.operations.service import OperationsService
from app.security.auth import PasswordService, load_auth_config, resolve_reference
from app.security.db import SecurityStore, now_ts
from app.security.recovery import RecoveryService
from app.security.totp import generate_secret, provisioning_uri

SERVICE = "com.yuanqilu.webui-home-gateway"


def store_key(account: str, value: str) -> None:
    subprocess.run([
        "/usr/bin/security", "add-generic-password", "-U", "-s", SERVICE,
        "-a", account, "-w", value,
    ], check=True, stdout=subprocess.DEVNULL)


def restart(*labels: str) -> None:
    domain = f"gui/{os.getuid()}"
    for label in labels:
        subprocess.run(["/bin/launchctl", "kickstart", "-k", f"{domain}/{label}"], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rotate Gateway Keychain secrets safely")
    parser.add_argument("key", choices=[
        "admin-password", "guest-password", "session", "desktop", "breakglass", "totp", "database-pepper",
    ])
    parser.add_argument("--invalidate-external-access", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    os.chdir(ROOT)
    gateway, _, _ = load_configs(ROOT / "configs")
    auth = load_auth_config(ROOT / "configs" / "auth.yaml")
    pepper = resolve_reference(auth.database_pepper_ref)
    store = SecurityStore(gateway.api_audit_db, pepper=pepper)

    if args.key in {"admin-password", "guest-password"}:
        first = getpass.getpass("输入新密码（至少 12 位）: ")
        second = getpass.getpass("再次输入: ")
        if first != second:
            raise SystemExit("两次输入不一致")
        account = "admin-password-hash" if args.key == "admin-password" else "guest-password-hash"
        store_key(account, PasswordService.hash_password(first))
        store.set_system_state("last_key_rotation", {"key": args.key, "at": now_ts(), "actor": "rotate_keys.py"})
        restart("com.yuanqilu.webui-home-gateway")
        print(f"{args.key} 已轮换。")
    elif args.key == "session":
        store_key("session-secret", secrets.token_urlsafe(48))
        store.set_system_state("last_key_rotation", {"key": args.key, "at": now_ts(), "actor": "rotate_keys.py"})
        restart("com.yuanqilu.webui-home-gateway")
        print("Session secret 已轮换，所有浏览器会话已失效。")
    elif args.key == "desktop":
        store_key("desktop-approver-secret", secrets.token_urlsafe(48))
        store.set_system_state("last_key_rotation", {"key": args.key, "at": now_ts(), "actor": "rotate_keys.py"})
        restart("com.yuanqilu.webui-home-gateway", "com.yuanqilu.webui-home-gateway.desktop-approver")
        print("桌面批准器密钥已轮换。")
    elif args.key == "breakglass":
        store_key("breakglass-secret", secrets.token_urlsafe(48))
        RecoveryService(store, verifier_secret="rotating").revoke_emergency_tokens()
        store.set_system_state("last_key_rotation", {"key": args.key, "at": now_ts(), "actor": "rotate_keys.py"})
        restart("com.yuanqilu.webui-home-gateway")
        print("Break-glass 验证密钥已轮换，活动应急 token 已撤销。")
    elif args.key == "totp":
        secret = generate_secret()
        store_key("totp-secret", secret)
        auth_path = ROOT / "configs" / "auth.yaml"
        text = auth_path.read_text(encoding="utf-8")
        reference = 'totp_secret_ref: "keychain:com.yuanqilu.webui-home-gateway:totp-secret"'
        if reference not in [line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")]:
            commented = f"# {reference}"
            if commented not in text:
                raise SystemExit("configs/auth.yaml 中缺少 TOTP Keychain 引用占位符")
            auth_path.write_text(text.replace(commented, reference, 1), encoding="utf-8")
        store.set_system_state("totp_last_counter", -1)
        store.set_system_state("last_key_rotation", {"key": args.key, "at": now_ts(), "actor": "rotate_keys.py"})
        restart("com.yuanqilu.webui-home-gateway")
        print("新 TOTP 密钥（仅显示一次）:")
        print(secret)
        print(provisioning_uri(secret, issuer=auth.totp_issuer, account=auth.totp_account))
    else:
        if not args.invalidate_external_access or args.confirm != "ROTATE-DATABASE-PEPPER":
            raise SystemExit("database-pepper rotation requires --invalidate-external-access --confirm ROTATE-DATABASE-PEPPER")
        operations = OperationsService(
            project_root=ROOT, config_dir=ROOT / "configs", log_dir=gateway.log_path,
            store=store, config=gateway.operations, release_version=(ROOT / "VERSION").read_text().strip(),
        )
        backup = operations.create_backup(reason="before database pepper rotation", actor="rotate_keys.py")
        previous_account = f"database-pepper-previous-{time.strftime('%Y%m%d-%H%M%S')}"
        store_key(previous_account, pepper)
        with store.transaction() as conn:
            for table in ("lease_record", "token_record", "grant_record", "approval_request", "trusted_device", "emergency_token", "recovery_code"):
                conn.execute(f"DELETE FROM {table}")
            conn.execute("DELETE FROM system_state WHERE state_key='totp_last_counter'")
        store.set_system_state("last_key_rotation", {
            "key": args.key, "at": now_ts(), "actor": "rotate_keys.py",
            "external_access_invalidated": True,
        })
        store_key("database-pepper", secrets.token_urlsafe(48))
        restart("com.yuanqilu.webui-home-gateway")
        print(f"Database pepper 已轮换；所有外部设备需重新注册。备份: {backup['filename']}")
        print(f"旧 pepper 已保存到 macOS Keychain 账户: {previous_account}")
        print("请随后运行 .venv/bin/python scripts/configure_recovery_codes.py")


if __name__ == "__main__":
    main()
