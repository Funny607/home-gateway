from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config.loader import load_configs
from app.security.auth import load_auth_config, resolve_reference
from app.security.db import SecurityStore
from app.security.recovery import RecoveryService


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate one-time offline Gateway recovery codes")
    parser.add_argument("--ensure", action="store_true", help="generate only when no active code exists")
    parser.add_argument("--count", type=int, default=8)
    args = parser.parse_args()
    os.chdir(ROOT)
    gateway, _, _ = load_configs(ROOT / "configs")
    auth = load_auth_config(ROOT / "configs" / "auth.yaml")
    store = SecurityStore(gateway.api_audit_db, pepper=resolve_reference(auth.database_pepper_ref))
    service = RecoveryService(
        store,
        verifier_secret=(resolve_reference(auth.breakglass_secret_ref) if auth.breakglass_secret_ref else ""),
        token_ttl_seconds=gateway.operations.emergency_token_ttl_seconds,
    )
    if args.ensure and service.status()["active_recovery_codes"]:
        print("恢复码已经配置，保持不变。")
        return
    codes = service.generate_codes(count=args.count)
    print("\nHome Gateway 恢复码（每个只能使用一次）：")
    for code in codes:
        print(code)
    print("\n请立即保存到离线密码管理器或打印件。程序不会再次显示这些明文。")


if __name__ == "__main__":
    main()
