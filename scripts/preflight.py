from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.config.loader import load_configs
from app.security.auth import PasswordService, load_auth_config, resolve_reference, resolve_session_secret
from app.security.db import SecurityStore


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    os.chdir(ROOT)
    gateway, apps, links = load_configs(ROOT / "configs")
    auth = load_auth_config(ROOT / "configs" / "auth.yaml")
    if gateway.listen_host not in {"127.0.0.1", "::1", "localhost"}:
        fail("Gateway is not bound to loopback")
    if gateway.notifications.recipient != "lu.yuanqi.2005@gmail.com":
        fail("Local Mailer recipient does not match the approved address")
    run_script = (ROOT / "deploy" / "run_gateway.sh").read_text(encoding="utf-8")
    if "--host 127.0.0.1" not in run_script or "0.0.0.0" in run_script:
        fail("deployment runner does not enforce loopback")
    for path in ROOT.rglob("*.py"):
        if any(part in {".venv", "runtime"} for part in path.parts):
            continue
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    session_secret = resolve_session_secret(auth)
    database_pepper = resolve_reference(auth.database_pepper_ref)
    if len(database_pepper) < 32:
        fail("database pepper must contain at least 32 characters")
    if auth.desktop_approver_secret_ref:
        desktop_secret = resolve_reference(auth.desktop_approver_secret_ref)
        if len(desktop_secret) < 32:
            fail("desktop approver secret must contain at least 32 characters")
    if auth.totp_secret_ref:
        if len(resolve_reference(auth.totp_secret_ref).replace(" ", "")) < 16:
            fail("TOTP secret is invalid")
    if auth.breakglass_secret_ref and len(resolve_reference(auth.breakglass_secret_ref)) < 32:
        fail("break-glass verifier must contain at least 32 characters")
    PasswordService(auth.users)
    store = SecurityStore(gateway.api_audit_db, pepper=database_pepper)
    report = store.integrity_report()
    if not report["ok"]:
        fail(f"database integrity check failed: {report}")
    missing_workdirs = [app.app_id for app in apps.values() if not Path(app.workdir).expanduser().is_dir()]
    print(f"Config OK: {len(apps)} apps, {len(links)} local links")
    print(f"Database OK: schema v{report['schema_version']}, foreign keys clean")
    if missing_workdirs:
        print("WARNING: app workdirs currently missing: " + ", ".join(missing_workdirs))
    if not Path(gateway.notifications.command).expanduser().is_file():
        print("WARNING: Local Mailer script currently missing: " + gateway.notifications.command)
    print("Security preflight passed.")


if __name__ == "__main__":
    main()
