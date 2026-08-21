from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from pathlib import PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config.loader import load_configs
from app.operations.service import OperationsService
from app.security.auth import load_auth_config, resolve_reference
from app.security.db import SCHEMA_VERSION, SecurityStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline verified Gateway backup restore")
    parser.add_argument("backup")
    parser.add_argument("--restore-configs", action="store_true")
    parser.add_argument("--confirm", required=True, help="must be RESTORE")
    args = parser.parse_args()
    if args.confirm != "RESTORE":
        raise SystemExit("--confirm must equal RESTORE")
    os.chdir(ROOT)
    gateway, _, _ = load_configs(ROOT / "configs")
    auth = load_auth_config(ROOT / "configs" / "auth.yaml")
    store = SecurityStore(gateway.api_audit_db, pepper=resolve_reference(auth.database_pepper_ref))
    operations = OperationsService(
        project_root=ROOT, config_dir=ROOT / "configs", log_dir=gateway.log_path,
        store=store, config=gateway.operations, release_version=(ROOT / "VERSION").read_text().strip(),
    )
    source = Path(args.backup).expanduser().resolve()
    if source.parent != operations.backup_dir:
        raise SystemExit(f"backup must be inside {operations.backup_dir}")
    verified = operations.verify_backup(source.name)
    if int(verified.get("schema_version", -1)) != SCHEMA_VERSION:
        raise SystemExit(f"backup schema must be v{SCHEMA_VERSION}")

    label = "com.yuanqilu.webui-home-gateway"
    domain = f"gui/{os.getuid()}"
    subprocess.run(["/bin/launchctl", "bootout", f"{domain}/{label}"], check=False)
    try:
        operations.create_backup(reason="automatic pre-restore backup", actor="restore script")
        with tempfile.TemporaryDirectory(dir=gateway.runtime_path) as directory:
            stage = Path(directory)
            with zipfile.ZipFile(source, "r") as archive:
                archive.extract("gateway.sqlite3", stage)
                restored = stage / "gateway.sqlite3"
                check = sqlite3.connect(restored)
                try:
                    if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                        raise SystemExit("restored database failed integrity_check")
                    if int(check.execute("PRAGMA user_version").fetchone()[0]) != SCHEMA_VERSION:
                        raise SystemExit("restored database schema mismatch")
                    if check.execute("PRAGMA foreign_key_check").fetchone() is not None:
                        raise SystemExit("restored database failed foreign_key_check")
                finally:
                    check.close()

                staged_configs = stage / "configs"
                if args.restore_configs:
                    members = []
                    for name in archive.namelist():
                        parts = PurePosixPath(name).parts
                        if parts and parts[0] == "configs" and ".." not in parts:
                            members.append(name)
                    archive.extractall(stage, members)
                    load_configs(staged_configs)
                    load_auth_config(staged_configs / "auth.yaml")

                for suffix in ("-wal", "-shm"):
                    Path(str(gateway.api_audit_db) + suffix).unlink(missing_ok=True)
                os.replace(restored, gateway.api_audit_db)
                if args.restore_configs:
                    config_backup = ROOT / f"configs.pre-restore-{time.strftime('%Y%m%d-%H%M%S')}"
                    os.rename(ROOT / "configs", config_backup)
                    try:
                        os.rename(staged_configs, ROOT / "configs")
                    except Exception:
                        os.rename(config_backup, ROOT / "configs")
                        raise
    finally:
        plist = Path.home() / "Library/LaunchAgents/com.yuanqilu.webui-home-gateway.plist"
        subprocess.run(["/bin/launchctl", "bootstrap", domain, str(plist)], check=False)
        subprocess.run(["/bin/launchctl", "kickstart", "-k", f"{domain}/{label}"], check=False)
    print("恢复完成。请运行 curl --fail http://127.0.0.1:8081/readyz")


if __name__ == "__main__":
    main()
