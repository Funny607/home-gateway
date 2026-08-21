from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from app.config.schema import OperationsConfig
from app.security.db import SecurityStore, now_ts


REDACT = re.compile(
    r"(?i)(authorization|cookie|password|secret|token|credential)(\s*[:=]\s*)([^\s,;]+)"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class OperationsService:
    def __init__(
        self,
        *,
        project_root: Path,
        config_dir: Path,
        log_dir: Path,
        store: SecurityStore,
        config: OperationsConfig,
        release_version: str,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.config_dir = Path(config_dir).resolve()
        self.log_dir = Path(log_dir).resolve()
        self.store = store
        self.config = config
        self.release_version = release_version
        self.backup_dir = Path(config.backup_dir).resolve()
        self.diagnostic_dir = Path(config.diagnostic_dir).resolve()
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.diagnostic_dir.mkdir(parents=True, exist_ok=True)

    def _safe_child(self, root: Path, filename: str) -> Path:
        candidate = (root / Path(filename).name).resolve()
        if candidate.parent != root:
            raise ValueError("path escapes managed operations directory")
        return candidate

    def create_backup(self, *, reason: str, actor: str) -> dict[str, Any]:
        stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000_000:09d}"
        final = self.backup_dir / f"gateway-backup-{stamp}.zip"
        with tempfile.TemporaryDirectory(dir=self.backup_dir) as directory:
            stage = Path(directory)
            database = stage / "gateway.sqlite3"
            source = sqlite3.connect(str(self.store.db_path), timeout=10)
            target = sqlite3.connect(str(database), timeout=10)
            try:
                source.backup(target)
            finally:
                target.close()
                source.close()
            config_copy = stage / "configs"
            shutil.copytree(self.config_dir, config_copy)
            files = [database, *sorted(path for path in config_copy.rglob("*") if path.is_file())]
            manifest = {
                "format": 1,
                "created_at": now_ts(),
                "created_by": actor[:120],
                "reason": reason[:500],
                "release_version": self.release_version,
                "schema_version": self.store.integrity_report()["schema_version"],
                "files": {
                    str(path.relative_to(stage)): {"size": path.stat().st_size, "sha256": sha256_file(path)}
                    for path in files
                },
            }
            (stage / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            temporary = final.with_suffix(".zip.tmp")
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in sorted(stage.rglob("*")):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(stage)))
            os.replace(temporary, final)
        self.store.set_system_state("operations_last_backup", {
            "filename": final.name, "created_at": manifest["created_at"], "reason": reason[:500]
        })
        self._enforce_retention()
        result = {"filename": final.name, "size": final.stat().st_size, "sha256": sha256_file(final), **manifest}
        self.audit_operation("backup", actor=actor, success=True, raw={
            "filename": final.name, "reason": reason[:500], "sha256": result["sha256"],
        })
        return result

    def _enforce_retention(self) -> None:
        files = sorted(self.backup_dir.glob("gateway-backup-*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in files[self.config.backup_retention_count:]:
            path.unlink(missing_ok=True)

    def list_backups(self) -> list[dict[str, Any]]:
        result = []
        for path in sorted(self.backup_dir.glob("gateway-backup-*.zip"), reverse=True):
            try:
                verified = self.verify_backup(path.name)
            except Exception as exc:
                verified = {"ok": False, "error": str(exc)}
            result.append({
                "filename": path.name, "size": path.stat().st_size,
                "modified_at": int(path.stat().st_mtime), "verification": verified,
            })
        return result

    def verify_backup(self, filename: str) -> dict[str, Any]:
        path = self._safe_child(self.backup_dir, filename)
        if not path.is_file():
            raise FileNotFoundError("backup not found")
        with zipfile.ZipFile(path, "r") as archive:
            names = set(archive.namelist())
            if "manifest.json" not in names or "gateway.sqlite3" not in names:
                raise ValueError("backup is missing manifest or database")
            manifest = json.loads(archive.read("manifest.json"))
            for name, expected in manifest.get("files", {}).items():
                if name not in names:
                    raise ValueError(f"backup member missing: {name}")
                data = archive.read(name)
                if len(data) != int(expected["size"]):
                    raise ValueError(f"backup member size mismatch: {name}")
                if hashlib.sha256(data).hexdigest() != expected["sha256"]:
                    raise ValueError(f"backup member checksum mismatch: {name}")
        return {
            "ok": True, "filename": path.name, "archive_sha256": sha256_file(path),
            "created_at": manifest.get("created_at"), "release_version": manifest.get("release_version"),
            "schema_version": manifest.get("schema_version"),
        }

    def backup_path(self, filename: str) -> Path:
        path = self._safe_child(self.backup_dir, filename)
        if not path.is_file() or not path.name.startswith("gateway-backup-") or path.suffix != ".zip":
            raise FileNotFoundError("backup not found")
        return path

    def create_diagnostic_bundle(self, *, actor: str) -> dict[str, Any]:
        stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000_000:09d}"
        final = self.diagnostic_dir / f"gateway-diagnostics-{stamp}.zip"
        report = {
            "created_at": now_ts(), "created_by": actor[:120], "release_version": self.release_version,
            "platform": platform.platform(), "python": platform.python_version(),
            "database": self.store.integrity_report(),
            "external_api_disabled": bool(self.store.get_system_state("external_api_disabled", False)),
            "last_backup": self.store.get_system_state("operations_last_backup", {}),
        }
        launchd = "unavailable"
        if platform.system() == "Darwin":
            result = subprocess.run(
                ["/bin/launchctl", "print", f"gui/{os.getuid()}/com.yuanqilu.webui-home-gateway"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            launchd = (result.stdout or result.stderr)[-20000:]
        with zipfile.ZipFile(final, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.json", json.dumps(report, ensure_ascii=False, indent=2))
            archive.writestr("launchd.txt", REDACT.sub(r"\1\2[redacted]", launchd))
            for path in sorted(self.config_dir.rglob("*.yaml")):
                text = REDACT.sub(r"\1\2[redacted]", path.read_text(encoding="utf-8", errors="replace"))
                archive.writestr(f"configs/{path.relative_to(self.config_dir)}", text)
            for path in sorted(self.log_dir.glob("*.log")):
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                tail = "\n".join(lines[-self.config.diagnostic_log_tail_lines:])
                archive.writestr(f"logs/{path.name}.tail.txt", REDACT.sub(r"\1\2[redacted]", tail))
        result = {"filename": final.name, "size": final.stat().st_size, "sha256": sha256_file(final)}
        self.audit_operation("diagnostics", actor=actor, success=True, raw=result)
        return result

    def diagnostic_path(self, filename: str) -> Path:
        path = self._safe_child(self.diagnostic_dir, filename)
        if not path.is_file():
            raise FileNotFoundError("diagnostic bundle not found")
        return path

    def list_diagnostics(self) -> list[dict[str, Any]]:
        return [
            {
                "filename": path.name,
                "size": path.stat().st_size,
                "modified_at": int(path.stat().st_mtime),
                "sha256": sha256_file(path),
            }
            for path in sorted(self.diagnostic_dir.glob("gateway-diagnostics-*.zip"), reverse=True)
        ]

    def due_for_scheduled_backup(self) -> bool:
        last = self.store.get_system_state("operations_last_backup", {})
        created = int(last.get("created_at", 0)) if isinstance(last, dict) else 0
        return created + self.config.backup_interval_hours * 3600 <= now_ts()

    def status(self) -> dict[str, Any]:
        return {
            "release_version": self.release_version,
            "backup_dir": str(self.backup_dir), "diagnostic_dir": str(self.diagnostic_dir),
            "last_backup": self.store.get_system_state("operations_last_backup", {}),
            "backup_count": len(list(self.backup_dir.glob("gateway-backup-*.zip"))),
            "scheduled_backup_due": self.due_for_scheduled_backup(),
        }

    def audit_operation(
        self, action: str, *, actor: str, success: bool, raw: dict[str, Any], error_code: str = ""
    ) -> None:
        self.store.write_api_audit(
            request_id=f"operations-{secrets.token_hex(8)}",
            actor_type="operations",
            actor_name=actor[:120],
            method="POST",
            path=f"/internal/operations/{action[:80]}",
            status_code=200 if success else 500,
            success=success,
            error_code=error_code[:120],
            risk_level="high" if action == "restore" else "medium",
            raw=raw,
        )
