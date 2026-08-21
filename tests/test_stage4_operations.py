from __future__ import annotations

import json
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from app.config.schema import AppConfig, OperationsConfig
from app.operations.service import OperationsService
from app.security.db import SecurityStore
from app.security.policy import PolicyEngine
from app.security.recovery import RecoveryService
from app.security.service import SecurityError, SecurityService
from app.security.totp import _counter_code


def approval_app(methods: list[str]) -> AppConfig:
    return AppConfig.model_validate({
        "app_id": "protected-app",
        "display_name": "Protected",
        "mount_path": "/apps/protected",
        "workdir": "/tmp",
        "command": ["python3", "--host", "{host}", "--port", "{port}"],
        "api": {"enabled": True},
        "capabilities": [{
            "id": "protected-app.read",
            "title": "Read",
            "risk": "low",
            "routes": [{"method": "GET", "path": "/status"}],
            "grant_policy": {
                "privileged": {
                    "enabled": True,
                    "max_ttl_seconds": 86400,
                    "approval_required": True,
                    "approval_methods": methods,
                }
            },
        }],
    })


class Stage3ApprovalCompletionTests(unittest.TestCase):
    def service(self, directory: str, methods: list[str], *, totp_secret: str = ""):
        app = approval_app(methods)
        store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="p" * 48)
        service = SecurityService(store, PolicyEngine({app.app_id: app}), totp_secret=totp_secret)
        device = service.create_manual_device(
            device_name="Owner CLI", device_type="cli", trust_level="privileged",
            trust_ttl_seconds=86400, created_by="admin",
        )
        return store, service, device

    def test_totp_cannot_be_replayed_across_approvals(self) -> None:
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        with tempfile.TemporaryDirectory() as directory:
            _, service, device = self.service(directory, ["totp"], totp_secret=secret)
            requests = [service.request_grant(
                device_id=device["device"]["device_id"], device_secret=device["device_secret"],
                target_app="protected-app", capabilities=["protected-app.read"],
                requested_ttl_seconds=3600, grant_type="session", reason=f"request-{index}",
            ) for index in range(2)]
            code = _counter_code(secret, int(time.time()) // 30)
            service.approve(
                approval_id=requests[0]["approval_id"], approved_by="TOTP:test",
                approval_method="totp", request_code=requests[0]["request_code"], totp_code=code,
            )
            with self.assertRaises(SecurityError) as replay:
                service.approve(
                    approval_id=requests[1]["approval_id"], approved_by="TOTP:test",
                    approval_method="totp", request_code=requests[1]["request_code"], totp_code=code,
                )
            self.assertEqual(replay.exception.code, "totp_replayed")

    def test_device_registration_can_use_local_desktop_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="d" * 48)
            service = SecurityService(
                store, PolicyEngine({}), desktop_approver_secret="desktop" * 8
            )
            registration = service.register_device(device_name="Mac watcher", device_type="cli")
            pending = service.approval_status_for_device(
                approval_id=registration["approval_id"], device_id=registration["device_id"],
                device_secret=registration["device_secret"],
            )["approval"]
            self.assertIn("desktop", pending["required_approval_methods"])
            approved = service.approve(
                approval_id=registration["approval_id"], approved_by="macOS Desktop Approver",
                approval_method="desktop", desktop_verified=True,
            )
            self.assertEqual(approved["device"]["status"], "active")

    def test_desktop_approval_works_for_grants_and_device_rotation_revokes_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, service, device = self.service(directory, ["desktop"])
            request = service.request_grant(
                device_id=device["device"]["device_id"], device_secret=device["device_secret"],
                target_app="protected-app", capabilities=["protected-app.read"],
                requested_ttl_seconds=3600, grant_type="session", reason="desktop grant",
            )
            granted = service.approve(
                approval_id=request["approval_id"], approved_by="macOS Desktop Approver",
                approval_method="desktop", desktop_verified=True,
            )["grant"]
            rotated = service.rotate_device_secret(
                device_id=device["device"]["device_id"], rotated_by="admin"
            )
            with self.assertRaises(SecurityError):
                service.request_grant(
                    device_id=device["device"]["device_id"], device_secret=device["device_secret"],
                    target_app="protected-app", capabilities=["protected-app.read"],
                    requested_ttl_seconds=300, grant_type="session", reason="old secret",
                )
            row = store.fetch_one("SELECT revoked_at FROM grant_record WHERE grant_id=?", (granted["grant_id"],))
            self.assertIsNotNone(row["revoked_at"])
            status = service.request_grant(
                device_id=device["device"]["device_id"], device_secret=rotated["device_secret"],
                target_app="protected-app", capabilities=["protected-app.read"],
                requested_ttl_seconds=300, grant_type="session", reason="new secret",
            )
            self.assertEqual(status["status"], "pending_approval")


class RecoveryAndOperationsTests(unittest.TestCase):
    def test_recovery_codes_are_one_time_and_emergency_access_is_constrained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="r" * 48)
            recovery = RecoveryService(store, verifier_secret="v" * 48, token_ttl_seconds=300)
            codes = recovery.generate_codes(count=4)
            activated = recovery.activate(recovery_code=codes[0], reason="drill")
            verified = recovery.verify_token(activated["emergency_token"])
            self.assertTrue(verified["token_id"].startswith("bgt_"))
            self.assertNotIn("admin_session", activated)
            self.assertEqual(
                set(activated["allowed_actions"]),
                {"status", "create-backup", "disable-external-api", "revoke-all-access"},
            )
            with self.assertRaises(SecurityError) as reused:
                recovery.activate(recovery_code=codes[0], reason="replay")
            self.assertEqual(reused.exception.code, "recovery_code_invalid")
            recovery.set_external_api_disabled(True, actor=verified["token_id"])
            self.assertTrue(recovery.external_api_disabled())

    def test_backup_verification_tamper_detection_and_diagnostic_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs = root / "configs"
            logs = root / "logs"
            backups = root / "backups"
            diagnostics = root / "diagnostics"
            configs.mkdir()
            logs.mkdir()
            (configs / "gateway.yaml").write_text(
                'session_secret_ref: "keychain:service:session-secret"\n', encoding="utf-8"
            )
            (logs / "gateway.log").write_text(
                "healthy\npassword=DO-NOT-LEAK\nAuthorization: Bearer-DO-NOT-LEAK\n",
                encoding="utf-8",
            )
            store = SecurityStore(root / "gateway.sqlite3", pepper="o" * 48)
            service = OperationsService(
                project_root=root,
                config_dir=configs,
                log_dir=logs,
                store=store,
                config=OperationsConfig(
                    backup_dir=str(backups), diagnostic_dir=str(diagnostics),
                    backup_interval_hours=24, backup_retention_count=3,
                    emergency_token_ttl_seconds=300, diagnostic_log_tail_lines=20,
                ),
                release_version="5.0.0-test",
            )
            backup = service.create_backup(reason="test", actor="unittest")
            self.assertTrue(service.verify_backup(backup["filename"])["ok"])

            original = backups / backup["filename"]
            tampered = backups / "gateway-backup-tampered.zip"
            with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w") as target:
                for name in source.namelist():
                    data = source.read(name)
                    if name == "gateway.sqlite3":
                        data += b"tamper"
                    target.writestr(name, data)
            with self.assertRaises(ValueError):
                service.verify_backup(tampered.name)

            diagnostic = service.create_diagnostic_bundle(actor="unittest")
            with zipfile.ZipFile(diagnostics / diagnostic["filename"], "r") as archive:
                combined = b"\n".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(b"DO-NOT-LEAK", combined)
            self.assertIn(b"[redacted]", combined)


if __name__ == "__main__":
    unittest.main()
