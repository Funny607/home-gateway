from __future__ import annotations

import tempfile
import unittest
import hashlib
from pathlib import Path

from app.config.schema import AppConfig
from app.security.db import SecurityStore, now_ts
from app.security.policy import PolicyEngine
from app.security.service import SecurityError, SecurityService


def build_app() -> AppConfig:
    return AppConfig.model_validate(
        {
            "app_id": "test-app",
            "display_name": "Test App",
            "mount_path": "/apps/test",
            "workdir": "/tmp",
            "command": ["python3", "--host", "{host}", "--port", "{port}"],
            "api": {"enabled": True},
            "capabilities": [
                {
                    "id": "test-app.status.read",
                    "title": "Read status",
                    "risk": "low",
                    "routes": [{"method": "GET", "path": "/status"}],
                },
                {
                    "id": "test-app.status.auto",
                    "title": "Auto read",
                    "risk": "low",
                    "routes": [{"method": "GET", "path": "/auto"}],
                    "grant_policy": {
                        "paired": {
                            "max_ttl_seconds": 3600,
                            "approval_required": False,
                            "approval_methods": [],
                        }
                    },
                },
                {
                    "id": "test-app.item.delete",
                    "title": "Delete item",
                    "risk": "high",
                    "routes": [{"method": "DELETE", "path": "/item"}],
                    "action_policy": {
                        "per_action_approval": True,
                        "one_time_token": True,
                        "require_payload_preview": False,
                    },
                },
            ],
        }
    )


class SecurityServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SecurityStore(Path(self.temp.name) / "gateway.sqlite3", pepper="x" * 48)
        app = build_app()
        self.service = SecurityService(self.store, PolicyEngine({app.app_id: app}))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _paired_device(self):
        registration = self.service.register_device(device_name="Watcher", device_type="mac")
        approved = self.service.approve(
            approval_id=registration["approval_id"],
            approved_by="admin",
            device_trust_level="paired",
            request_code=registration["request_code"],
        )
        self.assertEqual(approved["device"]["status"], "active")
        return registration

    def test_secret_is_required_for_grant_and_is_never_stored_plaintext(self) -> None:
        device = self._paired_device()
        with self.assertRaises(SecurityError) as caught:
            self.service.request_grant(
                device_id=device["device_id"],
                device_secret="wrong",
                target_app="test-app",
                capabilities=["test-app.status.auto"],
                requested_ttl_seconds=3600,
                grant_type="session",
                reason="test",
            )
        self.assertEqual(caught.exception.code, "invalid_device_credentials")
        result = self.service.request_grant(
            device_id=device["device_id"],
            device_secret=device["device_secret"],
            target_app="test-app",
            capabilities=["test-app.status.auto"],
            requested_ttl_seconds=3600,
            grant_type="session",
            reason="test",
        )
        self.assertEqual(result["status"], "granted")
        raw = Path(self.store.db_path).read_bytes()
        self.assertNotIn(device["device_secret"].encode(), raw)

    def test_full_grant_token_revoke_flow(self) -> None:
        device = self._paired_device()
        requested = self.service.request_grant(
            device_id=device["device_id"],
            device_secret=device["device_secret"],
            target_app="test-app",
            capabilities=["test-app.status.read"],
            requested_ttl_seconds=7200,
            grant_type="session",
            reason="read status",
        )
        self.assertEqual(requested["status"], "pending_approval")
        approved = self.service.approve(
            approval_id=requested["approval_id"], approved_by="admin", request_code=requested["request_code"]
        )
        grant = approved["grant"]
        issued = self.service.issue_token(
            device_id=device["device_id"],
            device_secret=device["device_secret"],
            grant_id=grant["grant_id"],
        )
        token = issued["access_token"]
        actor = self.service.verify_access_token(
            token, target_app="test-app", capability="test-app.status.read"
        )
        self.assertEqual(actor["device_id"], device["device_id"])
        with self.assertRaises(SecurityError):
            self.service.verify_access_token(token, target_app="another-app")
        self.service.revoke_current_token(token)
        with self.assertRaises(SecurityError) as caught:
            self.service.verify_access_token(token)
        self.assertEqual(caught.exception.code, "token_revoked")

    def test_expired_approval_cannot_be_approved(self) -> None:
        device = self._paired_device()
        request = self.service.request_grant(
            device_id=device["device_id"],
            device_secret=device["device_secret"],
            target_app="test-app",
            capabilities=["test-app.status.read"],
            requested_ttl_seconds=3600,
            grant_type="session",
            reason="expire me",
        )
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE approval_request SET expires_at=? WHERE approval_id=?",
                (now_ts() - 1, request["approval_id"]),
            )
        with self.assertRaises(SecurityError):
            self.service.approve(
                approval_id=request["approval_id"],
                approved_by="admin",
                request_code=request["request_code"],
            )
        row = self.store.fetch_one(
            "SELECT status FROM approval_request WHERE approval_id=?", (request["approval_id"],)
        )
        self.assertEqual(row["status"], "expired")

    def test_trust_hierarchy_and_expiry_are_enforced(self) -> None:
        paired = self._paired_device()
        with self.assertRaises(SecurityError) as caught:
            self.service.request_grant(
                device_id=paired["device_id"],
                device_secret=paired["device_secret"],
                target_app="test-app",
                capabilities=["test-app.item.delete"],
                requested_ttl_seconds=300,
                grant_type="one_time",
                reason="delete",
            )
        self.assertEqual(caught.exception.code, "insufficient_trust")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE trusted_device SET trust_expires_at=? WHERE device_id=?",
                (now_ts() - 1, paired["device_id"]),
            )
        with self.assertRaises(SecurityError) as expired:
            self.service.authenticate_device(
                device_id=paired["device_id"], device_secret=paired["device_secret"]
            )
        self.assertIn(expired.exception.code, {"device_not_active", "device_trust_expired"})

    def test_one_time_token_is_consumed_atomically(self) -> None:
        device = self.service.create_manual_device(
            device_name="Privileged",
            device_type="test",
            trust_level="trusted",
            trust_ttl_seconds=3600,
            created_by="admin",
        )
        request = self.service.request_grant(
            device_id=device["device"]["device_id"],
            device_secret=device["device_secret"],
            target_app="test-app",
            capabilities=["test-app.item.delete"],
            requested_ttl_seconds=300,
            grant_type="one_time",
            reason="delete item 1",
        )
        approved = self.service.approve(
            approval_id=request["approval_id"], approved_by="admin", request_code=request["request_code"]
        )
        body_hash = hashlib.sha256(b"").hexdigest()
        action = self.service.request_action_approval(
            device_id=device["device"]["device_id"], device_secret=device["device_secret"],
            grant_id=approved["grant"]["grant_id"], capability="test-app.item.delete",
            method="DELETE", path="/item", body_sha256=body_hash, reason="delete item 1",
        )
        self.service.approve(
            approval_id=action["approval"]["approval_id"], approved_by="admin",
            request_code=action["request_code"],
        )
        token = self.service.issue_token(
            device_id=device["device"]["device_id"],
            device_secret=device["device_secret"],
            grant_id=approved["grant"]["grant_id"],
            action_approval_id=action["approval"]["approval_id"],
        )["access_token"]
        self.service.verify_access_token(
            token,
            target_app="test-app",
            capability="test-app.item.delete",
            consume=True,
            method="DELETE", path="/item", body_sha256=body_hash,
        )
        with self.assertRaises(SecurityError) as caught:
            self.service.verify_access_token(token, consume=True)
        self.assertEqual(caught.exception.code, "token_consumed")


if __name__ == "__main__":
    unittest.main()
