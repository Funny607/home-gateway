from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from app.config.schema import AppConfig
from app.security.actions import canonical_action
from app.security.db import SecurityStore
from app.security.policy import PolicyEngine
from app.security.service import SecurityError, SecurityService
from app.security.totp import _counter_code, verify


class Stage3PrimitiveTests(unittest.TestCase):
    def test_rfc6238_sha1_vector(self) -> None:
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(_counter_code(secret, 1, 8), "94287082")
        code = _counter_code(secret, 1, 6)
        self.assertEqual(verify(secret, code, now=59, window=0), 1)

    def test_action_hash_is_exact_and_canonical(self) -> None:
        empty = hashlib.sha256(b"").hexdigest()
        first = canonical_action("delete", "/item?id=1", empty)
        second = canonical_action("DELETE", "/item?id=2", empty)
        self.assertNotEqual(first[3], second[3])
        with self.assertRaises(ValueError):
            canonical_action("DELETE", "/item/../other", empty)


class ReusableGrantActionTests(unittest.TestCase):
    def test_action_token_does_not_consume_long_lived_grant(self) -> None:
        app = AppConfig.model_validate({
            "app_id": "danger-app", "display_name": "Danger", "mount_path": "/apps/danger",
            "workdir": "/tmp", "command": ["python3", "--host", "{host}", "--port", "{port}"],
            "api": {"enabled": True},
            "capabilities": [{
                "id": "danger-app.item.delete", "title": "Delete", "risk": "critical",
                "routes": [{"method": "DELETE", "path": "/item"}],
                "action_policy": {"per_action_approval": True, "require_payload_preview": True, "one_time_token": True},
                "grant_policy": {"privileged": {
                    "enabled": True, "max_ttl_seconds": 31536000,
                    "approval_required": True, "approval_methods": ["web-admin"],
                }},
            }],
        })
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="z" * 48)
            service = SecurityService(store, PolicyEngine({app.app_id: app}))
            device = service.create_manual_device(
                device_name="Owner", device_type="test", trust_level="privileged",
                trust_ttl_seconds=200000, created_by="admin",
            )
            grant_request = service.request_grant(
                device_id=device["device"]["device_id"], device_secret=device["device_secret"],
                target_app=app.app_id, capabilities=["danger-app.item.delete"],
                requested_ttl_seconds=172800, grant_type="long_lived", reason="managed deletes",
            )
            grant = service.approve(
                approval_id=grant_request["approval_id"], approved_by="admin",
                request_code=grant_request["request_code"],
            )["grant"]
            body_hash = hashlib.sha256(b'{"id":1}').hexdigest()
            action = service.request_action_approval(
                device_id=device["device"]["device_id"], device_secret=device["device_secret"],
                grant_id=grant["grant_id"], capability="danger-app.item.delete", method="DELETE",
                path="/item", body_sha256=body_hash, payload_preview="删除项目 1",
            )
            service.approve(
                approval_id=action["approval"]["approval_id"], approved_by="admin",
                request_code=action["request_code"],
            )
            token = service.issue_token(
                device_id=device["device"]["device_id"], device_secret=device["device_secret"],
                grant_id=grant["grant_id"], action_approval_id=action["approval"]["approval_id"],
            )["access_token"]
            with self.assertRaises(SecurityError) as mismatch:
                service.verify_access_token(
                    token, target_app=app.app_id, capability="danger-app.item.delete", consume=True,
                    method="DELETE", path="/item", body_sha256=hashlib.sha256(b'{"id":2}').hexdigest(),
                )
            self.assertEqual(mismatch.exception.code, "action_binding_mismatch")
            service.verify_access_token(
                token, target_app=app.app_id, capability="danger-app.item.delete", consume=True,
                method="DELETE", path="/item", body_sha256=body_hash,
            )
            row = store.fetch_one("SELECT one_time_consumed_at FROM grant_record WHERE grant_id=?", (grant["grant_id"],))
            self.assertIsNone(row["one_time_consumed_at"])


if __name__ == "__main__":
    unittest.main()
