from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import httpx

from app.api_v1.qbt_lease import APP_ID, LEASE_CAPABILITY, _finish_release
from app.config.schema import AppConfig
from app.security.db import SecurityStore, now_ts
from app.security.policy import PolicyEngine
from app.security.service import SecurityService


def qbt_app() -> AppConfig:
    return AppConfig.model_validate(
        {
            "app_id": APP_ID,
            "display_name": "qbt mode",
            "mount_path": "/apps/qbt-mode",
            "workdir": "/tmp",
            "command": ["python3", "--host", "{host}", "--port", "{port}"],
            "api": {"enabled": True},
            "capabilities": [
                {
                    "id": LEASE_CAPABILITY,
                    "title": "gaming lease",
                    "risk": "medium_high",
                    "gateway_managed": True,
                    "routes": [],
                    "grant_policy": {
                        "trusted": {
                            "max_ttl_seconds": 3600,
                            "approval_required": False,
                            "approval_methods": [],
                        }
                    },
                    "lease_policy": {
                        "resource_key": "qbt-mode.mode",
                        "max_lease_seconds": 600,
                        "heartbeat_interval_seconds": 30,
                        "acquire": {"method": "POST", "path": "/api/mode/gaming"},
                        "release": {"method": "POST", "path": "/api/mode/normal"},
                        "probe": {
                            "method": "GET",
                            "path": "/api/mode/status",
                            "json_path": "mode",
                            "active_values": ["gaming"],
                            "released_values": ["normal"],
                        },
                    },
                }
            ],
        }
    )


class LeaseRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_normal_mode_waits_for_last_lease_and_failed_release_retries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="z" * 48)
            app = qbt_app()
            service = SecurityService(store, PolicyEngine({APP_ID: app}))
            records = []
            for number in (1, 2):
                device = service.create_manual_device(
                    device_name=f"device {number}",
                    device_type="test",
                    trust_level="trusted",
                    trust_ttl_seconds=3600,
                    created_by="admin",
                )
                grant = service.request_grant(
                    device_id=device["device"]["device_id"],
                    device_secret=device["device_secret"],
                    target_app=APP_ID,
                    capabilities=[LEASE_CAPABILITY],
                    requested_ttl_seconds=3600,
                    grant_type="session",
                    reason="test",
                )["grant"]
                records.append((device["device"]["device_id"], grant["grant_id"]))
            now = now_ts()
            with store.transaction() as conn:
                for number, (device_id, grant_id) in enumerate(records, start=1):
                    conn.execute(
                        """
                        INSERT INTO lease_record (
                            lease_id, device_id, grant_id, target_app, capability, status,
                            created_at, expires_at, max_expires_at, last_heartbeat_at
                        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
                        """,
                        (
                            f"lease-{number}",
                            device_id,
                            grant_id,
                            APP_ID,
                            LEASE_CAPABILITY,
                            now,
                            now + 300,
                            now + 600,
                            now,
                        ),
                    )

            manager = SimpleNamespace(
                get_app=lambda app_id: SimpleNamespace(
                    config=app,
                    state="running",
                    runtime=SimpleNamespace(internal_url="http://qbt.local"),
                )
            )
            calls: list[str] = []

            async def fail_handler(request: httpx.Request) -> httpx.Response:
                calls.append(str(request.url))
                return httpx.Response(500, text="failed")

            async with httpx.AsyncClient(transport=httpx.MockTransport(fail_handler)) as client:
                first = await _finish_release(
                    service=service,
                    manager=manager,
                    client=client,
                    lease_id="lease-1",
                    reason="first released",
                )
                self.assertTrue(first)
                self.assertEqual(calls, [])
                second = await _finish_release(
                    service=service,
                    manager=manager,
                    client=client,
                    lease_id="lease-2",
                    reason="last released",
                )
                self.assertFalse(second)
            self.assertEqual(store.fetch_one("SELECT status FROM lease_record WHERE lease_id='lease-2'")["status"], "releasing")

            async def success_handler(request: httpx.Request) -> httpx.Response:
                calls.append(str(request.url))
                return httpx.Response(200, json={"ok": True})

            async with httpx.AsyncClient(transport=httpx.MockTransport(success_handler)) as client:
                recovered = await _finish_release(
                    service=service,
                    manager=manager,
                    client=client,
                    lease_id="lease-2",
                    reason="automatic recovery",
                )
            self.assertTrue(recovered)
            self.assertEqual(store.fetch_one("SELECT status FROM lease_record WHERE lease_id='lease-2'")["status"], "released")
            self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
