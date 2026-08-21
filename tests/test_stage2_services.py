from __future__ import annotations

import logging
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import httpx

from app.config.schema import AppConfig, NotificationConfig
from app.leases.coordinator import LeaseCoordinator
from app.notifications.service import NotificationService
from app.registry.service import AppRegistry, RegistryError
from app.security.db import SecurityStore
from app.security.policy import PolicyEngine
from app.security.service import SecurityService
from app.utils.processes import process_identity, process_matches_identity


def lease_app(app_id: str = "mode-app") -> AppConfig:
    capability = f"{app_id}.mode.lease"
    return AppConfig.model_validate(
        {
            "manifest_version": 1,
            "app_id": app_id,
            "display_name": "Mode App",
            "mount_path": f"/apps/{app_id}",
            "workdir": "/tmp",
            "command": ["python3", "--host", "{host}", "--port", "{port}"],
            "api": {"enabled": True, "auto_start": True},
            "capabilities": [
                {
                    "id": capability,
                    "title": "Temporary active mode",
                    "risk": "medium_high",
                    "gateway_managed": True,
                    "grant_policy": {
                        "trusted": {
                            "max_ttl_seconds": 3600,
                            "approval_required": False,
                            "approval_methods": [],
                        }
                    },
                    "lease_policy": {
                        "resource_key": f"{app_id}.mode",
                        "max_lease_seconds": 600,
                        "heartbeat_interval_seconds": 30,
                        "acquire": {"method": "POST", "path": "/activate"},
                        "release": {"method": "POST", "path": "/release"},
                        "probe": {
                            "path": "/status",
                            "json_path": "state",
                            "active_values": ["active"],
                            "released_values": ["released"],
                        },
                    },
                }
            ],
        }
    )


class EventSink:
    def __init__(self) -> None:
        self.items = []

    def write(self, event_type: str, **fields) -> None:
        self.items.append({"event_type": event_type, **fields})


class ManagerStub:
    def __init__(self, apps: dict[str, AppConfig]) -> None:
        self.events = EventSink()
        self.logger = logging.getLogger("stage2-test")
        self.apps = {
            app_id: SimpleNamespace(
                config=config,
                state="running",
                runtime=SimpleNamespace(internal_url="http://app.local"),
                enabled=True,
            )
            for app_id, config in apps.items()
        }

    def get_app(self, app_id: str):
        if app_id not in self.apps:
            raise KeyError(app_id)
        return self.apps[app_id]

    async def ensure_started(self, app_id: str):
        return self.get_app(app_id).runtime

    def register_app(self, config: AppConfig, *, enabled: bool = True) -> None:
        self.apps[config.app_id] = SimpleNamespace(
            config=config, state="stopped", runtime=None, enabled=enabled
        )

    def update_app(self, config: AppConfig) -> None:
        self.apps[config.app_id].config = config

    def set_enabled(self, app_id: str, enabled: bool) -> None:
        self.apps[app_id].enabled = enabled


class NotificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_dedupe_and_local_mailer_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = SecurityStore(root / "gateway.sqlite3", pepper="n" * 48)
            script = root / "mailer.py"
            argv_file = root / "argv.json"
            script.write_text(
                "import json, sys\n"
                f"open({str(argv_file)!r}, 'w', encoding='utf-8').write(json.dumps(sys.argv))\n",
                encoding="utf-8",
            )
            config = NotificationConfig(
                python_executable=sys.executable,
                command=str(script),
                recipient="lu.yuanqi.2005@gmail.com",
                cooldown_seconds=300,
            )
            service = NotificationService(store, config, logging.getLogger("notification-test"))
            marker = root / "must-not-exist"
            first = service.enqueue(
                category="test", severity="info", title=f"$(touch {marker})", message="Safe body", dedupe_key="same"
            )
            second = service.enqueue(
                category="test", severity="warning", title=f"$(touch {marker})", message="Safe body", dedupe_key="same"
            )
            self.assertEqual(first["notification_id"], second["notification_id"])
            self.assertTrue(second["deduplicated"])
            self.assertEqual(second["repeat_count"], 2)
            self.assertTrue(await service.worker_once())
            sent = store.fetch_one(
                "SELECT status, attempts FROM notification_record WHERE notification_id=?",
                (first["notification_id"],),
            )
            self.assertEqual(sent["status"], "sent")
            self.assertEqual(sent["attempts"], 1)
            argv = json.loads(argv_file.read_text(encoding="utf-8"))
            self.assertEqual(argv[1:4], ["send", "--to", "lu.yuanqi.2005@gmail.com"])
            self.assertIn("--prefix", argv)
            self.assertIn("--subject", argv)
            self.assertIn("--body", argv)
            self.assertFalse(marker.exists())

    async def test_mailer_failure_is_retained_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = SecurityStore(root / "gateway.sqlite3", pepper="f" * 48)
            service = NotificationService(
                store,
                NotificationConfig(command=str(root / "missing.py"), retry_backoff_seconds=1),
                logging.getLogger("notification-test"),
            )
            item = service.enqueue(
                category="test", severity="danger", title="Failure", message="Body", force=True
            )
            self.assertTrue(await service.worker_once())
            failed = store.fetch_one(
                "SELECT status, attempts, last_error FROM notification_record WHERE notification_id=?",
                (item["notification_id"],),
            )
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["attempts"], 1)
            self.assertTrue(failed["last_error"])


class LeaseCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_resource_acquires_once_and_releases_after_last_holder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = lease_app()
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="l" * 48)
            security = SecurityService(store, PolicyEngine({app.app_id: app}))
            actors = []
            for number in (1, 2):
                device_result = security.create_manual_device(
                    device_name=f"Device {number}", device_type="test", trust_level="trusted",
                    trust_ttl_seconds=3600, created_by="admin",
                )
                device = device_result["device"]
                grant = security.request_grant(
                    device_id=device["device_id"], device_secret=device_result["device_secret"],
                    target_app=app.app_id, capabilities=[f"{app.app_id}.mode.lease"],
                    requested_ttl_seconds=3600, grant_type="session", reason="test",
                )["grant"]
                actors.append({"device_id": device["device_id"], "grant_id": grant["grant_id"]})
            state = {"value": "released", "acquire": 0, "release": 0}

            async def handler(request: httpx.Request) -> httpx.Response:
                if request.url.path == "/activate":
                    state.update(value="active", acquire=state["acquire"] + 1)
                    return httpx.Response(200)
                if request.url.path == "/release":
                    state.update(value="released", release=state["release"] + 1)
                    return httpx.Response(200)
                return httpx.Response(200, json={"state": state["value"]})

            manager = ManagerStub({app.app_id: app})
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                coordinator = LeaseCoordinator(manager=manager, client=client, security=security)
                first = await coordinator.create(
                    actor=actors[0], capability_id=f"{app.app_id}.mode.lease",
                    lease_seconds=300, request_id="one",
                )
                second = await coordinator.create(
                    actor=actors[1], capability_id=f"{app.app_id}.mode.lease",
                    lease_seconds=300, request_id="two",
                )
                self.assertEqual(state["acquire"], 1)
                released_first = await coordinator.release(
                    actor=actors[0], lease_id=first["lease"]["lease_id"], reason="test"
                )
                self.assertTrue(released_first["recovered"])
                self.assertEqual(state["release"], 0)
                released_second = await coordinator.release(
                    actor=actors[1], lease_id=second["lease"]["lease_id"], reason="test"
                )
                self.assertTrue(released_second["recovered"])
                self.assertEqual(state["release"], 1)


class RegistryTests(unittest.TestCase):
    def test_preview_save_and_revision_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = lease_app("existing-app")
            manager = ManagerStub({existing.app_id: existing})
            manager.apps[existing.app_id].state = "stopped"
            manager.apps[existing.app_id].runtime = None
            store = SecurityStore(root / "gateway.sqlite3", pepper="r" * 48)
            security = SecurityService(store, PolicyEngine({existing.app_id: existing}))
            registry = AppRegistry(config_dir=root / "configs", manager=manager, security=security)
            registry.bootstrap()
            candidate = lease_app("new-app")
            preview = registry.preview(candidate.model_dump(mode="json"))
            self.assertTrue(preview["valid"])
            saved = registry.save(
                manifest=candidate.model_dump(mode="json"), actor="admin"
            )
            self.assertTrue(Path(saved["path"]).is_file())
            with self.assertRaises(RegistryError) as caught:
                registry.save(
                    manifest=candidate.model_dump(mode="json"),
                    actor="admin",
                    expected_revision="stale",
                )
            self.assertEqual(caught.exception.code, "manifest_revision_conflict")


class ProcessIdentityTests(unittest.TestCase):
    def test_pid_generation_marker_matches_current_process(self) -> None:
        marker = process_identity(os.getpid())
        if not marker:
            self.assertFalse(process_matches_identity(os.getpid(), ""))
            self.skipTest("platform sandbox does not expose /proc or a usable ps process marker")
        self.assertTrue(process_matches_identity(os.getpid(), marker))
        self.assertFalse(process_matches_identity(os.getpid(), marker + "-stale"))


class AuditRedactionTests(unittest.TestCase):
    def test_sensitive_metadata_is_redacted_before_storage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="a" * 48)
            store.write_api_audit(
                request_id="redact",
                method="POST",
                path="/test",
                success=False,
                raw={"access_token": "never-store", "nested": {"password": "never-store"}},
            )
            row = store.fetch_one("SELECT raw_json FROM api_audit WHERE request_id='redact'")
            self.assertNotIn("never-store", row["raw_json"])
            self.assertIn("[redacted]", row["raw_json"])


if __name__ == "__main__":
    unittest.main()
