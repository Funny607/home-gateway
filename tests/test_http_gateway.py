from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

import yaml
from argon2 import PasswordHasher


_TEMP = tempfile.TemporaryDirectory()
warnings.filterwarnings(
    "ignore", message="Using `httpx` with `starlette.testclient` is deprecated*"
)
_ROOT = Path(__file__).resolve().parent.parent
_CONFIG = Path(_TEMP.name) / "configs"
_CONFIG.mkdir(parents=True)
_RUNTIME = Path(_TEMP.name) / "runtime"
_LOGS = Path(_TEMP.name) / "logs"

os.environ["GATEWAY_CONFIG_DIR"] = str(_CONFIG)
os.environ["TEST_SESSION_SECRET"] = "s" * 48
os.environ["TEST_DATABASE_PEPPER"] = "p" * 48
os.environ["TEST_BREAKGLASS_SECRET"] = "b" * 48
os.environ["TEST_ADMIN_HASH"] = PasswordHasher().hash("correct-admin-password")
os.environ["TEST_GUEST_HASH"] = PasswordHasher().hash("correct-guest-password")

(_CONFIG / "auth.yaml").write_text(
    yaml.safe_dump(
        {
            "session_secret_ref": "env:TEST_SESSION_SECRET",
            "database_pepper_ref": "env:TEST_DATABASE_PEPPER",
            "breakglass_secret_ref": "env:TEST_BREAKGLASS_SECRET",
            "session_max_age_seconds": 3600,
            "secure_cookies": False,
            "same_site": "strict",
            "allowed_hosts": ["testserver", "127.0.0.1"],
            "trusted_origins": ["http://127.0.0.1"],
            "users": [
                {
                    "username": "admin",
                    "password_hash_ref": "env:TEST_ADMIN_HASH",
                    "role": "admin",
                },
                {
                    "username": "guest",
                    "password_hash_ref": "env:TEST_GUEST_HASH",
                    "role": "guest",
                },
            ],
        }
    ),
    encoding="utf-8",
)
(_CONFIG / "gateway.yaml").write_text(
    yaml.safe_dump(
        {
            "listen_host": "127.0.0.1",
            "listen_port": 8081,
            "runtime_dir": str(_RUNTIME),
            "log_dir": str(_LOGS),
            "event_log_path": str(_LOGS / "events.jsonl"),
            "api_audit_db_path": str(_RUNTIME / "gateway.sqlite3"),
            "health_poll_interval_seconds": 1,
            "idle_scan_interval_seconds": 60,
            "notifications": {"enabled": False},
            "tunnel": {"enabled": False},
            "operations": {
                "backup_dir": str(_RUNTIME / "backups" / "operations"),
                "diagnostic_dir": str(_RUNTIME / "diagnostics"),
                "backup_interval_hours": 24,
                "backup_retention_count": 4,
                "emergency_token_ttl_seconds": 300,
                "diagnostic_log_tail_lines": 50,
            },
        }
    ),
    encoding="utf-8",
)
(_CONFIG / "links.yaml").write_text("links: []\n", encoding="utf-8")
(_CONFIG / "visitor_prompts.txt").write_text("guest denied\n", encoding="utf-8")
apps_dir = _CONFIG / "apps"
apps_dir.mkdir()
(apps_dir / "demo.yaml").write_text(
    yaml.safe_dump(
        {
            "app_id": "demo-echo",
            "display_name": "Demo Echo",
            "mount_path": "/apps/demo-echo",
            "workdir": str(_ROOT),
            "command": [
                sys.executable,
                "-m",
                "uvicorn",
                "apps.demo_echo_app:app",
                "--host",
                "{host}",
                "--port",
                "{port}",
            ],
            "listen_host": "127.0.0.1",
            "health_path": "/health",
            "allow_auto_stop": False,
            "dashboard": {
                "visible_roles": ["guest", "admin"],
                "allow_detail_roles": ["guest", "admin"],
                "allow_open_roles": ["admin"],
                "allow_proxy_roles": ["admin"],
            },
            "api": {
                "enabled": True,
                "auto_start": True,
                "timeout_seconds": 5,
                "max_request_body_bytes": 1024,
            },
            "proxy": {
                "websocket": {
                    "enabled": True,
                    "path_prefixes": ["/ws"],
                    "max_message_bytes": 4096,
                    "idle_timeout_seconds": 30,
                }
            },
            "capabilities": [
                {
                    "id": "demo-echo.hello.read",
                    "title": "Read hello",
                    "risk": "low",
                    "routes": [{"method": "GET", "path": "/hello"}],
                },
                {
                    "id": "demo-echo.echo.write",
                    "title": "Echo form",
                    "risk": "low",
                    "routes": [{"method": "POST", "path": "/echo"}],
                },
            ],
        }
    ),
    encoding="utf-8",
)

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app, get_recovery  # noqa: E402


class HttpGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = TestClient(app)
        cls.client = cls.context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls._login("admin", "correct-admin-password")
            csrf = cls.client.get("/api/auth/v1/csrf").json()["csrf_token"]
            cls.client.post("/api/apps/demo-echo/stop", headers={"X-CSRF-Token": csrf})
        finally:
            cls.context.__exit__(None, None, None)
            _TEMP.cleanup()

    @classmethod
    def _login(cls, username: str, password: str):
        page = cls.client.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        return cls.client.post(
            "/login",
            data={"username": username, "password": password, "csrf_token": token},
            follow_redirects=True,
        )

    def setUp(self) -> None:
        self.client.cookies.clear()

    def test_public_surface_and_host_filter(self) -> None:
        health = self.client.get("/healthz")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.headers["x-content-type-options"], "nosniff")
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)
        self.assertEqual(self.client.get("/api/apps").status_code, 401)
        self.assertEqual(
            self.client.get("/healthz", headers={"Host": "attacker.example"}).status_code,
            400,
        )

    def test_stage4_emergency_activation_and_external_api_kill_switch(self) -> None:
        recovery = get_recovery()
        code = recovery.generate_codes(count=4)[0]
        activated = self.client.post(
            "/api/emergency/v1/activate",
            json={"recovery_code": code, "reason": "HTTP drill"},
            headers={"X-Breakglass-Secret": "b" * 48},
        )
        self.assertEqual(activated.status_code, 200, activated.text)
        token = activated.json()["emergency_token"]
        disabled = self.client.post(
            "/api/emergency/v1/disable-external-api",
            json={},
            headers={"Authorization": f"BreakGlass {token}"},
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        try:
            blocked = self.client.get("/api/apps/v1/demo-echo/hello")
            self.assertEqual(blocked.status_code, 503, blocked.text)
            self.assertEqual(blocked.json()["error"]["code"], "EXTERNAL_API_DISABLED")
        finally:
            recovery.set_external_api_disabled(False, actor="unittest")

    def test_stage5_operations_dashboard_and_artifact_apis(self) -> None:
        self._login("admin", "correct-admin-password")
        dashboard = self.client.get("/dashboard/operations")
        self.assertEqual(dashboard.status_code, 200, dashboard.text)
        self.assertIn("运维与恢复", dashboard.text)
        csrf = self.client.get("/api/auth/v1/csrf").json()["csrf_token"]
        backup = self.client.post(
            "/api/operations/v1/backups",
            json={"reason": "HTTP test"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(backup.status_code, 200, backup.text)
        backup_filename = backup.json()["backup"]["filename"]
        self.assertTrue(backup_filename.endswith(".zip"))
        backup_download = self.client.get(f"/api/operations/v1/backups/{backup_filename}")
        self.assertEqual(backup_download.status_code, 200)
        self.assertEqual(backup_download.headers["content-type"], "application/zip")
        diagnostic = self.client.post(
            "/api/operations/v1/diagnostics",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(diagnostic.status_code, 200, diagnostic.text)
        filename = diagnostic.json()["diagnostic"]["filename"]
        downloaded = self.client.get(f"/api/operations/v1/diagnostics/{filename}")
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.headers["content-type"], "application/zip")

    def test_device_cannot_self_declare_trust(self) -> None:
        response = self.client.post(
            "/api/auth/v1/devices/register",
            json={"device_name": "attacker", "device_type": "test", "trust_level": "privileged"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["error"]["code"], "UNKNOWN_FIELDS")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_login_csrf_admin_csrf_and_protected_openapi(self) -> None:
        missing = self.client.post(
            "/login",
            data={"username": "admin", "password": "correct-admin-password"},
            follow_redirects=False,
        )
        self.assertEqual(missing.status_code, 303)
        self.assertEqual(missing.headers["cache-control"], "no-store")
        response = self._login("admin", "correct-admin-password")
        self.assertIn("管理员模式", response.text)
        openapi = self.client.get("/api/admin/v1/openapi.json")
        self.assertEqual(openapi.status_code, 200)
        operation_ids = [
            operation["operationId"]
            for methods in openapi.json()["paths"].values()
            for operation in methods.values()
            if isinstance(operation, dict) and "operationId" in operation
        ]
        self.assertEqual(len(operation_ids), len(set(operation_ids)))
        self.assertEqual(self.client.post("/api/apps/demo-echo/start").status_code, 403)
        csrf = self.client.get("/api/auth/v1/csrf").json()["csrf_token"]
        started = self.client.post(
            "/api/apps/demo-echo/start", headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(started.status_code, 200, started.text)

    def test_guest_cannot_proxy_even_when_app_is_running(self) -> None:
        self._login("admin", "correct-admin-password")
        csrf = self.client.get("/api/auth/v1/csrf").json()["csrf_token"]
        self.client.post("/api/apps/demo-echo/start", headers={"X-CSRF-Token": csrf})
        before = next(
            item for item in self.client.get("/api/apps").json() if item["app_id"] == "demo-echo"
        )["request_count"]
        logout_page = self.client.get("/dashboard")
        logout_csrf = re.search(r'name="csrf_token" value="([^"]+)"', logout_page.text).group(1)
        self.client.post("/logout", data={"csrf_token": logout_csrf})
        self._login("guest", "correct-guest-password")
        blocked = self.client.get("/apps/demo-echo/hello")
        self.assertEqual(blocked.status_code, 200)
        self.assertIn("无权代理", blocked.text)
        after = next(
            item for item in self.client.get("/api/apps").json() if item["app_id"] == "demo-echo"
        )["request_count"]
        self.assertEqual(before, after)

    def test_external_proxy_strips_spoofed_gateway_headers(self) -> None:
        self._login("admin", "correct-admin-password")
        response = self.client.get(
            "/api/apps/v1/demo-echo/hello",
            headers={"X-Gateway-Actor-Name": "spoofed", "X-Gateway-Capability": "spoofed"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        headers = response.json()["headers"]
        self.assertEqual(headers["x_gateway_actor_name"], "admin")
        self.assertEqual(headers["x_gateway_capability"], "demo-echo.hello.read")

    def test_stage2_body_limit_websocket_and_management_surfaces(self) -> None:
        self._login("admin", "correct-admin-password")
        csrf = self.client.get("/api/auth/v1/csrf").json()["csrf_token"]
        too_large = self.client.post(
            "/api/apps/v1/demo-echo/echo",
            content=b"x" * 2048,
            headers={"Content-Type": "application/octet-stream", "X-CSRF-Token": csrf},
        )
        self.assertEqual(too_large.status_code, 413, too_large.text)

        self.client.post("/api/apps/demo-echo/start", headers={"X-CSRF-Token": csrf})
        with self.client.websocket_connect(
            "/apps/demo-echo/ws", headers={"Origin": "http://127.0.0.1"}
        ) as socket:
            socket.send_text("stage2")
            self.assertEqual(socket.receive_text(), "echo:stage2")

        registry = self.client.get("/dashboard/apps?tab=registry")
        settings = self.client.get("/dashboard/settings?tab=notifications")
        notifications = self.client.get("/dashboard/notifications")
        self.assertIn("应用注册表", registry.text)
        self.assertIn("lu.yuanqi.2005@gmail.com", settings.text)
        self.assertIn("通知中心", notifications.text)
        registry_api = self.client.get("/api/registry/v1/apps")
        self.assertEqual(registry_api.status_code, 200)
        self.assertEqual(registry_api.json()["items"][0]["app_id"], "demo-echo")
        queued = self.client.post(
            "/api/notifications/v1/test", headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(queued.status_code, 200, queued.text)
        self.assertEqual(queued.json()["notification"]["status"], "in_app")
        export = self.client.get("/api/audit/v1/export?format=csv")
        self.assertEqual(export.status_code, 200)
        self.assertIn("text/csv", export.headers["content-type"])

    def test_goal_driven_ui_shell_responsive_assets_and_role_navigation(self) -> None:
        login = self.client.get("/login")
        self.assertIn("一个入口，管理所有本地服务", login.text)
        css = self.client.get("/assets/gateway.css")
        js = self.client.get("/assets/gateway.js")
        self.assertEqual(css.status_code, 200)
        self.assertEqual(js.status_code, 200)
        self.assertIn("--nav-expanded: 232px", css.text)
        self.assertIn("@media (max-width: 719px)", css.text)
        self.assertIn("prefers-reduced-motion", css.text)
        self.assertIn("gateway-nav-mode", js.text)
        self.assertIn("data-auto-submit", js.text)

        admin = self._login("admin", "correct-admin-password")
        self.assertEqual(admin.text.count('class="global-navigation"'), 1)
        for href in (
            "/dashboard",
            "/dashboard/apps",
            "/dashboard/security",
            "/dashboard/activity",
            "/dashboard/settings",
        ):
            self.assertIn(f'href="{href}"', admin.text)
        self.assertNotIn('http-equiv="refresh"', admin.text)
        self.assertIn('aria-current="page"', admin.text)
        filtered = self.client.get("/dashboard/apps?q=Demo&state=all")
        self.assertIn("back=apps&amp;state=all&amp;q=Demo", filtered.text)
        detail_logs = self.client.get("/dashboard/apps/demo-echo?tab=logs")
        self.assertIn("back=detail&amp;tab=logs", detail_logs.text)

        self.client.cookies.clear()
        guest = self._login("guest", "correct-guest-password")
        self.assertNotIn('href="/dashboard/security"', guest.text)
        self.assertNotIn('href="/dashboard/settings"', guest.text)
        apps = self.client.get("/dashboard/apps")
        self.assertNotIn("/dashboard/apps/demo-echo/start", apps.text)
        self.assertNotIn("/dashboard/apps/demo-echo/stop", apps.text)

    def test_security_workspace_audit_and_request_code_api_flow(self) -> None:
        registration = self.client.post(
            "/api/auth/v1/devices/register",
            json={"device_name": "UI Test Watcher", "device_type": "test"},
        )
        self.assertEqual(registration.status_code, 200, registration.text)
        request_data = registration.json()

        self._login("admin", "correct-admin-password")
        csrf = self.client.get("/api/auth/v1/csrf").json()["csrf_token"]
        approved = self.client.post(
            f'/api/approvals/v1/{request_data["approval_id"]}/approve',
            json={"request_code": request_data["request_code"], "trust_level": "paired"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["device"]["status"], "active")

        manual = self.client.post(
            "/api/devices/v1/manual",
            json={
                "device_name": "Manual UI Test",
                "device_type": "test",
                "trust_level": "paired",
                "trust_ttl_seconds": 3600,
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(manual.status_code, 200, manual.text)

        security = self.client.get("/dashboard/security")
        approvals = self.client.get("/dashboard/approvals")
        leases = self.client.get("/dashboard/leases")
        activity = self.client.get("/dashboard/activity?tab=audit")
        system = self.client.get("/dashboard/system")
        for page in (security, approvals, leases, activity, system):
            self.assertEqual(page.status_code, 200)
            self.assertIn('class="global-navigation"', page.text)
        self.assertIn("外部访问闭环", security.text)
        self.assertIn("请求码", approvals.text)
        self.assertIn("异常恢复", leases.text)
        self.assertIn("API 审计", activity.text)
        self.assertIn("仅监听 loopback", system.text)

        self.client.get("/api/apps")
        audit = self.client.get("/api/audit/v1?limit=20")
        self.assertEqual(audit.status_code, 200)
        self.assertTrue(audit.json()["items"])
        self.assertTrue(all("client_ip" not in row for row in audit.json()["items"]))
        lease_api = self.client.get("/api/leases/v1?active_only=true&limit=20")
        self.assertEqual(lease_api.status_code, 200)
        self.assertEqual(lease_api.json()["items"], [])


if __name__ == "__main__":
    unittest.main()
