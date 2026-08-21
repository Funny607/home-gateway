from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from app.config.schema import NotificationConfig, TunnelMonitorConfig
from app.monitoring.tunnel import TunnelMonitor
from app.notifications.service import NotificationService
from app.security.db import SecurityStore


class EventSink:
    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []

    def write(self, event_type: str, **fields: object) -> None:
        self.items.append({"event_type": event_type, **fields})


class TunnelAlertPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_persistent_outage_alerts_once_after_one_hour_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="t" * 48)
            events = EventSink()
            config = TunnelMonitorConfig(
                public_url="https://gateway.test/readyz",
                interval_seconds=60,
                timeout_seconds=1,
                failure_threshold=1,
                alert_after_seconds=3600,
            )

            async def handler(_request: httpx.Request) -> httpx.Response:
                return httpx.Response(530)

            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                monitor = TunnelMonitor(
                    config=config,
                    client=client,
                    store=store,
                    events=events,
                    logger=logging.getLogger("tunnel-alert-test"),
                )
                with patch("app.monitoring.tunnel.now_ts", return_value=1000):
                    first = await monitor.check_once()
                self.assertEqual(first["failure_started_at"], 1000)
                self.assertEqual(first["alert_sent_at"], 0)

                # Recreate the monitor to prove the outage timer survives Gateway restarts.
                monitor = TunnelMonitor(
                    config=config,
                    client=client,
                    store=store,
                    events=events,
                    logger=logging.getLogger("tunnel-alert-test"),
                )
                with patch("app.monitoring.tunnel.now_ts", return_value=4599):
                    before_hour = await monitor.check_once()
                self.assertEqual(before_hour["alert_sent_at"], 0)
                self.assertFalse(
                    any(item["event_type"] == "tunnel_recovery_failed" for item in events.items)
                )

                with patch("app.monitoring.tunnel.now_ts", return_value=4600):
                    due = await monitor.check_once()
                self.assertEqual(due["alert_sent_at"], 4600)

                with patch("app.monitoring.tunnel.now_ts", return_value=8200):
                    await monitor.check_once()

            delayed = [
                item for item in events.items if item["event_type"] == "tunnel_recovery_failed"
            ]
            self.assertEqual(len(delayed), 1)
            self.assertEqual(delayed[0]["failure_started_at"], 1000)
            self.assertEqual(delayed[0]["outage_seconds"], 3600)

    async def test_recovery_resets_incident_without_sending_recovery_email(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="r" * 48)
            events = EventSink()
            responses = iter((530, 200, 530))

            async def handler(_request: httpx.Request) -> httpx.Response:
                return httpx.Response(next(responses))

            config = TunnelMonitorConfig(
                public_url="https://gateway.test/readyz",
                failure_threshold=1,
                alert_after_seconds=3600,
            )
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                monitor = TunnelMonitor(
                    config=config,
                    client=client,
                    store=store,
                    events=events,
                    logger=logging.getLogger("tunnel-recovery-test"),
                )
                with patch("app.monitoring.tunnel.now_ts", return_value=1000):
                    await monitor.check_once()
                with patch("app.monitoring.tunnel.now_ts", return_value=1200):
                    recovered = await monitor.check_once()
                self.assertEqual(recovered["failure_started_at"], 0)
                self.assertEqual(recovered["alert_sent_at"], 0)
                with patch("app.monitoring.tunnel.now_ts", return_value=1300):
                    next_incident = await monitor.check_once()
                self.assertEqual(next_incident["failure_started_at"], 1300)

            notifications = NotificationService(
                store,
                NotificationConfig(),
                logging.getLogger("tunnel-notification-test"),
            )
            for event in events.items:
                notifications.handle_event(event)
            rows = store.fetch_all(
                "SELECT category, status, email_requested FROM notification_record ORDER BY created_at"
            )
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row["status"] == "in_app" for row in rows))
            self.assertTrue(all(int(row["email_requested"]) == 0 for row in rows))

    async def test_only_delayed_recovery_failure_is_queued_for_email(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="n" * 48)
            notifications = NotificationService(
                store,
                NotificationConfig(),
                logging.getLogger("tunnel-notification-test"),
            )
            notifications.handle_event(
                {"event_type": "tunnel_unhealthy", "reason": "HTTP 530"}
            )
            notifications.handle_event(
                {"event_type": "tunnel_recovered", "http_status": 200}
            )
            delayed = {
                "event_type": "tunnel_recovery_failed",
                "reason": "HTTP 530",
                "http_status": 530,
                "failure_started_at": 1000,
                "outage_seconds": 3600,
                "consecutive_failures": 61,
            }
            notifications.handle_event(delayed)
            notifications.handle_event(delayed)

            rows = store.fetch_all(
                """
                SELECT category, status, email_requested, repeat_count, title
                FROM notification_record ORDER BY created_at, notification_id
                """
            )
            self.assertEqual(len(rows), 3)
            queued = [row for row in rows if row["status"] == "queued"]
            self.assertEqual(len(queued), 1)
            self.assertEqual(queued[0]["category"], "tunnel_failure")
            self.assertEqual(int(queued[0]["email_requested"]), 1)
            self.assertEqual(int(queued[0]["repeat_count"]), 2)
            self.assertIn("1 小时", queued[0]["title"])

    async def test_upgrade_suppresses_pending_transient_tunnel_mail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SecurityStore(Path(directory) / "gateway.sqlite3", pepper="u" * 48)
            legacy_config = NotificationConfig(
                send_categories=["tunnel_failure", "tunnel_recovery"]
            )
            legacy = NotificationService(
                store,
                legacy_config,
                logging.getLogger("legacy-tunnel-notification-test"),
            )
            legacy.enqueue(
                category="tunnel_failure",
                severity="danger",
                title="公网隧道不可用",
                message="HTTP 530",
                force=True,
                metadata={"event_type": "tunnel_unhealthy"},
            )
            legacy.enqueue(
                category="tunnel_recovery",
                severity="success",
                title="公网隧道已恢复",
                message="恢复正常",
                force=True,
                metadata={"event_type": "tunnel_recovered"},
            )
            self.assertEqual(
                store.fetch_one(
                    "SELECT COUNT(*) AS count FROM notification_record WHERE status='queued'"
                )["count"],
                2,
            )

            NotificationService(
                store,
                NotificationConfig(),
                logging.getLogger("new-tunnel-notification-test"),
            )
            rows = store.fetch_all(
                "SELECT status, email_requested FROM notification_record ORDER BY created_at"
            )
            self.assertTrue(all(row["status"] == "in_app" for row in rows))
            self.assertTrue(all(int(row["email_requested"]) == 0 for row in rows))


if __name__ == "__main__":
    unittest.main()
