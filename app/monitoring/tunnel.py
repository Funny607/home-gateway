from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.config.schema import TunnelMonitorConfig
from app.events import EventRecorder
from app.security.db import SecurityStore, now_ts


class TunnelMonitor:
    STATE_KEY = "tunnel_health"

    def __init__(
        self,
        *,
        config: TunnelMonitorConfig,
        client: httpx.AsyncClient,
        store: SecurityStore,
        events: EventRecorder,
        logger,
    ) -> None:
        self.config = config
        self.client = client
        self.store = store
        self.events = events
        self.logger = logger
        saved = store.get_system_state(self.STATE_KEY, {})
        self.state: dict[str, Any] = {
            "enabled": config.enabled,
            "public_url": config.public_url,
            "status": saved.get("status", "unknown") if isinstance(saved, dict) else "unknown",
            "consecutive_failures": int(saved.get("consecutive_failures", 0)) if isinstance(saved, dict) else 0,
            "last_checked_at": int(saved.get("last_checked_at", 0)) if isinstance(saved, dict) else 0,
            "last_ok_at": int(saved.get("last_ok_at", 0)) if isinstance(saved, dict) else 0,
            "last_error": str(saved.get("last_error", ""))[:1000] if isinstance(saved, dict) else "",
            "http_status": int(saved.get("http_status", 0)) if isinstance(saved, dict) else 0,
            "failure_started_at": int(saved.get("failure_started_at", 0)) if isinstance(saved, dict) else 0,
            "alert_sent_at": int(saved.get("alert_sent_at", 0)) if isinstance(saved, dict) else 0,
        }

    def snapshot(self) -> dict[str, Any]:
        return dict(self.state)

    async def check_once(self) -> dict[str, Any]:
        if not self.config.enabled:
            self.state.update({"enabled": False, "status": "disabled"})
            self.store.set_system_state(self.STATE_KEY, self.state)
            return self.snapshot()
        previous = str(self.state.get("status", "unknown"))
        now = now_ts()
        ok = False
        status_code = 0
        error = ""
        try:
            response = await self.client.get(
                self.config.public_url,
                timeout=float(self.config.timeout_seconds),
                headers={"User-Agent": "WebUI-Home-Gateway-Tunnel-Monitor/2"},
            )
            status_code = response.status_code
            ok = 200 <= status_code < 300
            if not ok:
                error = f"HTTP {status_code}"
        except httpx.TimeoutException:
            error = "health check timed out"
        except httpx.RequestError as exc:
            error = str(exc)[:1000]

        failures = 0 if ok else int(self.state.get("consecutive_failures", 0)) + 1
        failure_started_at = 0 if ok else int(self.state.get("failure_started_at", 0)) or now
        alert_sent_at = 0 if ok else int(self.state.get("alert_sent_at", 0))
        outage_seconds = max(0, now - failure_started_at) if failure_started_at else 0
        alert_due = bool(
            not ok
            and not alert_sent_at
            and outage_seconds >= self.config.alert_after_seconds
        )
        status = "healthy" if ok else (
            "unhealthy" if failures >= self.config.failure_threshold else "degraded"
        )
        self.state.update(
            {
                "enabled": True,
                "public_url": self.config.public_url,
                "status": status,
                "consecutive_failures": failures,
                "last_checked_at": now,
                "last_ok_at": now if ok else int(self.state.get("last_ok_at", 0)),
                "last_error": error,
                "http_status": status_code,
                "failure_started_at": failure_started_at,
                "alert_sent_at": alert_sent_at,
            }
        )
        self.store.set_system_state(self.STATE_KEY, self.state)
        if status == "unhealthy" and previous != "unhealthy":
            self.events.write("tunnel_unhealthy", reason=error, http_status=status_code)
        elif status == "healthy" and previous in {"degraded", "unhealthy"}:
            self.events.write("tunnel_recovered", http_status=status_code)
        if alert_due:
            self.events.write(
                "tunnel_recovery_failed",
                reason=error,
                http_status=status_code,
                outage_seconds=outage_seconds,
                failure_started_at=failure_started_at,
                consecutive_failures=failures,
            )
            self.state["alert_sent_at"] = now
            self.store.set_system_state(self.STATE_KEY, self.state)
        return self.snapshot()


async def tunnel_monitor_loop(monitor: TunnelMonitor) -> None:
    while True:
        try:
            await monitor.check_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            monitor.logger.exception("Tunnel monitor failed: %s", exc)
        await asyncio.sleep(monitor.config.interval_seconds)
