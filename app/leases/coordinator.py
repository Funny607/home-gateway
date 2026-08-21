from __future__ import annotations

import asyncio
import secrets
from collections.abc import Iterable
from typing import Any

import httpx

from app.config.schema import AdapterActionConfig, CapabilityConfig, LeasePolicyConfig
from app.lifecycle.manager import LifecycleManager
from app.security.db import json_dumps, json_loads, now_ts, redact_metadata
from app.security.service import SecurityError, SecurityService


class LeaseCoordinator:
    """Reference-counted fail-safe leases backed by app manifest adapters."""

    def __init__(
        self,
        *,
        manager: LifecycleManager,
        client: httpx.AsyncClient,
        security: SecurityService,
    ) -> None:
        self.manager = manager
        self.client = client
        self.security = security
        self._locks: dict[str, asyncio.Lock] = {}

    def resolve_capability(
        self, capability_id: str
    ) -> tuple[str, CapabilityConfig, LeasePolicyConfig]:
        for app_id, state in self.manager.apps.items():
            for capability in state.config.capabilities:
                if capability.id == capability_id and capability.lease_policy is not None:
                    return app_id, capability, capability.lease_policy
        raise SecurityError(404, "lease_capability_not_found", "lease capability was not found")

    def _policy_for_row(self, row: dict[str, Any]) -> LeasePolicyConfig:
        _, _, policy = self.resolve_capability(str(row["capability"]))
        return policy

    def _resource(self, capability: CapabilityConfig, policy: LeasePolicyConfig) -> str:
        return policy.resource_key or capability.id

    def _lock_for(self, resource_key: str) -> asyncio.Lock:
        return self._locks.setdefault(resource_key, asyncio.Lock())

    @staticmethod
    def public(row: Any) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["metadata"] = json_loads(item.pop("raw_json", "{}"), {})
        return item

    async def _ensure_app(self, app_id: str, capability: CapabilityConfig) -> str:
        state = self.manager.get_app(app_id)
        if state.state != "running" or state.runtime is None:
            auto_start = (
                capability.auto_start
                if capability.auto_start is not None
                else state.config.api.auto_start
            )
            if not auto_start:
                raise SecurityError(409, "app_not_running", "target app is stopped")
            await self.manager.ensure_started(app_id)
            state = self.manager.get_app(app_id)
        if state.runtime is None:
            raise SecurityError(503, "app_unavailable", "target app has no runtime")
        return state.runtime.internal_url

    async def _action(
        self,
        *,
        app_id: str,
        capability: CapabilityConfig,
        action: AdapterActionConfig,
    ) -> tuple[bool, int, str]:
        try:
            origin = await self._ensure_app(app_id, capability)
            response = await self.client.request(
                action.method,
                origin + action.path,
                json=action.json_body or None,
                timeout=float(action.timeout_seconds),
            )
        except SecurityError:
            raise
        except httpx.TimeoutException:
            return False, 504, "adapter timed out"
        except httpx.RequestError as exc:
            return False, 502, str(exc)[:500]
        ok = response.status_code in set(action.success_statuses)
        return ok, response.status_code, "" if ok else response.text[:500]

    @staticmethod
    def _read_json_path(data: Any, dotted: str) -> Any:
        value = data
        for key in dotted.split("."):
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
        return value

    async def _probe(
        self,
        *,
        app_id: str,
        capability: CapabilityConfig,
        policy: LeasePolicyConfig,
    ) -> str:
        try:
            origin = await self._ensure_app(app_id, capability)
            response = await self.client.request(
                policy.probe.method,
                origin + policy.probe.path,
                timeout=float(policy.probe.timeout_seconds),
            )
            if response.status_code < 200 or response.status_code >= 300:
                return "unknown"
            value = str(self._read_json_path(response.json(), policy.probe.json_path)).lower()
        except (SecurityError, httpx.HTTPError, ValueError, AttributeError):
            return "unknown"
        if value in set(policy.probe.active_values):
            return "active"
        if value in set(policy.probe.released_values):
            return "released"
        return "unknown"

    async def create(
        self,
        *,
        actor: dict[str, Any],
        capability_id: str,
        lease_seconds: int,
        request_id: str,
    ) -> dict[str, Any]:
        app_id, capability, policy = self.resolve_capability(capability_id)
        resource_key = self._resource(capability, policy)
        async with self._lock_for(resource_key):
            now = now_ts()
            requested = max(1, int(lease_seconds))
            duration = max(60, min(requested, policy.max_lease_seconds))
            with self.security.store.transaction() as conn:
                existing = conn.execute(
                    """
                    SELECT * FROM lease_record
                    WHERE device_id=? AND capability=?
                      AND status IN ('activating','active','releasing')
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (actor["device_id"], capability_id),
                ).fetchone()
                if existing is not None:
                    if existing["status"] != "active":
                        raise SecurityError(
                            409, "lease_recovery_in_progress", "existing lease is being recovered"
                        )
                    expires_at = min(
                        max(int(existing["expires_at"]), now + duration),
                        int(existing["max_expires_at"]),
                    )
                    conn.execute(
                        "UPDATE lease_record SET expires_at=?, last_heartbeat_at=? WHERE lease_id=?",
                        (expires_at, now, existing["lease_id"]),
                    )
                    row = conn.execute(
                        "SELECT * FROM lease_record WHERE lease_id=?", (existing["lease_id"],)
                    ).fetchone()
                    return {
                        "lease": self.public(row),
                        "reused": True,
                        "heartbeat_interval_seconds": policy.heartbeat_interval_seconds,
                    }
                holder = conn.execute(
                    """
                    SELECT 1 FROM lease_record
                    WHERE resource_key=? AND status='active' AND expires_at>? LIMIT 1
                    """,
                    (resource_key, now),
                ).fetchone()
                lease_id = f"lease_{secrets.token_urlsafe(18)}"
                conn.execute(
                    """
                    INSERT INTO lease_record (
                        lease_id, device_id, grant_id, target_app, capability, resource_key,
                        status, created_at, expires_at, max_expires_at,
                        last_heartbeat_at, next_reconcile_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, 'activating', ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        lease_id,
                        actor["device_id"],
                        actor["grant_id"],
                        app_id,
                        capability_id,
                        resource_key,
                        now,
                        now + duration,
                        now + policy.max_lease_seconds,
                        now,
                        json_dumps(redact_metadata({"request_id": request_id, "requested": requested})),
                    ),
                )

            ok, status, error = (True, 200, "shared resource already active")
            if holder is None:
                ok, status, error = await self._action(
                    app_id=app_id, capability=capability, action=policy.acquire
                )
                if not ok and await self._probe(
                    app_id=app_id, capability=capability, policy=policy
                ) == "active":
                    ok, error = True, "already active"
            with self.security.store.transaction() as conn:
                conn.execute(
                    """
                    UPDATE lease_record
                    SET status=?, release_reason=?, next_reconcile_at=?,
                        last_reconcile_error=?
                    WHERE lease_id=?
                    """,
                    (
                        "active" if ok else "releasing",
                        "" if ok else "activation outcome uncertain",
                        0 if ok else now_ts() + policy.reconcile_retry_seconds,
                        "" if ok else error,
                        lease_id,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                ).fetchone()
            if not ok:
                self.manager.events.write(
                    "lease_reconcile_failed",
                    app_id=app_id,
                    resource_key=resource_key,
                    reason=error or f"adapter status {status}",
                )
                raise SecurityError(status, "lease_activation_failed", error or "lease activation failed")
            self.manager.events.write(
                "lease_acquired", app_id=app_id, resource_key=resource_key, lease_id=lease_id
            )
            return {
                "lease": self.public(row),
                "reused": False,
                "heartbeat_interval_seconds": policy.heartbeat_interval_seconds,
            }

    async def heartbeat(self, *, actor: dict[str, Any], lease_id: str) -> dict[str, Any]:
        now = now_ts()
        with self.security.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
            ).fetchone()
            if row is None:
                raise SecurityError(404, "lease_not_found", "lease was not found")
            if row["device_id"] != actor["device_id"]:
                raise SecurityError(403, "lease_device_mismatch", "lease belongs to another device")
            if row["status"] != "active" or int(row["expires_at"]) <= now:
                raise SecurityError(409, "lease_not_active", "lease is not active")
            policy = self._policy_for_row(dict(row))
            new_expiry = min(
                max(int(row["expires_at"]), now + policy.heartbeat_interval_seconds * 3),
                int(row["max_expires_at"]),
            )
            conn.execute(
                "UPDATE lease_record SET expires_at=?, last_heartbeat_at=? WHERE lease_id=?",
                (new_expiry, now, lease_id),
            )
            updated = conn.execute(
                "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
            ).fetchone()
        return {"lease": self.public(updated), "heartbeat_interval_seconds": policy.heartbeat_interval_seconds}

    async def release(
        self, *, actor: dict[str, Any] | None, lease_id: str, reason: str
    ) -> dict[str, Any]:
        row = self.security.store.fetch_one(
            "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
        )
        if row is None:
            raise SecurityError(404, "lease_not_found", "lease was not found")
        if actor is not None and row["device_id"] != actor["device_id"]:
            raise SecurityError(403, "lease_device_mismatch", "lease belongs to another device")
        policy = self._policy_for_row(row)
        resource_key = str(row.get("resource_key") or policy.resource_key or row["capability"])
        async with self._lock_for(resource_key):
            with self.security.store.transaction() as conn:
                current = conn.execute(
                    "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                ).fetchone()
                if current is None:
                    raise SecurityError(404, "lease_not_found", "lease was not found")
                if current["status"] in {"released", "expired"}:
                    return {"lease": self.public(current), "recovered": True}
                conn.execute(
                    """
                    UPDATE lease_record SET status='releasing', release_reason=?, next_reconcile_at=0
                    WHERE lease_id=?
                    """,
                    (reason[:1000], lease_id),
                )
                other = conn.execute(
                    """
                    SELECT 1 FROM lease_record
                    WHERE lease_id!=? AND resource_key=? AND status='active' AND expires_at>?
                    LIMIT 1
                    """,
                    (lease_id, resource_key, now_ts()),
                ).fetchone()
                if other is not None:
                    conn.execute(
                        "UPDATE lease_record SET status='released', released_at=? WHERE lease_id=?",
                        (now_ts(), lease_id),
                    )
                    done = conn.execute(
                        "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                    ).fetchone()
                    return {"lease": self.public(done), "recovered": True}

            app_id, capability, policy = self.resolve_capability(str(row["capability"]))
            try:
                ok, status, error = await self._action(
                    app_id=app_id, capability=capability, action=policy.release
                )
                if not ok and await self._probe(
                    app_id=app_id, capability=capability, policy=policy
                ) == "released":
                    ok, error = True, "already released"
            except SecurityError as exc:
                ok, status, error = False, exc.status_code, str(exc)
            now = now_ts()
            with self.security.store.transaction() as conn:
                if ok:
                    final = "expired" if "expired" in reason or "heartbeat" in reason else "released"
                    conn.execute(
                        """
                        UPDATE lease_record SET status=?, released_at=?, next_reconcile_at=0,
                            last_reconcile_at=?, last_reconcile_error=''
                        WHERE lease_id=?
                        """,
                        (final, now, now, lease_id),
                    )
                else:
                    current = conn.execute(
                        "SELECT reconcile_attempts FROM lease_record WHERE lease_id=?", (lease_id,)
                    ).fetchone()
                    attempts = int(current["reconcile_attempts"] if current else 0) + 1
                    delay = min(policy.reconcile_retry_seconds * (2 ** min(attempts - 1, 6)), 3600)
                    conn.execute(
                        """
                        UPDATE lease_record SET status='releasing', reconcile_attempts=?,
                            next_reconcile_at=?, last_reconcile_at=?, last_reconcile_error=?
                        WHERE lease_id=?
                        """,
                        (attempts, now + delay, now, error[:1000], lease_id),
                    )
                updated = conn.execute(
                    "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                ).fetchone()
            if ok:
                self.manager.events.write(
                    "lease_recovered", app_id=app_id, resource_key=resource_key, lease_id=lease_id
                )
            else:
                self.manager.events.write(
                    "lease_reconcile_failed",
                    app_id=app_id,
                    resource_key=resource_key,
                    lease_id=lease_id,
                    reason=error or f"adapter status {status}",
                )
            return {"lease": self.public(updated), "recovered": ok}

    async def reconcile_once(self) -> int:
        self.security.store.expire_records()
        now = now_ts()
        with self.security.store.transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM lease_record WHERE status='activating' ORDER BY created_at"
            ).fetchall()
            for row in rows:
                try:
                    policy = self._policy_for_row(dict(row))
                except SecurityError:
                    continue
                if int(row["created_at"]) + policy.activation_grace_seconds <= now:
                    conn.execute(
                        """
                        UPDATE lease_record SET status='releasing',
                            release_reason='activation recovery', next_reconcile_at=0
                        WHERE lease_id=?
                        """,
                        (row["lease_id"],),
                    )
            due = conn.execute(
                """
                SELECT * FROM lease_record
                WHERE (status='active' AND expires_at<=?)
                   OR (status='releasing' AND next_reconcile_at<=?)
                ORDER BY created_at
                """,
                (now, now),
            ).fetchall()
        recovered = 0
        for raw in due:
            row = dict(raw)
            reason = str(row.get("release_reason") or "")
            if row["status"] == "active":
                reason = "lease expired or heartbeat missed"
            result = await self.release(actor=None, lease_id=row["lease_id"], reason=reason)
            recovered += int(bool(result["recovered"]))

        # Detect external drift for every referenced active resource.
        active_rows = self.security.store.fetch_all(
            """
            SELECT * FROM lease_record WHERE status='active' AND expires_at>?
            GROUP BY resource_key ORDER BY created_at
            """,
            (now_ts(),),
        )
        for row in active_rows:
            try:
                app_id, capability, policy = self.resolve_capability(str(row["capability"]))
                observed = await self._probe(app_id=app_id, capability=capability, policy=policy)
                if observed == "released":
                    ok, _, error = await self._action(
                        app_id=app_id, capability=capability, action=policy.acquire
                    )
                    if not ok:
                        self.manager.events.write(
                            "lease_reconcile_failed",
                            app_id=app_id,
                            resource_key=row.get("resource_key") or policy.resource_key,
                            reason=error or "active resource drift could not be corrected",
                        )
            except (SecurityError, KeyError):
                continue
        return recovered

    def for_actor(
        self, *, actor: dict[str, Any], capability_id: str = ""
    ) -> list[dict[str, Any]]:
        clauses = ["device_id=?"]
        params: list[Any] = [actor["device_id"]]
        if capability_id:
            clauses.append("capability=?")
            params.append(capability_id)
        rows = self.security.store.fetch_all(
            f"SELECT * FROM lease_record WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT 200",
            tuple(params),
        )
        return [self.public(row) or {} for row in rows]


async def lease_monitor_loop(coordinator: LeaseCoordinator, interval_seconds: int) -> None:
    while True:
        try:
            await coordinator.reconcile_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            coordinator.manager.logger.exception("Lease recovery monitor failed: %s", exc)
        await asyncio.sleep(interval_seconds)
