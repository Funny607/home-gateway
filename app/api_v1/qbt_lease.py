from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

import httpx
from fastapi import APIRouter, Request

from app.api_v1.errors import gateway_error
from app.api_v1.request_id import get_or_create_request_id
from app.lifecycle.manager import LifecycleManager
from app.security.db import json_dumps, json_loads, now_ts
from app.security.http import bearer_token, client_ip, read_json_object, reject_unknown_fields
from app.security.service import SecurityError, SecurityService


APP_ID = "qbt-mode"
LEASE_CAPABILITY = "qbt-mode.mode.lease_gaming"


def _lease_public(row) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    data["metadata"] = json_loads(data.pop("raw_json", "{}"), {})
    return data


def _error(request_id: str, exc: SecurityError):
    return gateway_error(
        code=exc.code.upper(),
        message=str(exc),
        request_id=request_id,
        status_code=exc.status_code,
    )


def _lease_policy(manager: LifecycleManager):
    try:
        app = manager.get_app(APP_ID).config
    except KeyError as exc:
        raise SecurityError(404, "app_not_found", "qbt-mode is not registered") from exc
    for capability in app.capabilities:
        if capability.id == LEASE_CAPABILITY and capability.lease_policy is not None:
            return capability, capability.lease_policy
    raise SecurityError(503, "lease_policy_missing", "qbt-mode lease policy is not configured")


async def _set_mode(
    manager: LifecycleManager,
    client: httpx.AsyncClient,
    mode: str,
) -> tuple[bool, int, str]:
    app_state = manager.get_app(APP_ID)
    if app_state.state != "running" or app_state.runtime is None:
        return False, 409, "qbt-mode is not running"
    path = "/api/mode/gaming" if mode == "gaming" else "/api/mode/normal"
    try:
        response = await client.post(
            f"{app_state.runtime.internal_url}{path}", timeout=15.0
        )
    except httpx.TimeoutException:
        return False, 504, "qbt-mode timed out"
    except httpx.RequestError as exc:
        return False, 502, str(exc)
    if 200 <= response.status_code < 300:
        return True, response.status_code, ""
    if response.status_code == 409:
        try:
            status = await client.get(
                f"{app_state.runtime.internal_url}/api/mode/status", timeout=5.0
            )
            if status.status_code == 200:
                data = status.json()
                current = str(
                    data.get("mode")
                    or data.get("current_mode")
                    or (data.get("data") or {}).get("mode")
                    or ""
                ).lower()
                if current == mode:
                    return True, response.status_code, "already in requested mode"
        except (httpx.HTTPError, ValueError, AttributeError):
            pass
    return False, response.status_code, response.text[:500]


async def _current_mode(manager: LifecycleManager, client: httpx.AsyncClient) -> str:
    app_state = manager.get_app(APP_ID)
    if app_state.state != "running" or app_state.runtime is None:
        return ""
    try:
        response = await client.get(
            f"{app_state.runtime.internal_url}/api/mode/status", timeout=5.0
        )
        if response.status_code != 200:
            return ""
        data = response.json()
        return str(
            data.get("mode")
            or data.get("current_mode")
            or (data.get("data") or {}).get("mode")
            or ""
        ).lower()
    except (httpx.HTTPError, ValueError, AttributeError):
        return ""


async def _finish_release(
    *,
    service: SecurityService,
    manager: LifecycleManager,
    client: httpx.AsyncClient,
    lease_id: str,
    reason: str,
) -> bool:
    store = service.store
    with store.transaction() as conn:
        lease = conn.execute(
            "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
        ).fetchone()
        if lease is None:
            return True
        if lease["status"] in {"released", "expired"}:
            return True
        conn.execute(
            "UPDATE lease_record SET status='releasing', release_reason=? WHERE lease_id=?",
            (reason, lease_id),
        )
        other = conn.execute(
            """
            SELECT 1 FROM lease_record
            WHERE lease_id!=? AND target_app=? AND capability=? AND status='active' AND expires_at>?
            LIMIT 1
            """,
            (lease_id, APP_ID, LEASE_CAPABILITY, now_ts()),
        ).fetchone()
        if other:
            conn.execute(
                "UPDATE lease_record SET status='released', released_at=? WHERE lease_id=?",
                (now_ts(), lease_id),
            )
            return True

    try:
        app_state = manager.get_app(APP_ID)
        if app_state.state != "running" or app_state.runtime is None:
            await manager.ensure_started(APP_ID)
    except Exception as exc:
        ok, status, error = False, 503, f"could not start qbt-mode for recovery: {exc}"
    else:
        ok, status, error = await _set_mode(manager, client, "normal")
    with store.transaction() as conn:
        if ok:
            final_status = "expired" if "expired" in reason or "heartbeat" in reason else "released"
            conn.execute(
                "UPDATE lease_record SET status=?, released_at=?, release_reason=? WHERE lease_id=?",
                (final_status, now_ts(), reason, lease_id),
            )
        else:
            row = conn.execute(
                "SELECT raw_json FROM lease_record WHERE lease_id=?", (lease_id,)
            ).fetchone()
            raw = json_loads(row["raw_json"] if row else "{}", {})
            raw.update(
                {
                    "last_release_attempt_at": now_ts(),
                    "last_release_status": status,
                    "last_release_error": error,
                }
            )
            conn.execute(
                "UPDATE lease_record SET status='releasing', raw_json=? WHERE lease_id=?",
                (json_dumps(raw), lease_id),
            )
    return ok


async def cleanup_leases_once(
    *,
    service: SecurityService,
    manager: LifecycleManager,
    client: httpx.AsyncClient,
) -> int:
    now = now_ts()
    with service.store.transaction() as conn:
        conn.execute(
            "UPDATE lease_record SET status='releasing', release_reason='activation recovery' WHERE status='activating' AND created_at<=?",
            (now - 30,),
        )
        rows = conn.execute(
            """
            SELECT * FROM lease_record
            WHERE (status='active' AND expires_at<=?) OR status='releasing'
            ORDER BY created_at
            """,
            (now,),
        ).fetchall()
    recovered = 0
    for row in rows:
        reason = str(row["release_reason"] or "")
        if row["status"] == "active":
            reason = "lease expired or heartbeat missed"
        if await _finish_release(
            service=service,
            manager=manager,
            client=client,
            lease_id=row["lease_id"],
            reason=reason,
        ):
            recovered += 1
    with service.store.read() as conn:
        active = conn.execute(
            """
            SELECT 1 FROM lease_record
            WHERE target_app=? AND capability=? AND status='active' AND expires_at>?
            LIMIT 1
            """,
            (APP_ID, LEASE_CAPABILITY, now_ts()),
        ).fetchone()
    if active:
        try:
            app_state = manager.get_app(APP_ID)
            if app_state.state != "running" or app_state.runtime is None:
                await manager.ensure_started(APP_ID)
            if await _current_mode(manager, client) != "gaming":
                ok, _, error = await _set_mode(manager, client, "gaming")
                if not ok:
                    manager.logger.warning("Could not reconcile active gaming lease: %s", error)
        except KeyError:
            pass
    return recovered


async def qbt_lease_monitor_loop(
    *,
    get_manager: Callable[[], LifecycleManager],
    get_http_client: Callable[[], httpx.AsyncClient],
    get_security_service: Callable[[], SecurityService],
    interval_seconds: int = 15,
) -> None:
    while True:
        try:
            await cleanup_leases_once(
                service=get_security_service(),
                manager=get_manager(),
                client=get_http_client(),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            get_manager().logger.exception("Lease recovery monitor failed: %s", exc)
        await asyncio.sleep(interval_seconds)


def build_qbt_lease_router(
    *,
    get_manager: Callable[[], LifecycleManager],
    get_http_client: Callable[[], httpx.AsyncClient],
    get_security_service: Callable[[], SecurityService],
) -> APIRouter:
    router = APIRouter(prefix="/api/leases/v1/qbt-mode/gaming", tags=["qbt-lease"])

    def actor(request: Request) -> dict[str, Any]:
        return get_security_service().verify_access_token(
            bearer_token(request),
            target_app=APP_ID,
            capability=LEASE_CAPABILITY,
            consume=False,
        )

    def audit(request: Request, request_id: str, who: dict, action: str, status: int, success: bool) -> None:
        get_security_service().store.write_api_audit(
            request_id=request_id,
            actor_type="device_token",
            actor_name=who.get("actor_name", ""),
            device_id=who.get("device_id", ""),
            source_id=who.get("source_id", ""),
            client_name=who.get("client_name", ""),
            grant_id=who.get("grant_id", ""),
            token_id=who.get("token_id", ""),
            target_app=APP_ID,
            capability=LEASE_CAPABILITY,
            method=request.method,
            path=str(request.url.path),
            upstream_path=action,
            status_code=status,
            success=success,
            duration_ms=0,
            error_code="" if success else "LEASE_OPERATION_FAILED",
            risk_level=who.get("risk_level", "medium_high"),
            client_ip=client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:512],
        )

    @router.post("/lease")
    async def create_lease(request: Request):
        request_id = get_or_create_request_id(request)
        who: dict[str, Any] = {}
        try:
            who = actor(request)
            if who.get("token_type") == "one_time":
                raise SecurityError(403, "one_time_not_allowed", "lease requires a renewable access token")
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {"lease_seconds"})
            capability, policy = _lease_policy(get_manager())
            requested = int(payload.get("lease_seconds", 300) or 300)
            lease_seconds = max(60, min(requested, policy.max_lease_seconds))
            app_state = get_manager().get_app(APP_ID)
            if app_state.state != "running" or app_state.runtime is None:
                auto_start = capability.auto_start if capability.auto_start is not None else app_state.config.api.auto_start
                if not auto_start:
                    raise SecurityError(409, "app_not_running", "qbt-mode is stopped and auto-start is disabled")
                await get_manager().ensure_started(APP_ID)
            now = now_ts()
            lease_id = f"lease_{__import__('secrets').token_urlsafe(18)}"
            renewed = None
            with get_security_service().store.transaction() as conn:
                existing = conn.execute(
                    """
                    SELECT * FROM lease_record
                    WHERE device_id=? AND capability=? AND status IN ('activating','active','releasing')
                    """,
                    (who["device_id"], LEASE_CAPABILITY),
                ).fetchone()
                if existing:
                    if existing["status"] != "active":
                        raise SecurityError(409, "lease_recovery_in_progress", "existing lease is being recovered")
                    new_expiry = min(
                        max(int(existing["expires_at"]), now + lease_seconds),
                        int(existing["max_expires_at"]),
                    )
                    conn.execute(
                        "UPDATE lease_record SET expires_at=?, last_heartbeat_at=? WHERE lease_id=?",
                        (new_expiry, now, existing["lease_id"]),
                    )
                    updated = conn.execute(
                        "SELECT * FROM lease_record WHERE lease_id=?", (existing["lease_id"],)
                    ).fetchone()
                    renewed = _lease_public(updated)
                else:
                    conn.execute(
                    """
                    INSERT INTO lease_record (
                        lease_id, device_id, grant_id, target_app, capability, resource_key, status,
                        created_at, expires_at, max_expires_at, last_heartbeat_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, 'activating', ?, ?, ?, ?, ?)
                    """,
                        (
                            lease_id,
                            who["device_id"],
                            who["grant_id"],
                            APP_ID,
                            LEASE_CAPABILITY,
                            policy.resource_key or LEASE_CAPABILITY,
                            now,
                            now + lease_seconds,
                            now + policy.max_lease_seconds,
                            now,
                            json_dumps({"request_id": request_id, "requested_seconds": requested}),
                        ),
                    )
            if renewed is not None:
                audit(request, request_id, who, "lease-renew", 200, True)
                return {
                    "ok": True,
                    "request_id": request_id,
                    "reused": True,
                    "lease": renewed,
                    "heartbeat_interval_seconds": policy.heartbeat_interval_seconds,
                }
            ok, status, message = await _set_mode(get_manager(), get_http_client(), "gaming")
            with get_security_service().store.transaction() as conn:
                conn.execute(
                    "UPDATE lease_record SET status=?, release_reason=? WHERE lease_id=?",
                    ("active" if ok else "releasing", None if ok else "activation outcome uncertain", lease_id),
                )
                lease = conn.execute(
                    "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                ).fetchone()
            audit(request, request_id, who, "lease", status, ok)
            if not ok:
                raise SecurityError(status, "upstream_error", message or "failed to enter gaming mode")
            return {
                "ok": True,
                "request_id": request_id,
                "reused": False,
                "lease": _lease_public(lease),
                "heartbeat_interval_seconds": policy.heartbeat_interval_seconds,
            }
        except (ValueError, TypeError) as exc:
            return _error(request_id, SecurityError(422, "invalid_request", str(exc)))
        except SecurityError as exc:
            return _error(request_id, exc)

    @router.post("/heartbeat")
    async def heartbeat(request: Request):
        request_id = get_or_create_request_id(request)
        try:
            who = actor(request)
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {"lease_id"})
            lease_id = str(payload.get("lease_id", ""))
            if not lease_id:
                raise SecurityError(422, "lease_id_required", "lease_id is required")
            _, policy = _lease_policy(get_manager())
            now = now_ts()
            with get_security_service().store.transaction() as conn:
                lease = conn.execute(
                    "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                ).fetchone()
                if lease is None:
                    raise SecurityError(404, "lease_not_found", "lease was not found")
                if lease["device_id"] != who["device_id"]:
                    raise SecurityError(403, "lease_device_mismatch", "lease belongs to another device")
                if lease["status"] != "active" or int(lease["expires_at"]) <= now:
                    raise SecurityError(409, "lease_not_active", "lease is not active")
                new_expiry = min(
                    max(int(lease["expires_at"]), now + policy.heartbeat_interval_seconds * 3),
                    int(lease["max_expires_at"]),
                )
                conn.execute(
                    "UPDATE lease_record SET expires_at=?, last_heartbeat_at=? WHERE lease_id=?",
                    (new_expiry, now, lease_id),
                )
                updated = conn.execute(
                    "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                ).fetchone()
            audit(request, request_id, who, "heartbeat", 200, True)
            return {
                "ok": True,
                "request_id": request_id,
                "lease": _lease_public(updated),
                "heartbeat_interval_seconds": policy.heartbeat_interval_seconds,
            }
        except SecurityError as exc:
            return _error(request_id, exc)

    @router.post("/release")
    async def release(request: Request):
        request_id = get_or_create_request_id(request)
        try:
            who = actor(request)
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {"lease_id"})
            lease_id = str(payload.get("lease_id", ""))
            if not lease_id:
                raise SecurityError(422, "lease_id_required", "lease_id is required")
            with get_security_service().store.read() as conn:
                lease = conn.execute(
                    "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                ).fetchone()
                if lease is None:
                    raise SecurityError(404, "lease_not_found", "lease was not found")
                if lease["device_id"] != who["device_id"]:
                    raise SecurityError(403, "lease_device_mismatch", "lease belongs to another device")
            ok = await _finish_release(
                service=get_security_service(),
                manager=get_manager(),
                client=get_http_client(),
                lease_id=lease_id,
                reason="released by device",
            )
            if not ok:
                raise SecurityError(502, "release_recovery_pending", "normal mode recovery will retry automatically")
            with get_security_service().store.read() as conn:
                updated = conn.execute(
                    "SELECT * FROM lease_record WHERE lease_id=?", (lease_id,)
                ).fetchone()
            audit(request, request_id, who, "release", 200, True)
            return {"ok": True, "request_id": request_id, "lease": _lease_public(updated)}
        except SecurityError as exc:
            return _error(request_id, exc)

    @router.get("/status")
    async def status(request: Request):
        request_id = get_or_create_request_id(request)
        try:
            who = actor(request)
            await cleanup_leases_once(
                service=get_security_service(), manager=get_manager(), client=get_http_client()
            )
            with get_security_service().store.read() as conn:
                lease = conn.execute(
                    """
                    SELECT * FROM lease_record
                    WHERE device_id=? AND capability=? AND status IN ('activating','active','releasing')
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (who["device_id"], LEASE_CAPABILITY),
                ).fetchone()
            return {"ok": True, "request_id": request_id, "active": bool(lease and lease["status"] == "active"), "lease": _lease_public(lease)}
        except SecurityError as exc:
            return _error(request_id, exc)

    @router.post("/cleanup")
    async def cleanup(request: Request):
        request_id = get_or_create_request_id(request)
        try:
            actor(request)
            count = await cleanup_leases_once(
                service=get_security_service(), manager=get_manager(), client=get_http_client()
            )
            return {"ok": True, "request_id": request_id, "released_count": count}
        except SecurityError as exc:
            return _error(request_id, exc)

    return router
