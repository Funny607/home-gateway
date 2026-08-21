from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Request

from app.api_v1.errors import gateway_error
from app.api_v1.request_id import get_or_create_request_id
from app.leases.coordinator import LeaseCoordinator
from app.security.http import bearer_token, read_json_object, reject_unknown_fields
from app.security.http import client_ip
from app.security.service import SecurityError, SecurityService


def _error(request_id: str, exc: SecurityError):
    return gateway_error(
        code=exc.code.upper(), message=str(exc), request_id=request_id, status_code=exc.status_code
    )


def build_lease_router(
    *,
    get_coordinator: Callable[[], LeaseCoordinator],
    get_security_service: Callable[[], SecurityService],
) -> APIRouter:
    router = APIRouter(prefix="/api/leases/v1", tags=["leases"])

    def actor(request: Request, capability: str) -> dict[str, Any]:
        app_id, _, _ = get_coordinator().resolve_capability(capability)
        who = get_security_service().verify_access_token(
            bearer_token(request), target_app=app_id, capability=capability, consume=False
        )
        if who.get("token_type") == "one_time":
            raise SecurityError(403, "one_time_not_allowed", "lease requires an access token")
        return who

    def audit(
        request: Request,
        *,
        request_id: str,
        who: dict[str, Any],
        capability: str,
        action: str,
    ) -> None:
        app_id, cap, _ = get_coordinator().resolve_capability(capability)
        get_security_service().store.write_api_audit(
            request_id=request_id,
            actor_type="device_token",
            actor_name=who.get("actor_name", ""),
            device_id=who.get("device_id", ""),
            source_id=who.get("source_id", ""),
            client_name=who.get("client_name", ""),
            grant_id=who.get("grant_id", ""),
            token_id=who.get("token_id", ""),
            target_app=app_id,
            capability=capability,
            method=request.method,
            path=str(request.url.path),
            upstream_path=action,
            status_code=200,
            success=True,
            risk_level=cap.risk,
            client_ip=client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:512],
        )

    @router.post("")
    async def create(request: Request):
        request_id = get_or_create_request_id(request)
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {"capability", "lease_seconds"})
            capability = str(payload.get("capability", "")).strip().lower()
            if not capability:
                raise SecurityError(422, "capability_required", "capability is required")
            who = actor(request, capability)
            result = await get_coordinator().create(
                actor=who,
                capability_id=capability,
                lease_seconds=int(payload.get("lease_seconds", 300) or 300),
                request_id=request_id,
            )
            audit(
                request, request_id=request_id, who=who, capability=capability, action="lease-create"
            )
            return {"ok": True, "request_id": request_id, **result}
        except (ValueError, TypeError) as exc:
            return _error(request_id, SecurityError(422, "invalid_request", str(exc)))
        except SecurityError as exc:
            return _error(request_id, exc)

    @router.post("/{lease_id}/heartbeat")
    async def heartbeat(request: Request, lease_id: str):
        request_id = get_or_create_request_id(request)
        try:
            row = get_security_service().store.fetch_one(
                "SELECT capability FROM lease_record WHERE lease_id=?", (lease_id,)
            )
            if row is None:
                raise SecurityError(404, "lease_not_found", "lease was not found")
            who = actor(request, str(row["capability"]))
            result = await get_coordinator().heartbeat(actor=who, lease_id=lease_id)
            audit(
                request,
                request_id=request_id,
                who=who,
                capability=str(row["capability"]),
                action="lease-heartbeat",
            )
            return {"ok": True, "request_id": request_id, **result}
        except SecurityError as exc:
            return _error(request_id, exc)

    @router.post("/{lease_id}/release")
    async def release(request: Request, lease_id: str):
        request_id = get_or_create_request_id(request)
        try:
            row = get_security_service().store.fetch_one(
                "SELECT capability FROM lease_record WHERE lease_id=?", (lease_id,)
            )
            if row is None:
                raise SecurityError(404, "lease_not_found", "lease was not found")
            who = actor(request, str(row["capability"]))
            result = await get_coordinator().release(
                actor=who, lease_id=lease_id, reason="released by device"
            )
            if not result["recovered"]:
                raise SecurityError(
                    502, "release_recovery_pending", "resource release will retry automatically"
                )
            audit(
                request,
                request_id=request_id,
                who=who,
                capability=str(row["capability"]),
                action="lease-release",
            )
            return {"ok": True, "request_id": request_id, **result}
        except SecurityError as exc:
            return _error(request_id, exc)

    @router.get("/status")
    async def status(request: Request, capability: str):
        request_id = get_or_create_request_id(request)
        try:
            who = actor(request, capability)
            items = get_coordinator().for_actor(actor=who, capability_id=capability)
            audit(
                request, request_id=request_id, who=who, capability=capability, action="lease-status"
            )
            return {
                "ok": True,
                "request_id": request_id,
                "active": any(item.get("status") == "active" for item in items),
                "items": items,
            }
        except SecurityError as exc:
            return _error(request_id, exc)

    return router
