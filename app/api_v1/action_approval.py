from __future__ import annotations

import hmac
from collections.abc import Callable

from fastapi import APIRouter, Request

from app.security.http import device_secret, read_json_object, reject_unknown_fields, security_error_response
from app.security.db import now_ts
from app.security.service import SecurityError, SecurityService


def build_action_approval_router(
    *, get_security_service: Callable[[], SecurityService]
) -> APIRouter:
    router = APIRouter(tags=["action-approval"])

    @router.post("/api/auth/v1/actions/request")
    async def request_action(request: Request):
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {
                "device_id", "device_secret", "grant_id", "capability", "method", "path",
                "body_sha256", "payload_preview", "reason",
            })
            return {"ok": True, **get_security_service().request_action_approval(
                device_id=str(payload.get("device_id", "")),
                device_secret=device_secret(payload, request),
                grant_id=str(payload.get("grant_id", "")),
                capability=str(payload.get("capability", "")),
                method=str(payload.get("method", "")),
                path=str(payload.get("path", "")),
                body_sha256=str(payload.get("body_sha256", "")),
                payload_preview=str(payload.get("payload_preview", "")),
                reason=str(payload.get("reason", "")),
            )}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.post("/api/auth/v1/actions/{approval_id}/status")
    async def action_status(request: Request, approval_id: str):
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {"device_id", "device_secret"})
            return {"ok": True, **get_security_service().action_request_status(
                approval_id=approval_id,
                device_id=str(payload.get("device_id", "")),
                device_secret=device_secret(payload, request),
            )}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.post("/api/auth/v1/approvals/{approval_id}/totp-approve")
    async def totp_approve(request: Request, approval_id: str):
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {
                "device_id", "device_secret", "request_code", "totp_code",
            })
            service = get_security_service()
            device_id = str(payload.get("device_id", ""))
            status = service.approval_status_for_device(
                approval_id=approval_id,
                device_id=device_id,
                device_secret=device_secret(payload, request),
            )
            if status["approval"]["device_id"] != device_id:
                raise SecurityError(403, "approval_device_mismatch", "approval belongs to another device")
            return {"ok": True, **service.approve(
                approval_id=approval_id,
                approved_by=f"TOTP:{device_id}",
                approval_method="totp",
                request_code=str(payload.get("request_code", "")),
                totp_code=str(payload.get("totp_code", "")),
            )}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.get("/api/approvals/v1/desktop-pending")
    async def desktop_pending(request: Request):
        service = get_security_service()
        supplied = request.headers.get("x-desktop-approver-secret", "")
        if not service.desktop_approver_secret or not hmac.compare_digest(supplied, service.desktop_approver_secret):
            return security_error_response(request, SecurityError(401, "desktop_helper_denied", "desktop helper secret is invalid"))
        with service.store.read() as conn:
            rows = conn.execute(
                """
                SELECT * FROM approval_request
                WHERE status='pending' AND expires_at>?
                  AND required_approval_methods LIKE '%desktop%'
                ORDER BY created_at ASC LIMIT 10
                """,
                (now_ts(),),
            ).fetchall()
        return {"ok": True, "approvals": [service.public_approval(row) for row in rows]}

    @router.post("/api/approvals/v1/{approval_id}/desktop-decision")
    async def desktop_decision(request: Request, approval_id: str):
        service = get_security_service()
        supplied = request.headers.get("x-desktop-approver-secret", "")
        if not service.desktop_approver_secret or not hmac.compare_digest(supplied, service.desktop_approver_secret):
            return security_error_response(request, SecurityError(401, "desktop_helper_denied", "desktop helper secret is invalid"))
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {"decision"})
            if payload.get("decision") == "approve":
                result = service.approve(
                    approval_id=approval_id, approved_by="macOS Desktop Approver",
                    approval_method="desktop", desktop_verified=True,
                )
            elif payload.get("decision") == "deny":
                result = service.deny(approval_id=approval_id, denied_by="macOS Desktop Approver")
            else:
                raise SecurityError(422, "invalid_decision", "decision must be approve or deny")
            return {"ok": True, **result}
        except SecurityError as exc:
            return security_error_response(request, exc)

    return router
