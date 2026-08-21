from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Request

from app.security.auth import AuthConfig
from app.security.http import client_ip, read_json_object, reject_unknown_fields, security_error_response
from app.security.rate_limit import SlidingWindowRateLimiter
from app.security.service import SecurityError, SecurityService


def build_device_auth_router(
    *,
    get_security_service: Callable[[], SecurityService],
    rate_limiter: SlidingWindowRateLimiter,
    auth_config: AuthConfig,
) -> APIRouter:
    router = APIRouter(tags=["device-auth"])

    @router.post("/api/auth/v1/devices/register")
    async def register_device(request: Request):
        key = f"device-register:{client_ip(request)}"
        decision = rate_limiter.check(
            key,
            limit=auth_config.public_api_attempts,
            window_seconds=auth_config.public_api_window_seconds,
            block_seconds=auth_config.public_api_window_seconds,
        )
        if not decision.allowed:
            return security_error_response(
                request,
                SecurityError(429, "rate_limited", f"retry after {decision.retry_after_seconds} seconds"),
            )
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(
                payload, {"device_name", "device_type", "source_id", "public_key"}
            )
            result = get_security_service().register_device(
                device_name=str(payload.get("device_name", "")),
                device_type=str(payload.get("device_type", "")),
                source_id=str(payload.get("source_id", "")),
                public_key=str(payload.get("public_key", "")),
                client_ip=client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
            )
            return {"ok": True, **result}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.get("/api/auth/v1/devices/requests/{approval_id}")
    async def registration_status(
        request: Request,
        approval_id: str,
        device_id: str,
    ):
        try:
            secret = request.headers.get("x-device-secret", "")
            if not secret:
                raise SecurityError(401, "device_secret_required", "X-Device-Secret header is required")
            result = get_security_service().device_registration_status(
                device_id=device_id,
                device_secret=secret,
            )
            actual = (result.get("approval") or {}).get("approval_id")
            if actual != approval_id:
                raise SecurityError(404, "approval_not_found", "approval request was not found")
            return {"ok": True, **result}
        except SecurityError as exc:
            return security_error_response(request, exc)

    return router
