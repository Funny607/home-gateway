from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Request

from app.security.auth import AuthConfig
from app.security.http import (
    client_ip,
    device_secret,
    read_json_object,
    reject_unknown_fields,
    security_error_response,
)
from app.security.rate_limit import SlidingWindowRateLimiter
from app.security.service import SecurityError, SecurityService


def _capabilities(value) -> list[str]:
    if not isinstance(value, list):
        raise SecurityError(422, "capabilities_required", "capabilities must be a JSON array")
    return [str(item) for item in value]


def build_grant_auth_router(
    *,
    get_security_service: Callable[[], SecurityService],
    rate_limiter: SlidingWindowRateLimiter,
    auth_config: AuthConfig,
) -> APIRouter:
    router = APIRouter(tags=["grant-auth"])

    @router.post("/api/auth/v1/grants/request")
    async def request_grant(request: Request):
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(
                payload,
                {
                    "device_id", "device_secret", "target_app", "capabilities",
                    "requested_ttl_seconds", "grant_type", "reason",
                },
            )
            device_id = str(payload.get("device_id", ""))
            secret = device_secret(payload, request)
            if not device_id or not secret:
                raise SecurityError(
                    401,
                    "device_credentials_required",
                    "device_id and device_secret are required",
                )
            rate = rate_limiter.check(
                f"grant-request:{client_ip(request)}:{device_id}",
                limit=auth_config.public_api_attempts,
                window_seconds=auth_config.public_api_window_seconds,
                block_seconds=auth_config.public_api_window_seconds,
            )
            if not rate.allowed:
                raise SecurityError(429, "rate_limited", f"retry after {rate.retry_after_seconds} seconds")
            result = get_security_service().request_grant(
                device_id=device_id,
                device_secret=secret,
                target_app=str(payload.get("target_app", "")),
                capabilities=_capabilities(payload.get("capabilities")),
                requested_ttl_seconds=int(payload.get("requested_ttl_seconds", 3600) or 0),
                grant_type=str(payload.get("grant_type", "session")),
                reason=str(payload.get("reason", "")),
                client_ip=client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
            )
            return {"ok": True, **result}
        except (TypeError, ValueError) as exc:
            return security_error_response(
                request, SecurityError(422, "invalid_request", str(exc))
            )
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.get("/api/auth/v1/grants/requests/{approval_id}")
    async def grant_status(request: Request, approval_id: str, device_id: str):
        try:
            secret = request.headers.get("x-device-secret", "")
            if not secret:
                raise SecurityError(401, "device_secret_required", "X-Device-Secret header is required")
            result = get_security_service().grant_request_status(
                approval_id=approval_id,
                device_id=device_id,
                device_secret=secret,
            )
            return {"ok": True, **result}
        except SecurityError as exc:
            return security_error_response(request, exc)

    return router
