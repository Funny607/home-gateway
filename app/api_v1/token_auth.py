from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Request

from app.security.auth import AuthConfig
from app.security.http import (
    bearer_token,
    client_ip,
    device_secret,
    read_json_object,
    reject_unknown_fields,
    security_error_response,
)
from app.security.rate_limit import SlidingWindowRateLimiter
from app.security.service import SecurityError, SecurityService


def build_token_auth_router(
    *,
    get_security_service: Callable[[], SecurityService],
    rate_limiter: SlidingWindowRateLimiter,
    auth_config: AuthConfig,
) -> APIRouter:
    router = APIRouter(tags=["token-auth"])

    @router.post("/api/auth/v1/token")
    async def issue_token(request: Request):
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(
                payload,
                {
                    "device_id", "device_secret", "grant_id", "requested_ttl_seconds",
                    "source_id", "client_name",
                    "action_approval_id",
                },
            )
            device_id = str(payload.get("device_id", ""))
            secret = device_secret(payload, request)
            if not device_id or not secret:
                raise SecurityError(401, "device_credentials_required", "device credentials are required")
            rate = rate_limiter.check(
                f"token-issue:{client_ip(request)}:{device_id}",
                limit=auth_config.public_api_attempts,
                window_seconds=auth_config.public_api_window_seconds,
                block_seconds=auth_config.public_api_window_seconds,
            )
            if not rate.allowed:
                raise SecurityError(429, "rate_limited", f"retry after {rate.retry_after_seconds} seconds")
            result = get_security_service().issue_token(
                device_id=device_id,
                device_secret=secret,
                grant_id=str(payload.get("grant_id", "")),
                requested_ttl_seconds=int(payload.get("requested_ttl_seconds", 900) or 0),
                source_id=str(payload.get("source_id", "")),
                client_name=str(payload.get("client_name", "")),
                action_approval_id=str(payload.get("action_approval_id", "")),
                client_ip=client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
            )
            return {"ok": True, **result}
        except (TypeError, ValueError) as exc:
            return security_error_response(request, SecurityError(422, "invalid_request", str(exc)))
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.post("/api/auth/v1/token/introspect")
    async def introspect_token(request: Request):
        try:
            token = bearer_token(request)
            result = get_security_service().verify_access_token(token)
            return {"ok": True, "active": True, "token": result}
        except SecurityError as exc:
            if exc.code in {
                "invalid_token",
                "token_revoked",
                "token_expired",
                "token_consumed",
                "device_not_active",
                "device_trust_expired",
                "policy_changed",
            }:
                return {"ok": True, "active": False, "reason": exc.code}
            return security_error_response(request, exc)

    @router.post("/api/auth/v1/token/revoke")
    async def revoke_token(request: Request):
        try:
            authorization = request.headers.get("authorization", "")
            if authorization:
                result = get_security_service().revoke_current_token(bearer_token(request))
            else:
                payload = await read_json_object(request)
                reject_unknown_fields(payload, {"device_id", "device_secret", "token_id"})
                secret = device_secret(payload, request)
                result = get_security_service().revoke_token_by_device(
                    device_id=str(payload.get("device_id", "")),
                    device_secret=secret,
                    token_id=str(payload.get("token_id", "")),
                )
            return {"ok": True, **result}
        except SecurityError as exc:
            return security_error_response(request, exc)

    return router
