from __future__ import annotations

import json
from typing import Any

from fastapi import Request

from app.api_v1.errors import gateway_error
from app.api_v1.request_id import get_request_id
from app.security.service import SecurityError


async def read_json_object(request: Request, *, max_bytes: int = 65536) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise SecurityError(415, "json_required", "Content-Type application/json is required")
    body = await request.body()
    if len(body) > max_bytes:
        raise SecurityError(413, "request_too_large", "request body is too large")
    try:
        value = json.loads(body or b"{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityError(400, "invalid_json", "request body is not valid JSON") from exc
    if not isinstance(value, dict):
        raise SecurityError(422, "object_required", "request body must be a JSON object")
    return value


def reject_unknown_fields(payload: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise SecurityError(422, "unknown_fields", f"unsupported request fields: {', '.join(unknown)}")


def bearer_token(request: Request, *, required: bool = True) -> str:
    value = request.headers.get("authorization", "").strip()
    if not value:
        if required:
            raise SecurityError(401, "bearer_required", "Bearer access token is required")
        return ""
    scheme, separator, token = value.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise SecurityError(401, "invalid_authorization", "Authorization must use Bearer scheme")
    return token.strip()


def device_secret(payload: dict[str, Any], request: Request) -> str:
    return str(payload.get("device_secret") or request.headers.get("x-device-secret") or "")


def client_ip(request: Request) -> str:
    # The Gateway binds only to loopback. cloudflared is the only intended trusted proxy.
    forwarded = request.headers.get("cf-connecting-ip", "").strip()
    if forwarded:
        return forwarded[:128]
    return (request.client.host if request.client else "")[:128]


def security_error_response(request: Request, exc: SecurityError):
    return gateway_error(
        code=exc.code.upper(),
        message=str(exc),
        request_id=get_request_id(request),
        status_code=exc.status_code,
    )
