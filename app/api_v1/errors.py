from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse


HTTP_BY_CODE = {
    "UNAUTHORIZED": 401,
    "FORBIDDEN": 403,
    "DEVICE_NOT_FOUND": 401,
    "DEVICE_NOT_TRUSTED": 403,
    "DEVICE_REVOKED": 403,
    "GRANT_NOT_FOUND": 403,
    "GRANT_EXPIRED": 403,
    "GRANT_REVOKED": 403,
    "TOKEN_EXPIRED": 401,
    "TOKEN_REVOKED": 401,
    "CAPABILITY_DENIED": 403,
    "APP_NOT_FOUND": 404,
    "APP_NOT_RUNNING": 409,
    "APP_START_FAILED": 500,
    "ROUTE_NOT_ALLOWED": 403,
    "APPROVAL_REQUIRED": 403,
    "APPROVAL_EXPIRED": 403,
    "UPSTREAM_TIMEOUT": 504,
    "UPSTREAM_ERROR": 502,
    "VALIDATION_FAILED": 422,
    "LEASE_EXPIRED": 409,
    "LEASE_HEARTBEAT_MISSED": 409,
}


def gateway_error(
    *,
    code: str,
    message: str,
    request_id: str,
    status_code: int | None = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    """统一 Gateway API 错误格式。"""

    payload: dict[str, Any] = {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
        },
    }
    if extra:
        payload["error"].update(extra)

    return JSONResponse(
        status_code=status_code or HTTP_BY_CODE.get(code, 500),
        content=payload,
        headers={"X-Gateway-Request-Id": request_id},
    )


# =============================================================================
# Compatibility helper for Stage 2 admin security routes
# =============================================================================

def gateway_error_response(
    *,
    code: str,
    message: str,
    status_code: int,
    request_id: str,
):
    """
    Return the standard Gateway error response.

    Stage 2 admin_security.py imports this helper directly.
    Some Stage 1 builds did not include this exact function name, so we define it
    here as a stable compatibility wrapper.

    Response format:
        {
          "ok": false,
          "error": {
            "code": "...",
            "message": "...",
            "request_id": "gw_..."
          }
        }
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=status_code,
        content={
            "ok": False,
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
            },
        },
        headers={
            "X-Gateway-Request-Id": request_id,
        },
    )
