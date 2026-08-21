from __future__ import annotations

import secrets
import time
import re

from fastapi import Request


REQUEST_ID_STATE_KEY = "gateway_request_id"
REQUEST_ID_HEADER = "X-Gateway-Request-Id"


def new_request_id() -> str:
    """
    Create a Gateway request id.

    Format example:
        gw_1781791498469_064a0c3c
    """
    return f"gw_{int(time.time() * 1000)}_{secrets.token_hex(4)}"


def get_or_create_request_id(request: Request) -> str:
    """
    Get request id from request.state, existing header, or create a new one.

    This is the compatibility function used by Stage 2 admin_security.py.
    """
    existing = getattr(request.state, REQUEST_ID_STATE_KEY, None)
    if existing:
        return str(existing)

    header_value = request.headers.get(REQUEST_ID_HEADER, "").strip()
    if re.fullmatch(r"[A-Za-z0-9_-]{8,80}", header_value):
        request_id = header_value
    else:
        request_id = new_request_id()

    setattr(request.state, REQUEST_ID_STATE_KEY, request_id)
    return request_id


def get_request_id(request: Request) -> str:
    """
    Backward-compatible alias.

    Some Stage 1 files may call get_request_id().
    """
    return get_or_create_request_id(request)


def ensure_request_id(request: Request) -> str:
    """
    Backward-compatible alias.

    Some Stage 1 files may call ensure_request_id().
    """
    return get_or_create_request_id(request)
