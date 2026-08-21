from __future__ import annotations

import asyncio
import hashlib
import tempfile
from typing import AsyncIterator, BinaryIO, Dict, Iterable

from fastapi import Request
from fastapi.responses import Response, StreamingResponse


class RequestBodyTooLarge(ValueError):
    pass


class SpooledRequestBody:
    def __init__(self, handle: BinaryIO, size: int, sha256_hex: str) -> None:
        self.handle = handle
        self.size = size
        self.sha256_hex = sha256_hex

    async def chunks(self, chunk_size: int = 64 * 1024) -> AsyncIterator[bytes]:
        await asyncio.to_thread(self.handle.seek, 0)
        while True:
            chunk = await asyncio.to_thread(self.handle.read, chunk_size)
            if not chunk:
                break
            yield chunk

    def close(self) -> None:
        self.handle.close()


async def spool_request_body(
    request: Request, *, max_bytes: int, memory_bytes: int
) -> SpooledRequestBody:
    content_length = request.headers.get("content-length", "")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise ValueError("Content-Length is invalid") from exc
        if declared < 0:
            raise ValueError("Content-Length is invalid")
        if declared > max_bytes:
            raise RequestBodyTooLarge("request body exceeds the configured limit")
    handle = tempfile.SpooledTemporaryFile(max_size=memory_bytes, mode="w+b")
    size = 0
    digest = hashlib.sha256()
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > max_bytes:
                raise RequestBodyTooLarge("request body exceeds the configured limit")
            digest.update(chunk)
            await asyncio.to_thread(handle.write, chunk)
        return SpooledRequestBody(handle, size, digest.hexdigest())
    except Exception:
        handle.close()
        raise


# -----------------------------------------------------------------------------
# Header filtering
# -----------------------------------------------------------------------------
#
# 这里分成两套：
#
# 1. 原 WebUI reverse proxy:
#    用于 /apps/<app-id>/... 这种网页代理。
#
# 2. External API proxy:
#    用于 /api/apps/v1/<app-id>/... 这种受控 API 穿透。
#
# API proxy 更严格：
# - 不把 Gateway 的 Cookie / Authorization 传给子应用。
# - 不把子应用 Set-Cookie 带回 Gateway。
# - 不转发 date/server，避免 uvicorn 再生成一份导致重复。
# - 不转发 content-length / transfer-encoding，避免流式响应长度错误。
# -----------------------------------------------------------------------------


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


RUNTIME_RESPONSE_HEADERS = {
    # uvicorn/starlette 会自己生成。
    # 如果上游的 date/server 也透传回来，curl -i 会看到重复头。
    "date",
    "server",

    # Gateway 可能使用 StreamingResponse，content-length 不一定仍然正确。
    "content-length",

    # 由 server runtime 控制，不应从上游透传。
    "transfer-encoding",
}


API_BLOCKED_REQUEST_HEADERS = HOP_BY_HOP_HEADERS | {
    "host",
    "cookie",
    "authorization",
    "proxy-connection",
}

WEBUI_BLOCKED_REQUEST_HEADERS = HOP_BY_HOP_HEADERS | {
    "host",
    "authorization",
    "proxy-authorization",
    "proxy-connection",
}

WEBSOCKET_BLOCKED_REQUEST_HEADERS = WEBUI_BLOCKED_REQUEST_HEADERS | {
    "origin",
    "sec-websocket-accept",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
}


def _is_gateway_internal_header(name: str) -> bool:
    return name.lower().startswith("x-gateway-")


def _is_forwarding_header(name: str) -> bool:
    return name.lower().startswith("x-forwarded-")


def _without_gateway_session(cookie_header: str) -> str:
    pairs = []
    for item in cookie_header.split(";"):
        name, separator, _ = item.strip().partition("=")
        if separator and name.strip().lower() == "gateway_session":
            continue
        if item.strip():
            pairs.append(item.strip())
    return "; ".join(pairs)


API_BLOCKED_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | RUNTIME_RESPONSE_HEADERS | {
    # 子应用的 Cookie 不应该变成 Gateway 域名下的 Cookie。
    "set-cookie",
}


WEBUI_BLOCKED_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | RUNTIME_RESPONSE_HEADERS


def build_upstream_headers(request: Request, mount_path: str) -> Dict[str, str]:
    """
    Build request headers for the original WebUI reverse proxy.

    Used by:
        /apps/<app-id>/...

    This proxy is for browser UI traffic, so it is less strict than the
    external API proxy. However, hop-by-hop headers and Host are still removed.
    """
    headers: Dict[str, str] = {}

    for key, value in request.headers.items():
        lower = key.lower()

        if (
            lower in WEBUI_BLOCKED_REQUEST_HEADERS
            or _is_gateway_internal_header(key)
            or _is_forwarding_header(key)
        ):
            continue

        if lower == "cookie":
            value = _without_gateway_session(value)
            if not value:
                continue

        headers[key] = value

    headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
    headers["X-Forwarded-Host"] = request.headers.get("host", "")
    headers["X-Forwarded-Proto"] = request.url.scheme
    headers["X-Forwarded-Prefix"] = mount_path

    return headers


def build_websocket_upstream_headers(request: Request, mount_path: str) -> Dict[str, str]:
    """Build non-handshake headers for a browser WebSocket upstream."""
    headers: Dict[str, str] = {}
    for key, value in request.headers.items():
        lower = key.lower()
        if (
            lower in WEBSOCKET_BLOCKED_REQUEST_HEADERS
            or _is_gateway_internal_header(key)
            or _is_forwarding_header(key)
        ):
            continue
        if lower == "cookie":
            value = _without_gateway_session(value)
            if not value:
                continue
        headers[key] = value
    headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
    headers["X-Forwarded-Host"] = request.headers.get("host", "")
    headers["X-Forwarded-Proto"] = request.url.scheme
    headers["X-Forwarded-Prefix"] = mount_path
    return headers


def build_api_upstream_headers(
    request: Request,
    *,
    app_id: str,
    capability_id: str,
    actor_type: str,
    actor_name: str,
    device_id: str,
    source_id: str,
    request_id: str,
) -> Dict[str, str]:
    """
    Build request headers for the External API proxy.

    Used by:
        /api/apps/v1/{app_id}/{path...}

    Important security rule:
        Do not forward Gateway Cookie / Authorization to child apps.

    Child apps should identify the caller through Gateway-injected headers:
        X-Gateway-Request-Id
        X-Gateway-Actor-Type
        X-Gateway-Actor-Name
        X-Gateway-Device-Id
        X-Gateway-Source-Id
        X-Gateway-App-Id
        X-Gateway-Capability
    """
    headers: Dict[str, str] = {}

    for key, value in request.headers.items():
        lower = key.lower()

        if (
            lower in API_BLOCKED_REQUEST_HEADERS
            or _is_gateway_internal_header(key)
            or _is_forwarding_header(key)
        ):
            continue

        if not key or key.startswith(":"):
            continue

        headers[key] = value

    headers["X-Gateway-Request-Id"] = request_id
    headers["X-Gateway-Actor-Type"] = actor_type
    headers["X-Gateway-Actor-Name"] = actor_name
    headers["X-Gateway-Device-Id"] = device_id
    headers["X-Gateway-Source-Id"] = source_id
    headers["X-Gateway-App-Id"] = app_id
    headers["X-Gateway-Capability"] = capability_id

    headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
    headers["X-Forwarded-Host"] = request.headers.get("host", "")
    headers["X-Forwarded-Proto"] = request.url.scheme

    return headers


def filter_response_headers(headers: Iterable[tuple[str, str]]) -> Dict[str, str]:
    """
    Filter response headers for the original WebUI reverse proxy.

    Used by:
        /apps/<app-id>/...

    This removes:
    - hop-by-hop headers
    - date/server to avoid duplicate runtime headers
    - content-length / transfer-encoding to avoid invalid streaming metadata
    """
    result: Dict[str, str] = {}

    for key, value in headers:
        lower = key.lower()

        if lower in WEBUI_BLOCKED_RESPONSE_HEADERS:
            continue

        if lower == "set-cookie":
            cookie_name = value.split(";", 1)[0].partition("=")[0].strip().lower()
            if cookie_name == "gateway_session":
                continue

        if not key or key.startswith(":"):
            continue

        result[key] = value

    return result


def filter_api_response_headers(headers: Iterable[tuple[str, str]]) -> Dict[str, str]:
    """
    Filter response headers for External API proxy.

    Used by:
        /api/apps/v1/{app_id}/{path...}

    This is stricter than WebUI proxy because API proxy is part of the
    security boundary.

    It removes:
    - hop-by-hop headers
    - date/server to avoid duplicates
    - content-length / transfer-encoding
    - set-cookie from child apps
    """
    result: Dict[str, str] = {}

    for key, value in headers:
        lower = key.lower()

        if lower in API_BLOCKED_RESPONSE_HEADERS:
            continue

        if not key or key.startswith(":"):
            continue

        result[key] = value

    return result


def build_plain_response(status_code: int, content: bytes, headers: Dict[str, str]) -> Response:
    """
    Build a normal response from upstream bytes.
    """
    return Response(
        content=content,
        status_code=status_code,
        headers=headers,
    )


def build_streaming_response(status_code: int, iterator, headers: Dict[str, str]) -> StreamingResponse:
    """
    Build a streaming response from upstream iterator.
    """
    return StreamingResponse(
        iterator,
        status_code=status_code,
        headers=headers,
    )
