from __future__ import annotations

import json
import hashlib
import os
import ssl
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class GatewayClientError(RuntimeError):
    def __init__(self, status: int, code: str, message: str, request_id: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id


class GatewayClient:
    """Small stdlib client suitable for watchers and local automation."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30,
        verify_tls: bool = True,
        user_agent: str = "webui-home-gateway-sdk/5",
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an HTTP(S) origin")
        self.base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self.timeout = timeout
        self.user_agent = user_agent
        self.ssl_context = None if verify_tls else ssl._create_unverified_context()

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        token: str = "",
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be Gateway-relative")
        data = None
        request_headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
        request_headers.update(headers or {})
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=request_headers,
            method=method.upper(),
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self.ssl_context
            ) as response:
                raw = response.read()
                return json.loads(raw.decode("utf-8")) if raw else {"ok": True}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                body = json.loads(raw)
            except ValueError:
                body = {}
            raise GatewayClientError(
                exc.code,
                str(body.get("error") or body.get("code") or "http_error"),
                str(body.get("message") or body.get("detail") or f"HTTP {exc.code}"),
                str(body.get("request_id") or exc.headers.get("X-Gateway-Request-Id", "")),
            ) from exc
        except urllib.error.URLError as exc:
            raise GatewayClientError(0, "network_error", str(exc.reason)) from exc

    def register_device(self, *, name: str, device_type: str, source_id: str = "") -> dict[str, Any]:
        return self.request(
            "POST",
            "/api/auth/v1/devices/register",
            payload={"device_name": name, "device_type": device_type, "source_id": source_id},
        )

    def registration_status(self, *, approval_id: str, device_id: str, secret: str) -> dict[str, Any]:
        query = urllib.parse.urlencode({"device_id": device_id})
        return self.request(
            "GET",
            f"/api/auth/v1/devices/requests/{urllib.parse.quote(approval_id)}?{query}",
            headers={"X-Device-Secret": secret},
        )

    def request_grant(
        self,
        *,
        device_id: str,
        secret: str,
        app_id: str,
        capabilities: list[str],
        ttl_seconds: int = 3600,
        grant_type: str = "session",
        reason: str = "",
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/api/auth/v1/grants/request",
            payload={
                "device_id": device_id,
                "device_secret": secret,
                "target_app": app_id,
                "capabilities": capabilities,
                "requested_ttl_seconds": ttl_seconds,
                "grant_type": grant_type,
                "reason": reason,
            },
        )

    def issue_token(
        self,
        *,
        device_id: str,
        secret: str,
        grant_id: str,
        ttl_seconds: int = 900,
        client_name: str = "gateway-sdk",
        action_approval_id: str = "",
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/api/auth/v1/token",
            payload={
                "device_id": device_id,
                "device_secret": secret,
                "grant_id": grant_id,
                "requested_ttl_seconds": ttl_seconds,
                "client_name": client_name,
                "action_approval_id": action_approval_id,
            },
        )

    def request_action(
        self,
        *,
        device_id: str,
        secret: str,
        grant_id: str,
        capability: str,
        method: str,
        path: str,
        body: bytes = b"",
        payload_preview: str,
        reason: str = "",
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/api/auth/v1/actions/request",
            payload={
                "device_id": device_id,
                "device_secret": secret,
                "grant_id": grant_id,
                "capability": capability,
                "method": method,
                "path": path,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "payload_preview": payload_preview,
                "reason": reason,
            },
        )

    def action_status(
        self, *, approval_id: str, device_id: str, secret: str
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            f"/api/auth/v1/actions/{urllib.parse.quote(approval_id)}/status",
            payload={"device_id": device_id, "device_secret": secret},
        )

    def approve_with_totp(
        self,
        *,
        approval_id: str,
        device_id: str,
        secret: str,
        request_code: str,
        totp_code: str,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            f"/api/auth/v1/approvals/{urllib.parse.quote(approval_id)}/totp-approve",
            payload={
                "device_id": device_id,
                "device_secret": secret,
                "request_code": request_code,
                "totp_code": totp_code,
            },
        )

    def call_app(
        self,
        *,
        app_id: str,
        path: str,
        token: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        suffix = path if path.startswith("/") else "/" + path
        return self.request(
            method,
            f"/api/apps/v1/{urllib.parse.quote(app_id)}{suffix}",
            payload=payload,
            token=token,
        )

    def create_lease(self, *, capability: str, token: str, seconds: int = 300) -> dict[str, Any]:
        return self.request(
            "POST",
            "/api/leases/v1",
            payload={"capability": capability, "lease_seconds": seconds},
            token=token,
        )

    def heartbeat_lease(self, *, lease_id: str, token: str) -> dict[str, Any]:
        return self.request(
            "POST", f"/api/leases/v1/{urllib.parse.quote(lease_id)}/heartbeat", payload={}, token=token
        )

    def release_lease(self, *, lease_id: str, token: str) -> dict[str, Any]:
        return self.request(
            "POST", f"/api/leases/v1/{urllib.parse.quote(lease_id)}/release", payload={}, token=token
        )


def load_credentials(path: Path) -> dict[str, Any]:
    path = Path(path).expanduser()
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise PermissionError(f"credential file cannot be a symlink: {path}")
    if mode & 0o077:
        raise PermissionError(f"credential file must be mode 600: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("credential file must contain a JSON object")
    return data


def save_credentials(path: Path, data: dict[str, Any]) -> None:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
