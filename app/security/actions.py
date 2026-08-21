from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def canonical_action(method: str, path: str, body_sha256: str) -> tuple[str, str, str, str]:
    method = method.strip().upper()
    body_sha256 = body_sha256.strip().lower()
    if method not in ALLOWED_METHODS:
        raise ValueError("unsupported action method")
    if not SHA256_RE.fullmatch(body_sha256):
        raise ValueError("body_sha256 must be 64 lowercase hexadecimal characters")
    if len(path) > 4096 or "\\" in path or "\r" in path or "\n" in path:
        raise ValueError("action path is invalid")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        raise ValueError("action path must be an absolute local path with no fragment")
    segments = parsed.path.split("/")
    if "" in segments[1:-1] or any(segment in {".", ".."} for segment in segments):
        raise ValueError("action path must be canonical")
    canonical_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    encoded = json.dumps(
        {"body_sha256": body_sha256, "method": method, "path": canonical_path},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return method, canonical_path, body_sha256, hashlib.sha256(encoded).hexdigest()


def validate_payload_preview(value: str, *, required: bool) -> str:
    value = value.strip()
    if required and not value:
        raise ValueError("payload_preview is required by policy")
    if len(value) > 2000 or any(ord(char) < 32 and char not in "\t" for char in value):
        raise ValueError("payload_preview is invalid or exceeds 2000 characters")
    return value
