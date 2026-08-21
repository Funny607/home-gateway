from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _counter_code(secret: str, counter: int, digits: int = 6) -> str:
    normalized = secret.strip().replace(" ", "").upper()
    padded = normalized + "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def verify(secret: str, code: str, *, now: int | None = None, window: int = 1) -> int | None:
    if not code.isdigit() or len(code) != 6:
        return None
    current = int(time.time() if now is None else now) // 30
    for counter in range(current - window, current + window + 1):
        if hmac.compare_digest(_counter_code(secret, counter), code):
            return counter
    return None


def provisioning_uri(secret: str, *, issuer: str, account: str) -> str:
    label = quote(f"{issuer}:{account}", safe="")
    return f"otpauth://totp/{label}?secret={quote(secret)}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
