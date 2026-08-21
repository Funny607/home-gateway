from __future__ import annotations

import re


ENCODED_PATH_META = re.compile(rb"%(?:2e|2f|5c)", re.IGNORECASE)


def proxy_path_is_canonical(path: str, raw_path: bytes | None = None) -> bool:
    if len(path) > 4096 or not path.startswith("/") or "\x00" in path or "\\" in path:
        return False
    segments = path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return False
    if "//" in path:
        return False
    if ENCODED_PATH_META.search(path.encode("utf-8", errors="ignore")):
        return False
    if raw_path and ENCODED_PATH_META.search(raw_path):
        return False
    return True
