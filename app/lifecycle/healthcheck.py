from __future__ import annotations

from typing import Optional

import httpx


async def wait_until_healthy(
    client: httpx.AsyncClient,
    url: str,
    timeout_seconds: int,
    interval_seconds: int,
) -> tuple[bool, str]:
    import asyncio
    import time

    started = time.time()
    last_error = ""

    while time.time() - started < timeout_seconds:
        try:
            response = await client.get(url, timeout=5.0)
            if response.status_code == 200:
                return True, ""
            last_error = f"health check returned {response.status_code}"
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)

        await asyncio.sleep(interval_seconds)

    return False, last_error or "health check timeout"


async def check_once(client: httpx.AsyncClient, url: str) -> tuple[bool, str]:
    try:
        response = await client.get(url, timeout=5.0)
        if response.status_code == 200:
            return True, ""
        return False, f"health check returned {response.status_code}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
