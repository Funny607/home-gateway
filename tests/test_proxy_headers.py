from __future__ import annotations

import unittest

from starlette.requests import Request

from app.proxy.reverse_proxy import (
    build_api_upstream_headers,
    build_upstream_headers,
    filter_response_headers,
)
from app.proxy.path_security import proxy_path_is_canonical


def request_with(headers: list[tuple[bytes, bytes]]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/apps/demo/",
            "raw_path": b"/apps/demo/",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "server": ("dev.lu607.com", 443),
        }
    )


class ProxyHeaderTests(unittest.TestCase):
    def test_non_canonical_proxy_paths_are_rejected(self) -> None:
        self.assertTrue(proxy_path_is_canonical("/api/items/7", b"/api/items/7"))
        self.assertFalse(proxy_path_is_canonical("/api/items/../private"))
        self.assertFalse(proxy_path_is_canonical("/api//private"))
        self.assertFalse(proxy_path_is_canonical("/api/items/private", b"/api/items/%2e%2e/private"))
        self.assertFalse(proxy_path_is_canonical("/api/items/private", b"/api/items%2fprivate"))

    def test_webui_does_not_leak_gateway_session_or_spoofed_identity(self) -> None:
        request = request_with(
            [
                (b"host", b"dev.lu607.com"),
                (b"cookie", b"gateway_session=secret; child_session=allowed"),
                (b"authorization", b"Bearer gateway-secret"),
                (b"x-gateway-actor-name", b"spoofed"),
                (b"x-forwarded-for", b"spoofed"),
            ]
        )
        headers = build_upstream_headers(request, "/apps/demo")
        lower = {key.lower(): value for key, value in headers.items()}
        self.assertEqual(lower["cookie"], "child_session=allowed")
        self.assertNotIn("authorization", lower)
        self.assertNotIn("x-gateway-actor-name", lower)
        self.assertEqual(lower["x-forwarded-for"], "127.0.0.1")

    def test_api_replaces_all_gateway_and_forwarded_headers(self) -> None:
        request = request_with(
            [
                (b"host", b"dev.lu607.com"),
                (b"cookie", b"gateway_session=secret"),
                (b"x-gateway-capability", b"spoofed"),
                (b"x-forwarded-for", b"spoofed"),
            ]
        )
        headers = build_api_upstream_headers(
            request,
            app_id="demo",
            capability_id="demo.read",
            actor_type="session",
            actor_name="admin",
            device_id="",
            source_id="",
            request_id="request-1",
        )
        lower = {key.lower(): value for key, value in headers.items()}
        self.assertNotIn("cookie", lower)
        self.assertEqual(lower["x-gateway-capability"], "demo.read")
        self.assertEqual(lower["x-forwarded-for"], "127.0.0.1")

    def test_child_cannot_overwrite_gateway_session_cookie(self) -> None:
        headers = filter_response_headers(
            [
                ("Set-Cookie", "gateway_session=attacker; Secure"),
                ("X-App", "ok"),
            ]
        )
        self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(headers["X-App"], "ok")


if __name__ == "__main__":
    unittest.main()
