from __future__ import annotations

import re
from dataclasses import dataclass

from app.config.schema import AppConfig, CapabilityConfig, CapabilityRouteConfig


@dataclass(frozen=True)
class CapabilityMatch:
    capability: CapabilityConfig
    route: CapabilityRouteConfig
    match_type: str


def _method_matches(route_method: str, request_method: str) -> bool:
    return route_method.upper() == request_method.upper()


def _exact_matches(route: CapabilityRouteConfig, upstream_path: str) -> bool:
    return route.path is not None and route.path == upstream_path


def _prefix_matches(route: CapabilityRouteConfig, upstream_path: str) -> bool:
    if route.path_prefix is None:
        return False
    if route.path_prefix == "/":
        return upstream_path.startswith("/")
    return upstream_path == route.path_prefix or upstream_path.startswith(route.path_prefix + "/")


def _regex_matches(route: CapabilityRouteConfig, upstream_path: str) -> bool:
    if route.path_regex is None:
        return False
    return re.fullmatch(route.path_regex, upstream_path) is not None


def find_capability_for_request(app_config: AppConfig, method: str, upstream_path: str) -> CapabilityMatch | None:
    """
    根据 method + upstream_path 找到允许该请求的 capability。

    优先级：
    1. exact path
    2. path_prefix
    3. path_regex
    4. fallback deny
    """

    method = method.upper()

    # 1. exact match
    for cap in app_config.capabilities:
        for route in cap.routes:
            if _method_matches(route.method, method) and _exact_matches(route, upstream_path):
                return CapabilityMatch(capability=cap, route=route, match_type="exact")

    # 2. prefix match
    best_prefix: CapabilityMatch | None = None
    best_len = -1
    for cap in app_config.capabilities:
        for route in cap.routes:
            if not _method_matches(route.method, method):
                continue
            if _prefix_matches(route, upstream_path):
                prefix_len = len(route.path_prefix or "")
                if prefix_len > best_len:
                    best_prefix = CapabilityMatch(capability=cap, route=route, match_type="prefix")
                    best_len = prefix_len
    if best_prefix is not None:
        return best_prefix

    # 3. regex match
    for cap in app_config.capabilities:
        for route in cap.routes:
            if _method_matches(route.method, method) and _regex_matches(route, upstream_path):
                return CapabilityMatch(capability=cap, route=route, match_type="regex")

    return None
