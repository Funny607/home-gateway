from __future__ import annotations

import re
import json
import shlex
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


APP_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
CAPABILITY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
RESERVED_MOUNTS = (
    "/api",
    "/dashboard",
    "/health",
    "/healthz",
    "/readyz",
    "/login",
    "/logout",
)


class StrictModel(BaseModel):
    """All release configuration rejects misspelled or unsupported keys."""

    model_config = ConfigDict(extra="forbid")


def _validate_loopback(value: str) -> str:
    value = value.strip().lower()
    if value in {"127.0.0.1", "localhost"}:
        return value
    raise ValueError("release listen_host must be 127.0.0.1 or localhost")


def _validate_prefix(prefix: str) -> str:
    prefix = prefix.strip()
    if not prefix.startswith("/"):
        raise ValueError("path prefixes must begin with '/'")
    if len(prefix) > 1:
        prefix = prefix.rstrip("/")
    return prefix


class ActivityConfig(StrictModel):
    count_as_user_prefixes: List[str] = Field(default_factory=lambda: ["/"])
    ignore_prefixes: List[str] = Field(default_factory=list)
    streaming_prefixes: List[str] = Field(default_factory=list)
    streaming_silence_seconds: int = 30

    @field_validator("count_as_user_prefixes", "ignore_prefixes", "streaming_prefixes")
    @classmethod
    def validate_prefixes(cls, values: List[str]) -> List[str]:
        return [_validate_prefix(str(value)) for value in values]

    @field_validator("streaming_silence_seconds")
    @classmethod
    def validate_streaming_silence_seconds(cls, value: int) -> int:
        if value < 0:
            raise ValueError("streaming_silence_seconds must be >= 0")
        return value


class CapabilityRouteConfig(StrictModel):
    method: str
    path: Optional[str] = None
    path_prefix: Optional[str] = None
    path_regex: Optional[str] = None

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        value = value.strip().upper()
        if value not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError("unsupported HTTP method")
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        if not value.startswith("/") or "?" in value or "#" in value:
            raise ValueError("route path must be an absolute path without query or fragment")
        return value

    @field_validator("path_prefix")
    @classmethod
    def validate_path_prefix(cls, value: Optional[str]) -> Optional[str]:
        return None if value is None else _validate_prefix(value)

    @field_validator("path_regex")
    @classmethod
    def validate_path_regex(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if len(value) > 512:
            raise ValueError("path_regex is too long")
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid path_regex: {exc}") from exc
        return value

    @model_validator(mode="after")
    def validate_one_matcher(self) -> "CapabilityRouteConfig":
        if sum(bool(item) for item in (self.path, self.path_prefix, self.path_regex)) != 1:
            raise ValueError("exactly one of path, path_prefix, path_regex is required")
        return self


class AdapterActionConfig(StrictModel):
    """One loopback-only action used by a Gateway-managed adapter."""

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "POST"
    path: str
    timeout_seconds: int = 15
    success_statuses: List[int] = Field(default_factory=lambda: [200, 204])
    json_body: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/") or "?" in value or "#" in value:
            raise ValueError("adapter action path must be absolute and contain no query or fragment")
        return value

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: int) -> int:
        if value <= 0 or value > 300:
            raise ValueError("adapter timeout_seconds must be in 1..300")
        return value

    @field_validator("success_statuses")
    @classmethod
    def validate_statuses(cls, values: List[int]) -> List[int]:
        normalized = sorted(set(int(value) for value in values))
        if not normalized or any(value < 100 or value > 599 for value in normalized):
            raise ValueError("adapter success_statuses must contain valid HTTP status codes")
        return normalized

    @field_validator("json_body")
    @classmethod
    def validate_json_body(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        sensitive = ("password", "secret", "token", "authorization", "cookie", "credential")

        def walk(item: Any) -> None:
            if isinstance(item, dict):
                for key, child in item.items():
                    if any(marker in str(key).lower() for marker in sensitive):
                        raise ValueError("adapter json_body cannot contain secret-like fields")
                    walk(child)
            elif isinstance(item, list):
                for child in item:
                    walk(child)

        walk(value)
        if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > 64 * 1024:
            raise ValueError("adapter json_body exceeds 64 KiB")
        return value


class AdapterProbeConfig(StrictModel):
    method: Literal["GET", "POST"] = "GET"
    path: str
    timeout_seconds: int = 5
    json_path: str
    active_values: List[str]
    released_values: List[str]

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/") or "?" in value or "#" in value:
            raise ValueError("adapter probe path must be absolute and contain no query or fragment")
        return value

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: int) -> int:
        if value <= 0 or value > 60:
            raise ValueError("adapter probe timeout_seconds must be in 1..60")
        return value

    @field_validator("json_path")
    @classmethod
    def validate_json_path(cls, value: str) -> str:
        value = value.strip()
        if not value or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", value):
            raise ValueError("adapter probe json_path must be a dotted object path")
        return value

    @field_validator("active_values", "released_values")
    @classmethod
    def validate_values(cls, values: List[str]) -> List[str]:
        normalized = [str(value).strip().lower() for value in values if str(value).strip()]
        if not normalized:
            raise ValueError("adapter probe values cannot be empty")
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def validate_disjoint_values(self) -> "AdapterProbeConfig":
        if set(self.active_values) & set(self.released_values):
            raise ValueError("adapter probe active_values and released_values must not overlap")
        return self


class TrustGrantRuleConfig(StrictModel):
    enabled: bool = True
    max_ttl_seconds: int = 3600
    approval_required: bool = True
    approval_methods: List[Literal["desktop", "totp", "web-admin"]] = Field(
        default_factory=lambda: ["web-admin"]
    )

    @field_validator("max_ttl_seconds")
    @classmethod
    def validate_ttl(cls, value: int) -> int:
        if value < 0:
            raise ValueError("max_ttl_seconds must be >= 0")
        return value

    @model_validator(mode="after")
    def validate_approval(self) -> "TrustGrantRuleConfig":
        if self.enabled and self.max_ttl_seconds <= 0:
            raise ValueError("an enabled grant rule must have max_ttl_seconds > 0")
        if self.approval_required and not self.approval_methods:
            raise ValueError("approval_required needs at least one approval method")
        return self


class GrantPolicyConfig(StrictModel):
    untrusted: TrustGrantRuleConfig = Field(
        default_factory=lambda: TrustGrantRuleConfig(enabled=False, max_ttl_seconds=0)
    )
    paired: TrustGrantRuleConfig = Field(
        default_factory=lambda: TrustGrantRuleConfig(max_ttl_seconds=3600)
    )
    trusted: TrustGrantRuleConfig = Field(
        default_factory=lambda: TrustGrantRuleConfig(max_ttl_seconds=2592000)
    )
    privileged: TrustGrantRuleConfig = Field(
        default_factory=lambda: TrustGrantRuleConfig(
            max_ttl_seconds=31536000,
            approval_required=False,
            approval_methods=[],
        )
    )


class LeasePolicyConfig(StrictModel):
    resource_key: str = ""
    max_lease_seconds: int = 7200
    heartbeat_interval_seconds: int = 30
    auto_release_on_missed_heartbeat: bool = True
    activation_grace_seconds: int = 30
    reconcile_retry_seconds: int = 15
    acquire: AdapterActionConfig
    release: AdapterActionConfig
    probe: AdapterProbeConfig

    @field_validator(
        "max_lease_seconds",
        "heartbeat_interval_seconds",
        "activation_grace_seconds",
        "reconcile_retry_seconds",
    )
    @classmethod
    def validate_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("lease policy values must be > 0")
        return value

    @field_validator("resource_key")
    @classmethod
    def validate_resource_key(cls, value: str) -> str:
        value = value.strip().lower()
        if value and not CAPABILITY_ID_RE.fullmatch(value):
            raise ValueError("lease resource_key must use capability-id syntax")
        return value

    @model_validator(mode="after")
    def require_fail_safe_release(self) -> "LeasePolicyConfig":
        if not self.auto_release_on_missed_heartbeat:
            raise ValueError("leases must auto-release after a missed heartbeat")
        return self


class ActionPolicyConfig(StrictModel):
    per_action_approval: bool = False
    require_payload_preview: bool = False
    one_time_token: bool = False

    @model_validator(mode="after")
    def validate_binding(self) -> "ActionPolicyConfig":
        if self.require_payload_preview and not self.per_action_approval:
            raise ValueError("payload preview requires per_action_approval")
        if self.per_action_approval and not self.one_time_token:
            raise ValueError("per-action approval requires a one-time token")
        return self


class CapabilityConfig(StrictModel):
    id: str
    title: str
    risk: Literal["low", "medium", "medium_high", "high", "critical"] = "low"
    routes: List[CapabilityRouteConfig] = Field(default_factory=list)
    gateway_managed: bool = False
    grant_policy: GrantPolicyConfig = Field(default_factory=GrantPolicyConfig)
    lease_policy: Optional[LeasePolicyConfig] = None
    action_policy: Optional[ActionPolicyConfig] = None
    audit: bool = True
    activity: Literal["api", "user", "ignore"] = "api"
    auto_start: Optional[bool] = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        value = value.strip().lower()
        if not CAPABILITY_ID_RE.fullmatch(value):
            raise ValueError("invalid capability id")
        return value

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("capability title cannot be empty")
        return value

    @model_validator(mode="after")
    def validate_routes(self) -> "CapabilityConfig":
        if self.gateway_managed and self.routes:
            raise ValueError(f"gateway-managed capability '{self.id}' cannot declare upstream routes")
        if not self.gateway_managed and not self.routes:
            raise ValueError(f"capability '{self.id}' must define at least one route")
        if self.risk == "critical" and (
            self.action_policy is None
            or not self.action_policy.per_action_approval
            or not self.action_policy.require_payload_preview
            or not self.action_policy.one_time_token
        ):
            raise ValueError(
                "critical capabilities require per-action approval, payload preview, and one-time tokens"
            )
        return self


class ApiExposureConfig(StrictModel):
    enabled: bool = False
    auto_start: bool = False
    timeout_seconds: int = 15
    max_request_body_bytes: int = 2 * 1024 * 1024

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: int) -> int:
        if value <= 0 or value > 300:
            raise ValueError("api.timeout_seconds must be in 1..300")
        return value

    @field_validator("max_request_body_bytes")
    @classmethod
    def validate_body_limit(cls, value: int) -> int:
        if value <= 0 or value > 1024 * 1024 * 1024:
            raise ValueError("api.max_request_body_bytes is outside the supported range")
        return value


class WebSocketProxyConfig(StrictModel):
    enabled: bool = False
    path_prefixes: List[str] = Field(default_factory=list)
    max_message_bytes: int = 1024 * 1024
    idle_timeout_seconds: int = 300

    @field_validator("path_prefixes")
    @classmethod
    def validate_prefixes(cls, values: List[str]) -> List[str]:
        return list(dict.fromkeys(_validate_prefix(str(value)) for value in values))

    @field_validator("max_message_bytes")
    @classmethod
    def validate_message_size(cls, value: int) -> int:
        if value <= 0 or value > 64 * 1024 * 1024:
            raise ValueError("websocket max_message_bytes is outside the supported range")
        return value

    @field_validator("idle_timeout_seconds")
    @classmethod
    def validate_idle_timeout(cls, value: int) -> int:
        if value <= 0 or value > 86400:
            raise ValueError("websocket idle_timeout_seconds must be in 1..86400")
        return value

    @model_validator(mode="after")
    def validate_enabled_prefixes(self) -> "WebSocketProxyConfig":
        if self.enabled and not self.path_prefixes:
            raise ValueError("enabled WebSocket proxy needs at least one path_prefix")
        return self


class ProxyConfig(StrictModel):
    max_request_body_bytes: int = 256 * 1024 * 1024
    memory_spool_bytes: int = 1024 * 1024
    connect_timeout_seconds: int = 10
    request_timeout_seconds: int = 300
    streaming_read_timeout_seconds: int = 0
    websocket: WebSocketProxyConfig = Field(default_factory=WebSocketProxyConfig)

    @field_validator("max_request_body_bytes")
    @classmethod
    def validate_max_body(cls, value: int) -> int:
        if value <= 0 or value > 4 * 1024 * 1024 * 1024:
            raise ValueError("proxy max_request_body_bytes is outside the supported range")
        return value

    @field_validator("memory_spool_bytes")
    @classmethod
    def validate_spool(cls, value: int) -> int:
        if value <= 0 or value > 64 * 1024 * 1024:
            raise ValueError("proxy memory_spool_bytes is outside the supported range")
        return value

    @field_validator("connect_timeout_seconds", "request_timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: int) -> int:
        if value <= 0 or value > 3600:
            raise ValueError("proxy timeouts must be in 1..3600")
        return value

    @field_validator("streaming_read_timeout_seconds")
    @classmethod
    def validate_stream_timeout(cls, value: int) -> int:
        if value < 0 or value > 86400:
            raise ValueError("streaming_read_timeout_seconds must be in 0..86400")
        return value

    @model_validator(mode="after")
    def validate_spool_not_larger_than_body(self) -> "ProxyConfig":
        if self.memory_spool_bytes > self.max_request_body_bytes:
            raise ValueError("memory_spool_bytes cannot exceed max_request_body_bytes")
        return self


class MaintenanceWindowConfig(StrictModel):
    days: List[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]]
    start: str
    end: str
    timezone: str = "Australia/Sydney"

    @field_validator("start", "end")
    @classmethod
    def validate_clock(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
            raise ValueError("maintenance times must use HH:MM")
        return value

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("maintenance timezone must be an IANA timezone") from exc
        return value

    @model_validator(mode="after")
    def validate_window(self) -> "MaintenanceWindowConfig":
        if not self.days:
            raise ValueError("maintenance window needs at least one day")
        if self.start == self.end:
            raise ValueError("maintenance window start and end cannot match")
        return self


class LifecyclePolicyConfig(StrictModel):
    start_policy: Literal["always", "on_demand", "manual"] = "on_demand"
    auto_restart: Optional[bool] = None
    unhealthy_threshold: Optional[int] = None
    restart_max_attempts: Optional[int] = None
    restart_window_seconds: int = 900
    restart_backoff_initial_seconds: Optional[int] = None
    restart_backoff_max_seconds: int = 300
    stable_reset_seconds: int = 300
    dependencies: List[str] = Field(default_factory=list)
    maintenance_windows: List[MaintenanceWindowConfig] = Field(default_factory=list)

    @field_validator("unhealthy_threshold", "restart_max_attempts", "restart_backoff_initial_seconds")
    @classmethod
    def validate_optional_positive(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value <= 0:
            raise ValueError("optional lifecycle limits must be > 0")
        return value

    @field_validator("restart_window_seconds", "restart_backoff_max_seconds", "stable_reset_seconds")
    @classmethod
    def validate_positive(cls, value: int) -> int:
        if value <= 0 or value > 7 * 86400:
            raise ValueError("lifecycle durations must be in 1..604800")
        return value

    @field_validator("dependencies")
    @classmethod
    def validate_dependencies(cls, values: List[str]) -> List[str]:
        result: List[str] = []
        for raw in values:
            value = str(raw).strip().lower()
            if not APP_ID_RE.fullmatch(value):
                raise ValueError(f"invalid lifecycle dependency: {raw}")
            if value not in result:
                result.append(value)
        return result

class DashboardConfig(StrictModel):
    visible_roles: List[Literal["guest", "admin"]] = Field(default_factory=lambda: ["guest", "admin"])
    allow_open_roles: List[Literal["guest", "admin"]] = Field(default_factory=lambda: ["admin"])
    allow_detail_roles: List[Literal["guest", "admin"]] = Field(default_factory=lambda: ["admin"])
    allow_proxy_roles: List[Literal["guest", "admin"]] = Field(default_factory=lambda: ["admin"])


class DashboardActionsConfig(StrictModel):
    show_open: bool = True
    show_detail: bool = True
    show_start: bool = True
    show_stop: bool = True
    show_restart: bool = True
    show_retry: bool = True


class AppConfig(StrictModel):
    manifest_version: Literal[1] = 1
    app_id: str
    display_name: str
    icon: Optional[str] = None
    app_type: Literal["managed"] = "managed"
    mount_path: str
    workdir: str
    command: str | List[str]
    listen_host: str = "127.0.0.1"
    health_path: str = "/health"
    allow_auto_stop: bool = True
    idle_timeout_seconds: Optional[int] = None
    startup_timeout_seconds: Optional[int] = None
    graceful_shutdown_seconds: int = 10
    activity: ActivityConfig = Field(default_factory=ActivityConfig)
    env: Dict[str, str] = Field(default_factory=dict)
    secret_env: Dict[str, str] = Field(default_factory=dict)
    api: ApiExposureConfig = Field(default_factory=ApiExposureConfig)
    capabilities: List[CapabilityConfig] = Field(default_factory=list)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    actions: DashboardActionsConfig = Field(default_factory=DashboardActionsConfig)
    lifecycle: LifecyclePolicyConfig = Field(default_factory=LifecyclePolicyConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)

    @field_validator("app_id")
    @classmethod
    def validate_app_id(cls, value: str) -> str:
        value = value.strip().lower()
        if not APP_ID_RE.fullmatch(value):
            raise ValueError("app_id must contain lowercase letters, digits, and internal hyphens")
        return value

    @field_validator("display_name", "workdir")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value cannot be empty")
        return value

    @field_validator("mount_path")
    @classmethod
    def validate_mount_path(cls, value: str) -> str:
        value = _validate_prefix(value)
        if value == "/" or any(value == item or value.startswith(item + "/") for item in RESERVED_MOUNTS):
            raise ValueError("mount_path conflicts with a reserved Gateway route")
        return value

    @field_validator("health_path")
    @classmethod
    def validate_health_path(cls, value: str) -> str:
        return _validate_prefix(value)

    @field_validator("listen_host")
    @classmethod
    def validate_listen_host(cls, value: str) -> str:
        return _validate_loopback(value)

    @field_validator("idle_timeout_seconds", "startup_timeout_seconds")
    @classmethod
    def validate_optional_timeout(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value < 0:
            raise ValueError("timeouts must be >= 0")
        return value

    @field_validator("graceful_shutdown_seconds")
    @classmethod
    def validate_graceful_shutdown_seconds(cls, value: int) -> int:
        if value < 0 or value > 300:
            raise ValueError("graceful_shutdown_seconds must be in 0..300")
        return value

    @field_validator("secret_env")
    @classmethod
    def validate_secret_env(cls, value: Dict[str, str]) -> Dict[str, str]:
        for env_name, reference in value.items():
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", env_name):
                raise ValueError(f"invalid environment variable name: {env_name}")
            if not (reference.startswith("env:") or reference.startswith("keychain:")):
                raise ValueError(f"secret_env {env_name} must use env: or keychain: reference")
        return value

    @field_validator("env")
    @classmethod
    def validate_plain_env(cls, value: Dict[str, str]) -> Dict[str, str]:
        sensitive_markers = ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY", "CREDENTIAL")
        for env_name, env_value in value.items():
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", env_name):
                raise ValueError(f"invalid environment variable name: {env_name}")
            if any(marker in env_name for marker in sensitive_markers):
                raise ValueError(f"sensitive environment variable {env_name} must use secret_env")
            if len(str(env_value)) > 8192:
                raise ValueError(f"environment value is too large: {env_name}")
        return value

    @model_validator(mode="after")
    def validate_command_and_capabilities(self) -> "AppConfig":
        rendered = self.command if isinstance(self.command, str) else " ".join(self.command)
        if not rendered.strip():
            raise ValueError(f"app '{self.app_id}' command cannot be empty")
        if "{host}" not in rendered or "{port}" not in rendered:
            raise ValueError(f"app '{self.app_id}' command must contain {{host}} and {{port}}")
        seen: set[str] = set()
        for cap in self.capabilities:
            if cap.id in seen:
                raise ValueError(f"duplicate capability id in app '{self.app_id}': {cap.id}")
            if not cap.id.startswith(self.app_id + "."):
                raise ValueError(f"capability '{cap.id}' must start with '{self.app_id}.'")
            seen.add(cap.id)
        if self.api.enabled and not self.capabilities:
            raise ValueError("api.enabled requires at least one capability")
        if self.app_id in self.lifecycle.dependencies:
            raise ValueError("an app cannot depend on itself")
        for cap in self.capabilities:
            if cap.lease_policy is not None:
                if not cap.gateway_managed:
                    raise ValueError("lease_policy requires gateway_managed=true")
                if not cap.lease_policy.resource_key:
                    cap.lease_policy.resource_key = cap.id
        return self

    def build_command(self, **variables: str) -> tuple[List[str], str]:
        if isinstance(self.command, str):
            rendered = self.command.format(**variables)
            return shlex.split(rendered), rendered
        rendered_list = [str(part).format(**variables) for part in self.command]
        return rendered_list, " ".join(shlex.quote(part) for part in rendered_list)


class LinkConfig(StrictModel):
    link_id: str
    display_name: str
    icon: Optional[str] = None
    url: str
    description: Optional[str] = None

    @field_validator("link_id")
    @classmethod
    def validate_link_id(cls, value: str) -> str:
        value = value.strip().lower()
        if not APP_ID_RE.fullmatch(value):
            raise ValueError("invalid link_id")
        return value

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/"):
            raise ValueError("release links must use a Gateway-local path")
        return value


class LinksConfig(StrictModel):
    links: List[LinkConfig] = Field(default_factory=list)


class AuditConfig(StrictModel):
    retention_days: int = 90
    export_limit: int = 10000
    cleanup_interval_seconds: int = 3600

    @field_validator("retention_days")
    @classmethod
    def validate_retention(cls, value: int) -> int:
        if value <= 0 or value > 3650:
            raise ValueError("audit retention_days must be in 1..3650")
        return value

    @field_validator("export_limit")
    @classmethod
    def validate_export_limit(cls, value: int) -> int:
        if value <= 0 or value > 100000:
            raise ValueError("audit export_limit must be in 1..100000")
        return value

    @field_validator("cleanup_interval_seconds")
    @classmethod
    def validate_cleanup_interval(cls, value: int) -> int:
        if value < 60 or value > 86400:
            raise ValueError("audit cleanup_interval_seconds must be in 60..86400")
        return value


class NotificationConfig(StrictModel):
    enabled: bool = True
    provider: Literal["local_mailer"] = "local_mailer"
    python_executable: str = "/usr/bin/python3"
    command: str = "/Users/yuanqilu/dev/Local_Mailer/send_mail.py"
    recipient: str = "lu.yuanqi.2005@gmail.com"
    subject_prefix: str = "[Home Gateway]"
    cooldown_seconds: int = 300
    max_attempts: int = 5
    retry_backoff_seconds: int = 60
    retention_days: int = 90
    send_categories: List[str] = Field(
        default_factory=lambda: [
            "app_failure",
            "app_recovery",
            "lease_failure",
            "lease_recovery",
            "tunnel_failure",
            "approval_pending",
            "test",
        ]
    )

    @field_validator("python_executable", "command")
    @classmethod
    def validate_commands(cls, value: str) -> str:
        value = value.strip()
        if not value or "\x00" in value or "\n" in value:
            raise ValueError("notification command paths cannot be empty")
        return value

    @field_validator("recipient")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("notification recipient must be an email address")
        return value

    @field_validator("subject_prefix")
    @classmethod
    def validate_prefix(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 80 or "\n" in value or "\r" in value:
            raise ValueError("notification subject_prefix is invalid")
        return value

    @field_validator("cooldown_seconds", "retry_backoff_seconds")
    @classmethod
    def validate_non_negative(cls, value: int) -> int:
        if value < 0 or value > 86400:
            raise ValueError("notification cooldown/backoff must be in 0..86400")
        return value

    @field_validator("max_attempts")
    @classmethod
    def validate_attempts(cls, value: int) -> int:
        if value <= 0 or value > 20:
            raise ValueError("notification max_attempts must be in 1..20")
        return value

    @field_validator("retention_days")
    @classmethod
    def validate_retention(cls, value: int) -> int:
        if value <= 0 or value > 3650:
            raise ValueError("notification retention_days must be in 1..3650")
        return value


class TunnelMonitorConfig(StrictModel):
    enabled: bool = True
    public_url: str = "https://dev.lu607.com/readyz"
    interval_seconds: int = 60
    timeout_seconds: int = 10
    failure_threshold: int = 3
    alert_after_seconds: int = 3600

    @field_validator("public_url")
    @classmethod
    def validate_public_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlparse(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "tunnel public_url must be an HTTPS URL without credentials, query, or fragment"
            )
        return value

    @field_validator(
        "interval_seconds", "timeout_seconds", "failure_threshold", "alert_after_seconds"
    )
    @classmethod
    def validate_positive(cls, value: int) -> int:
        if value <= 0 or value > 86400:
            raise ValueError("tunnel monitor values must be in 1..86400")
        return value


class OperationsConfig(StrictModel):
    backup_dir: str = "./runtime/backups/operations"
    diagnostic_dir: str = "./runtime/diagnostics"
    backup_interval_hours: int = 24
    backup_retention_count: int = 14
    emergency_token_ttl_seconds: int = 900
    diagnostic_log_tail_lines: int = 500

    @field_validator("backup_interval_hours")
    @classmethod
    def validate_backup_interval(cls, value: int) -> int:
        if not 1 <= value <= 720:
            raise ValueError("backup_interval_hours must be in 1..720")
        return value

    @field_validator("backup_retention_count")
    @classmethod
    def validate_backup_retention(cls, value: int) -> int:
        if not 1 <= value <= 365:
            raise ValueError("backup_retention_count must be in 1..365")
        return value

    @field_validator("emergency_token_ttl_seconds")
    @classmethod
    def validate_emergency_ttl(cls, value: int) -> int:
        if not 60 <= value <= 1800:
            raise ValueError("emergency_token_ttl_seconds must be in 60..1800")
        return value

    @field_validator("diagnostic_log_tail_lines")
    @classmethod
    def validate_diagnostic_tail(cls, value: int) -> int:
        if not 10 <= value <= 10000:
            raise ValueError("diagnostic_log_tail_lines must be in 10..10000")
        return value


class GatewayConfig(StrictModel):
    listen_host: str = "127.0.0.1"
    listen_port: int = 8081
    default_idle_timeout_seconds: int = 300
    default_startup_timeout_seconds: int = 25
    recovery_block_requests: bool = True
    health_poll_interval_seconds: int = 2
    idle_scan_interval_seconds: int = 10
    unhealthy_threshold: int = 3
    auto_restart_failed_apps: bool = True
    restart_max_attempts: int = 3
    restart_backoff_seconds: int = 5
    restart_backoff_max_seconds: int = 300
    restart_window_seconds: int = 900
    restart_stable_seconds: int = 300
    max_log_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 3
    runtime_dir: str = "./runtime"
    log_dir: str = "./logs"
    event_log_path: str = "./logs/events.jsonl"
    api_audit_db_path: str = "./runtime/gateway.sqlite3"
    default_icon: str = "🧩"
    lease_monitor_interval_seconds: int = 15
    audit: AuditConfig = Field(default_factory=AuditConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    tunnel: TunnelMonitorConfig = Field(default_factory=TunnelMonitorConfig)
    operations: OperationsConfig = Field(default_factory=OperationsConfig)

    @field_validator("listen_host")
    @classmethod
    def validate_listen_host(cls, value: str) -> str:
        return _validate_loopback(value)

    @field_validator("listen_port")
    @classmethod
    def validate_listen_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("listen_port must be in 1..65535")
        return value

    @field_validator(
        "default_idle_timeout_seconds",
        "log_backup_count",
    )
    @classmethod
    def validate_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("timeout, interval, and size values must be >= 0")
        return value

    @field_validator(
        "default_startup_timeout_seconds",
        "health_poll_interval_seconds",
        "idle_scan_interval_seconds",
        "restart_backoff_seconds",
        "restart_backoff_max_seconds",
        "restart_window_seconds",
        "restart_stable_seconds",
        "lease_monitor_interval_seconds",
    )
    @classmethod
    def validate_positive_interval(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("startup, polling, scanning, and backoff intervals must be > 0")
        return value

    @field_validator("max_log_bytes")
    @classmethod
    def validate_log_size(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("max_log_bytes must be > 0")
        return value

    @field_validator("unhealthy_threshold", "restart_max_attempts")
    @classmethod
    def validate_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("thresholds must be > 0")
        return value

    @property
    def runtime_path(self) -> Path:
        return Path(self.runtime_dir).resolve()

    @property
    def log_path(self) -> Path:
        return Path(self.log_dir).resolve()

    @property
    def event_log(self) -> Path:
        return Path(self.event_log_path).resolve()

    @property
    def api_audit_db(self) -> Path:
        return Path(self.api_audit_db_path).resolve()
