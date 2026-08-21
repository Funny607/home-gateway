from __future__ import annotations

import asyncio
import csv
import html
import io
import json
import os
import random
import time
import warnings
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, urlencode

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.openapi.utils import get_openapi
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from websockets.asyncio.client import connect as websocket_connect
from websockets.exceptions import ConnectionClosed

from app.api_v1.audit_store import ApiAuditStore
from app.api_v1.admin_security import build_admin_security_router
from app.api_v1.device_auth import build_device_auth_router
from app.api_v1.grant_auth import build_grant_auth_router
from app.api_v1.token_auth import build_token_auth_router
from app.api_v1.action_approval import build_action_approval_router
from app.api_v1.operations import build_operations_router
from app.api_v1.qbt_lease import build_qbt_lease_router
from app.api_v1.leases import build_lease_router
from app.api_v1.notifications import build_notification_router
from app.api_v1.registry import build_registry_router
from app.api_v1.app_proxy import build_api_apps_v1_router
from app.api_v1.gateway import build_gateway_v1_router
from app.api_v1.request_id import get_or_create_request_id

from app.config.loader import load_configs
from app.config.schema import LinkConfig
from app.events import EventRecorder, setup_logger
from app.lifecycle.manager import LifecycleManager
from app.leases.coordinator import LeaseCoordinator, lease_monitor_loop
from app.monitoring.tunnel import TunnelMonitor, tunnel_monitor_loop
from app.notifications.service import NotificationService
from app.operations.service import OperationsService
from app.proxy.reverse_proxy import (
    RequestBodyTooLarge,
    build_streaming_response,
    build_upstream_headers,
    build_websocket_upstream_headers,
    filter_response_headers,
    spool_request_body,
)
from app.proxy.path_security import proxy_path_is_canonical
from app.runtime.store import RuntimeStore
from app.registry.service import AppRegistry, RegistryError
from app.security.auth import (
    AuthConfig,
    PasswordService,
    csrf_token,
    current_identity as security_identity,
    issue_session,
    load_auth_config,
    resolve_reference,
    resolve_session_secret,
    verify_csrf,
    verify_same_origin,
)
from app.security.policy import PolicyEngine
from app.security.http import client_ip
from app.security.rate_limit import SlidingWindowRateLimiter
from app.security.service import SecurityService
from app.security.recovery import RecoveryService
from app.ui import design as ui
from app.ui import pages as ui_pages


CONFIG_DIR = Path(os.environ.get("GATEWAY_CONFIG_DIR", "configs")).resolve()
AUTH_CONFIG_PATH = CONFIG_DIR / "auth.yaml"
VISITOR_PROMPTS_PATH = CONFIG_DIR / "visitor_prompts.txt"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RELEASE_VERSION = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
BOOT_AUTH_CONFIG = load_auth_config(AUTH_CONFIG_PATH)
BOOT_SESSION_SECRET = resolve_session_secret(BOOT_AUTH_CONFIG)
RATE_LIMITER = SlidingWindowRateLimiter()


class AppRuntime:
    def __init__(self) -> None:
        self.manager: Optional[LifecycleManager] = None
        self.http_client: Optional[httpx.AsyncClient] = None
        self.idle_task: Optional[asyncio.Task] = None
        self.monitor_task: Optional[asyncio.Task] = None
        self.event_log_path: Optional[Path] = None
        self.api_audit_store: Optional[ApiAuditStore] = None
        self.security_service: Optional[SecurityService] = None
        self.lease_coordinator: Optional[LeaseCoordinator] = None
        self.app_registry: Optional[AppRegistry] = None
        self.notifications: Optional[NotificationService] = None
        self.tunnel_monitor: Optional[TunnelMonitor] = None
        self.lease_monitor_task: Optional[asyncio.Task] = None
        self.notification_task: Optional[asyncio.Task] = None
        self.tunnel_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None
        self.operations_task: Optional[asyncio.Task] = None
        self.operations: Optional[OperationsService] = None
        self.recovery: Optional[RecoveryService] = None
        self.auth_config: Optional[AuthConfig] = None
        self.password_service: Optional[PasswordService] = None
        self.visitor_prompts: list[str] = []
        self.links: list[LinkConfig] = []


runtime = AppRuntime()


async def idle_loop(manager: LifecycleManager, interval_seconds: int) -> None:
    while True:
        try:
            await manager.idle_scan_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            manager.logger.exception("Idle loop error: %s", exc)
            manager.events.write("idle_loop_error", message=str(exc))
        await asyncio.sleep(interval_seconds)


async def monitor_loop(manager: LifecycleManager, interval_seconds: int) -> None:
    while True:
        try:
            await manager.monitor_apps_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            manager.logger.exception("Monitor loop error: %s", exc)
            manager.events.write("monitor_loop_error", message=str(exc))
        await asyncio.sleep(interval_seconds)


async def notification_loop(service: NotificationService) -> None:
    next_approval_scan = 0.0
    while True:
        processed = 0
        try:
            if time.monotonic() >= next_approval_scan:
                service.scan_pending_approvals()
                next_approval_scan = time.monotonic() + 60
            while processed < 10 and await service.worker_once():
                processed += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            service.logger.exception("Notification worker failed: %s", exc)
        await asyncio.sleep(2 if processed else 5)


async def cleanup_loop(service: SecurityService, gateway_config) -> None:
    while True:
        try:
            service.store.prune(
                audit_retention_days=gateway_config.audit.retention_days,
                notification_retention_days=gateway_config.notifications.retention_days,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        await asyncio.sleep(gateway_config.audit.cleanup_interval_seconds)


async def operations_loop(service: OperationsService) -> None:
    while True:
        await asyncio.sleep(60)
        try:
            if service.due_for_scheduled_backup():
                await asyncio.to_thread(
                    service.create_backup, reason="scheduled backup", actor="system"
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            try:
                service.audit_operation(
                    "scheduled-backup", actor="system", success=False,
                    error_code="SCHEDULED_BACKUP_FAILED", raw={"error": str(exc)[:500]},
                )
            except Exception:
                pass


def load_prompt_lines(path: Path) -> list[str]:
    if not path.exists():
        return [
            "当前为 guest 模式，可查看状态与页面，但不能执行控制操作。",
        ]
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            lines.append(text)
    if not lines:
        lines = ["当前为 guest 模式，可查看状态与页面，但不能执行控制操作。"]
    return lines


@asynccontextmanager
async def lifespan(app: FastAPI):
    gateway_config, apps, links = load_configs(CONFIG_DIR)
    auth_config = load_auth_config(AUTH_CONFIG_PATH)
    gateway_config.runtime_path.mkdir(parents=True, exist_ok=True)
    gateway_config.log_path.mkdir(parents=True, exist_ok=True)
    gateway_config.event_log.parent.mkdir(parents=True, exist_ok=True)

    runtime.api_audit_store = ApiAuditStore(
        gateway_config.api_audit_db,
        pepper=resolve_reference(auth_config.database_pepper_ref),
    )
    runtime.security_service = SecurityService(
        runtime.api_audit_store,
        PolicyEngine(apps),
        totp_secret=(resolve_reference(auth_config.totp_secret_ref) if auth_config.totp_secret_ref else ""),
        desktop_approver_secret=(
            resolve_reference(auth_config.desktop_approver_secret_ref)
            if auth_config.desktop_approver_secret_ref else ""
        ),
    )

    logger = setup_logger(
        gateway_config.log_path,
        max_bytes=gateway_config.max_log_bytes,
        backup_count=gateway_config.log_backup_count,
    )
    events = EventRecorder(
        gateway_config.event_log,
        max_bytes=gateway_config.max_log_bytes,
        backup_count=gateway_config.log_backup_count,
    )
    # Local child-app traffic must never inherit system HTTP(S)/SOCKS proxy settings.
    http_client = httpx.AsyncClient(follow_redirects=False, timeout=30.0, trust_env=False)

    manager = LifecycleManager(
        gateway_config=gateway_config,
        apps=apps,
        runtime_store=RuntimeStore(gateway_config.runtime_path),
        http_client=http_client,
        logger=logger,
        events=events,
    )
    registry = AppRegistry(
        config_dir=CONFIG_DIR,
        manager=manager,
        security=runtime.security_service,
    )
    registry.bootstrap()
    notifications = NotificationService(
        runtime.api_audit_store,
        gateway_config.notifications,
        logger,
    )
    events.subscribe(notifications.handle_event)
    lease_coordinator = LeaseCoordinator(
        manager=manager,
        client=http_client,
        security=runtime.security_service,
    )
    tunnel_monitor = TunnelMonitor(
        config=gateway_config.tunnel,
        client=http_client,
        store=runtime.api_audit_store,
        events=events,
        logger=logger,
    )
    operations = OperationsService(
        project_root=PROJECT_ROOT, config_dir=CONFIG_DIR, log_dir=gateway_config.log_path,
        store=runtime.api_audit_store, config=gateway_config.operations,
        release_version=RELEASE_VERSION,
    )
    recovery = RecoveryService(
        runtime.api_audit_store,
        verifier_secret=(
            resolve_reference(auth_config.breakglass_secret_ref)
            if auth_config.breakglass_secret_ref else ""
        ),
        token_ttl_seconds=gateway_config.operations.emergency_token_ttl_seconds,
    )

    runtime.manager = manager
    runtime.http_client = http_client
    runtime.event_log_path = gateway_config.event_log
    runtime.visitor_prompts = load_prompt_lines(VISITOR_PROMPTS_PATH)
    runtime.links = links
    runtime.auth_config = auth_config
    runtime.password_service = PasswordService(auth_config.users)
    runtime.app_registry = registry
    runtime.notifications = notifications
    runtime.lease_coordinator = lease_coordinator
    runtime.tunnel_monitor = tunnel_monitor
    runtime.operations = operations
    runtime.recovery = recovery

    await manager.recover()

    runtime.idle_task = asyncio.create_task(
        idle_loop(manager, gateway_config.idle_scan_interval_seconds)
    )

    runtime.monitor_task = asyncio.create_task(
        monitor_loop(manager, gateway_config.health_poll_interval_seconds)
    )

    runtime.lease_monitor_task = asyncio.create_task(
        lease_monitor_loop(lease_coordinator, gateway_config.lease_monitor_interval_seconds)
    )
    runtime.notification_task = asyncio.create_task(notification_loop(notifications))
    runtime.tunnel_task = asyncio.create_task(tunnel_monitor_loop(tunnel_monitor))
    runtime.cleanup_task = asyncio.create_task(cleanup_loop(runtime.security_service, gateway_config))
    runtime.operations_task = asyncio.create_task(operations_loop(operations))
    manager.events.write(
        "stage5_operations_started",
        lease_interval_seconds=gateway_config.lease_monitor_interval_seconds,
        tunnel_interval_seconds=gateway_config.tunnel.interval_seconds,
    )

    try:
        yield
    finally:
        for attribute in (
            "lease_monitor_task",
            "notification_task",
            "tunnel_task",
            "cleanup_task",
            "operations_task",
            "idle_task",
            "monitor_task",
        ):
            task = getattr(runtime, attribute)
            if task is not None:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                setattr(runtime, attribute, None)

        await http_client.aclose()


app = FastAPI(
    title="WebUI Home Gateway",
    version=RELEASE_VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.mount(
    "/assets",
    StaticFiles(directory=Path(__file__).resolve().parent / "ui" / "static"),
    name="assets",
)

app.add_middleware(
    SessionMiddleware,
    secret_key=BOOT_SESSION_SECRET,
    session_cookie="gateway_session",
    max_age=BOOT_AUTH_CONFIG.session_max_age_seconds,
    same_site=BOOT_AUTH_CONFIG.same_site,
    https_only=BOOT_AUTH_CONFIG.secure_cookies,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=BOOT_AUTH_CONFIG.allowed_hosts)


@app.middleware("http")
async def audit_control_plane_requests(request: Request, call_next):
    path = request.url.path
    audited = (
        (
            path.startswith("/api/")
            and not path.startswith("/api/apps/v1/")
            and not path.startswith("/api/leases/")
        )
        or path in {"/login", "/logout"}
    )
    started = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        if audited and runtime.security_service is not None:
            runtime.security_service.store.write_api_audit(
                request_id=get_or_create_request_id(request),
                actor_type="control_plane",
                method=request.method,
                path=path,
                status_code=500,
                success=False,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code="UNHANDLED_EXCEPTION",
                client_ip=client_ip(request),
                user_agent=request.headers.get("user-agent", "")[:512],
            )
        raise
    if path.startswith("/api/leases/") and response.status_code >= 400:
        audited = True
    auth_result = response.headers.get("X-Gateway-Auth-Result", "")
    audit_success = response.status_code < 400 and auth_result not in {"failed", "rate_limited"}
    if audited and runtime.security_service is not None:
        identity = current_identity(request)
        try:
            runtime.security_service.store.write_api_audit(
                request_id=get_or_create_request_id(request),
                actor_type="session" if identity["authenticated"] == "true" else "control_plane",
                actor_name=identity["username"],
                method=request.method,
                path=path,
                status_code=response.status_code,
                success=audit_success,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_code=(
                    ""
                    if audit_success
                    else ("LOGIN_RATE_LIMITED" if auth_result == "rate_limited" else "CONTROL_PLANE_REJECTED")
                ),
                client_ip=client_ip(request),
                user_agent=request.headers.get("user-agent", "")[:512],
                raw={"query_keys": sorted(request.query_params.keys())},
            )
        except Exception:
            pass
    if "X-Gateway-Auth-Result" in response.headers:
        del response.headers["X-Gateway-Auth-Result"]
    response.headers.setdefault("X-Gateway-Request-Id", get_or_create_request_id(request))
    gateway_managed = (
        path == "/"
        or path.startswith("/api/")
        or path.startswith("/dashboard")
        or path.startswith("/login")
        or path.startswith("/logout")
        or path.startswith("/assets/")
        or path in {"/health", "/healthz", "/readyz", "/docs", "/redoc", "/openapi.json"}
    )
    if gateway_managed:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
    if (
        path.startswith("/api/")
        or path.startswith("/login")
        or path.startswith("/logout")
        or path.startswith("/dashboard")
        or path == "/health"
    ):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def get_manager() -> LifecycleManager:
    if runtime.manager is None:
        raise RuntimeError("manager not initialized")
    return runtime.manager


def get_http_client() -> httpx.AsyncClient:
    """
    返回 Gateway 共享 httpx client。

    External API 与清单驱动的 adapter 会复用这个 client。
    """
    if runtime.http_client is None:
        raise RuntimeError("http client not initialized")
    return runtime.http_client


def get_api_audit_store() -> ApiAuditStore:
    """
    返回统一安全与 API 审计库。

    目前用于记录 /api/apps/v1 的 capability-based API 穿透调用。
    """
    if runtime.api_audit_store is None:
        raise RuntimeError("api audit store not initialized")
    return runtime.api_audit_store


def get_security_service() -> SecurityService:
    if runtime.security_service is None:
        raise RuntimeError("security service not initialized")
    return runtime.security_service


def get_lease_coordinator() -> LeaseCoordinator:
    if runtime.lease_coordinator is None:
        raise RuntimeError("lease coordinator not initialized")
    return runtime.lease_coordinator


def get_app_registry() -> AppRegistry:
    if runtime.app_registry is None:
        raise RuntimeError("app registry not initialized")
    return runtime.app_registry


def get_notifications() -> NotificationService:
    if runtime.notifications is None:
        raise RuntimeError("notification service not initialized")
    return runtime.notifications


def get_operations() -> OperationsService:
    if runtime.operations is None:
        raise RuntimeError("operations service not initialized")
    return runtime.operations


def get_recovery() -> RecoveryService:
    if runtime.recovery is None:
        raise RuntimeError("recovery service not initialized")
    return runtime.recovery



def format_ts(ts_value: Any) -> str:
    if not ts_value:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts_value)))
    except Exception:
        return "-"


def h(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def pretty_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        return str(value)


def current_identity(request: Request) -> dict[str, str]:
    identity = security_identity(request, BOOT_AUTH_CONFIG.session_max_age_seconds)
    return {
        "authenticated": "true" if identity["authenticated"] else "false",
        "username": str(identity["username"]),
        "role": str(identity["role"]),
    }


def is_authenticated(request: Request) -> bool:
    return current_identity(request)["authenticated"] == "true"


def can_view(request: Request) -> bool:
    return is_authenticated(request)


def can_control(request: Request) -> bool:
    identity = current_identity(request)
    return identity["role"] == "admin"


def visible_apps(request: Request) -> list[dict[str, Any]]:
    manager = get_manager()
    role = current_identity(request)["role"]
    return [
        item
        for item in manager.snapshot()
        if role in manager.get_app(item["app_id"]).config.dashboard.visible_roles
    ]


def visible_events(request: Request, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    allowed = {item["app_id"] for item in visible_apps(request)}
    return [item for item in events if not item.get("app_id") or item.get("app_id") in allowed]


def pick_guest_prompt() -> str:
    prompts = runtime.visitor_prompts or ["当前为 guest 模式，可查看状态与页面，但不能执行控制操作。"]
    return random.choice(prompts)


def set_flash_message(request: Request, message: str) -> None:
    request.session["flash_message"] = message


def pop_flash_message(request: Request) -> str:
    value = str(request.session.pop("flash_message", "") or "")
    return value




def unauthorized_json(status_code: int = 403, message: str | None = None) -> JSONResponse:
    if message is None:
        message = pick_guest_prompt()
    return JSONResponse(
        status_code=status_code,
        content={
            "ok": False,
            "error": "permission_denied" if status_code == 403 else "authentication_required",
            "message": message,
        },
    )


def get_redirect_target(
    app_id: str,
    back: str | None,
    *,
    tab: str | None = None,
    state: str | None = None,
    q: str | None = None,
) -> str:
    if back == "detail":
        safe_tab = tab if tab in {"overview", "activity", "logs", "access"} else "overview"
        return f"/dashboard/apps/{app_id}?{urlencode({'tab': safe_tab})}"
    if back == "apps":
        params: dict[str, str] = {}
        if state in {"all", "running", "stopped", "failed"}:
            params["state"] = str(state)
        if q:
            params["q"] = str(q)[:160]
        return "/dashboard/apps" + (f"?{urlencode(params)}" if params else "")
    return "/dashboard"




def require_login_redirect(request: Request) -> RedirectResponse:
    set_flash_message(request, "请先登录。")
    return RedirectResponse(url="/login", status_code=303)


def read_recent_events(
    limit: int = 50,
    app_id: str | None = None,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    path = runtime.event_log_path
    if path is None or not path.exists():
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    result: list[dict[str, Any]] = []

    for line in reversed(lines):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if app_id is not None and event.get("app_id") != app_id:
            continue

        if event_type is not None and event.get("event_type") != event_type:
            continue

        result.append(event)
        if len(result) >= limit:
            break

    return result


def collect_event_types(limit_scan: int = 500) -> list[str]:
    path = runtime.event_log_path
    if path is None or not path.exists():
        return []

    event_types: set[str] = set()
    lines = path.read_text(encoding="utf-8").splitlines()[-limit_scan:]
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        value = event.get("event_type")
        if isinstance(value, str) and value:
            event_types.add(value)

    return sorted(event_types)




def summarize_apps(snapshot: list[dict[str, Any]]) -> dict[str, int]:
    total = len(snapshot)
    running = sum(1 for item in snapshot if item["state"] == "running")
    stopped = sum(1 for item in snapshot if item["state"] == "stopped")
    failed = sum(1 for item in snapshot if item["state"] == "failed")
    transitional = sum(1 for item in snapshot if item["state"] in {"starting", "stopping"})
    unhealthy = sum(
        1
        for item in snapshot
        if item["state"] == "running" and item.get("last_health_check_ok") is False
    )
    return {
        "total": total,
        "running": running,
        "stopped": stopped,
        "failed": failed,
        "transitional": transitional,
        "unhealthy": unhealthy,
    }


def render_gateway_page(
    request: Request,
    *,
    title: str,
    description: str,
    content: str,
    active_nav: str,
    page_actions: str = "",
    breadcrumbs: tuple[tuple[str, str], ...] = (),
    section_tabs: str = "",
    flash_message: str | None = None,
) -> HTMLResponse:
    """Render every authenticated screen from the same goal-driven shell."""
    manager = get_manager()
    identity = current_identity(request)
    snapshot = visible_apps(request)
    pending_count = 0
    unread_count = 0
    if identity["role"] == "admin" and runtime.security_service is not None:
        try:
            pending_count = sum(
                1 for row in get_security_service().list_approvals() if row.get("status") == "pending"
            )
        except Exception:
            pending_count = 0
        try:
            unread_count = get_notifications().unread_count()
        except Exception:
            unread_count = 0
    failed_count = sum(
        1
        for item in snapshot
        if item.get("state") == "failed"
        or (item.get("state") == "running" and item.get("last_health_check_ok") is False)
    )
    commands: list[ui.CommandItem] = []
    for item in snapshot:
        config = manager.get_app(str(item["app_id"])).config
        if identity["role"] in config.dashboard.allow_detail_roles:
            commands.append(
                ui.CommandItem(
                    label=str(item["display_name"]),
                    url=f'/dashboard/apps/{item["app_id"]}',
                    group="应用",
                    description=str(item.get("state", "")),
                    icon_name="apps",
                )
            )
    message = pop_flash_message(request) if flash_message is None else flash_message
    return ui.render_shell(
        title=title,
        description=description,
        content=content,
        identity=identity,
        csrf_value=csrf_token(request),
        active_nav=active_nav,
        gateway_phase=manager.phase,
        version=RELEASE_VERSION,
        pending_approvals=pending_count,
        failed_apps=failed_count,
        unread_notifications=unread_count,
        tunnel_state=(runtime.tunnel_monitor.snapshot() if runtime.tunnel_monitor else {}),
        page_actions=page_actions,
        breadcrumbs=breadcrumbs,
        section_tabs=section_tabs,
        command_items=commands,
        flash_message=message,
    )




def tail_file(path: Path, lines: int = 50) -> str:
    if not path.exists():
        return "(file not found)"
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not content:
            return "(empty file)"
        return "\n".join(content[-lines:])
    except Exception as exc:
        return f"(failed to read file: {exc})"


def get_app_log_paths(app_id: str) -> tuple[Path, Path]:
    manager = get_manager()
    log_dir = manager.gateway_config.log_path / "apps"
    return (
        log_dir / f"{app_id}.stdout.log",
        log_dir / f"{app_id}.stderr.log",
    )


def render_upstream_error_page(
    request: Request,
    *,
    title: str,
    app_id: str,
    app_path: str,
    upstream_url: str,
    message: str,
) -> HTMLResponse:
    content = f"""
    {ui.notice(message, kind="danger", title="代理异常")}
    <section class="surface surface-padded">
      <dl class="detail-list">
        <dt>应用</dt><dd><code>{h(app_id)}</code></dd>
        <dt>Gateway 路径</dt><dd><code>{h(app_path)}</code></dd>
        <dt>内部目标</dt><dd><code>{h(upstream_url)}</code></dd>
        <dt>判断</dt><dd>Gateway 已允许该访问，但本地上游应用启动失败或当前不可达。</dd>
      </dl>
    </section>"""
    return render_gateway_page(
        request,
        title=title,
        description="Gateway 无法完成到本地应用的代理请求。",
        content=content,
        active_nav="apps",
        page_actions=f'<a class="button secondary" href="/dashboard/apps/{h(app_id)}">查看应用详情</a>',
        breadcrumbs=(("应用", "/dashboard/apps"), (app_id, f"/dashboard/apps/{app_id}"), ("代理异常", "")),
    )



async def do_start(app_id: str) -> dict[str, Any]:
    manager = get_manager()
    record = await manager.ensure_started(app_id)
    return {
        "app_id": app_id,
        "state": "running",
        "internal_url": record.internal_url,
        "pid": record.pid,
    }


async def do_stop(app_id: str) -> dict[str, Any]:
    active_leases = get_security_service().active_lease_count(app_id)
    if active_leases:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot stop {app_id}: {active_leases} lease(s) require recovery or release first",
        )
    manager = get_manager()
    await manager.stop(app_id, reason="manual stop api")
    return {"app_id": app_id, "state": "stopped"}


async def do_restart(app_id: str) -> dict[str, Any]:
    manager = get_manager()
    await manager.stop(app_id, reason="manual restart api")
    record = await manager.ensure_started(app_id)
    return {
        "app_id": app_id,
        "state": "running",
        "internal_url": record.internal_url,
        "pid": record.pid,
    }


@app.get("/", include_in_schema=False)
async def root_redirect(request: Request) -> RedirectResponse:
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/dashboard", status_code=307)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
async def readyz():
    ready = runtime.manager is not None and runtime.manager.phase == "ready"
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "recovering"},
    )


@app.get("/health")
async def health(request: Request) -> dict[str, Any]:
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Login required")
    manager = get_manager()
    return {
        "status": "ok",
        "phase": manager.phase,
        "apps": visible_apps(request),
        "links": [
            {
                "link_id": link.link_id,
                "display_name": link.display_name,
                "icon": link.icon or "",
                "url": link.url,
                "description": link.description,
            }
            for link in runtime.links
        ],
    }


@app.get("/api/admin/v1/openapi.json", include_in_schema=False)
async def protected_openapi(request: Request):
    if not can_control(request):
        raise HTTPException(status_code=403, detail="Administrator role required")
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Duplicate Operation ID*")
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description="Authenticated Gateway API surface. Catch-all WebUI proxy is intentionally omitted.",
            routes=app.routes,
        )
    for path, operations in schema.get("paths", {}).items():
        for method, operation in operations.items():
            if isinstance(operation, dict) and "operationId" in operation:
                base = str(operation["operationId"]).rsplit("_", 1)[0]
                operation["operationId"] = f"{base}_{method.lower()}"
    return schema


@app.get("/api/apps")
async def list_apps(request: Request) -> list[dict[str, Any]]:
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Login required")
    return visible_apps(request)


@app.get("/api/events")
async def list_events(
    request: Request,
    limit: int = 50,
    app_id: str | None = None,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="Login required")
    return visible_events(
        request,
        read_recent_events(limit=limit, app_id=app_id, event_type=event_type),
    )


@app.get("/api/audit/v1")
async def list_api_audit(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    limit: int | None = Query(default=None, ge=1, le=500),
    target_app: str = Query(default="", max_length=64),
    device_id: str = Query(default="", max_length=160),
    success: bool | None = Query(default=None),
    actor_type: str = Query(default="", max_length=64),
    capability: str = Query(default="", max_length=160),
    request_id: str = Query(default="", max_length=160),
    since: int | None = None,
    until: int | None = None,
    status_code: int | None = Query(default=None, ge=100, le=599),
) -> dict[str, Any]:
    if not can_control(request):
        raise HTTPException(status_code=403, detail="Administrator role required")
    # ``limit`` was the Stage1 query parameter. Keep it as an alias for page 1
    # so existing local scripts continue to receive the requested row count.
    if limit is not None:
        page = 1
        page_size = limit
    return {
        "ok": True,
        **get_security_service().query_audit(
            page=page,
            page_size=page_size,
            target_app=target_app,
            device_id=device_id,
            success=success,
            actor_type=actor_type,
            capability=capability,
            request_id=request_id,
            since=since,
            until=until,
            status_code=status_code,
        ),
    }


@app.get("/api/audit/v1/export")
async def export_api_audit(
    request: Request,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    target_app: str = Query(default="", max_length=64),
    device_id: str = Query(default="", max_length=160),
    success: bool | None = Query(default=None),
    actor_type: str = Query(default="", max_length=64),
    capability: str = Query(default="", max_length=160),
    since: int | None = None,
    until: int | None = None,
):
    if not can_control(request):
        raise HTTPException(status_code=403, detail="Administrator role required")
    limit = get_manager().gateway_config.audit.export_limit
    page = get_security_service().query_audit(
        page=1,
        page_size=limit,
        target_app=target_app,
        device_id=device_id,
        success=success,
        actor_type=actor_type,
        capability=capability,
        since=since,
        until=until,
        max_page_size=limit,
    )
    rows = page["items"]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if format == "json":
        return Response(
            json.dumps({"items": rows, "total": page["total"]}, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="gateway-audit-{stamp}.json"'},
        )
    output = io.StringIO()
    fields = [
        "id", "created_at", "request_id", "actor_type", "actor_name", "device_id",
        "target_app", "capability", "method", "path", "upstream_path", "status_code",
        "success", "duration_ms", "error_code", "risk_level",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        safe_row: dict[str, Any] = {}
        for field in fields:
            value = row.get(field, "")
            text_value = "" if value is None else str(value)
            if text_value.startswith(("=", "+", "-", "@", "\t", "\r")):
                text_value = "'" + text_value
            safe_row[field] = text_value
        writer.writerow(safe_row)
    return Response(
        output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="gateway-audit-{stamp}.csv"'},
    )


@app.post("/api/apps/{app_id}/start")
async def start_app(request: Request, app_id: str):
    if not is_authenticated(request):
        return unauthorized_json(status_code=401, message="Login required")
    if not can_control(request):
        return unauthorized_json(status_code=403, message=pick_guest_prompt())
    verify_csrf(request, request.headers.get("x-csrf-token"))
    try:
        return await do_start(app_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/apps/{app_id}/stop")
async def stop_app(request: Request, app_id: str):
    if not is_authenticated(request):
        return unauthorized_json(status_code=401, message="Login required")
    if not can_control(request):
        return unauthorized_json(status_code=403, message=pick_guest_prompt())
    verify_csrf(request, request.headers.get("x-csrf-token"))
    try:
        return await do_stop(app_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/apps/{app_id}/restart")
async def restart_app(request: Request, app_id: str):
    if not is_authenticated(request):
        return unauthorized_json(status_code=401, message="Login required")
    if not can_control(request):
        return unauthorized_json(status_code=403, message=pick_guest_prompt())
    verify_csrf(request, request.headers.get("x-csrf-token"))
    try:
        return await do_restart(app_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/apps/{app_id}/retry")
async def retry_app(request: Request, app_id: str):
    if not is_authenticated(request):
        return unauthorized_json(status_code=401, message="Login required")
    if not can_control(request):
        return unauthorized_json(status_code=403, message=pick_guest_prompt())
    verify_csrf(request, request.headers.get("x-csrf-token"))
    manager = get_manager()
    try:
        record = await manager.retry(app_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "app_id": app_id,
        "state": "running",
        "internal_url": record.internal_url,
        "pid": record.pid,
    }


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    flash = pop_flash_message(request)
    identity = current_identity(request)

    return ui.render_login(
        csrf_value=csrf_token(request),
        flash_message=flash,
        gateway_phase=get_manager().phase,
        version=RELEASE_VERSION,
    )



@app.post("/login")
async def login_submit(request: Request) -> RedirectResponse:
    content_length = request.headers.get("content-length", "")
    try:
        if content_length and int(content_length) > 16384:
            raise HTTPException(status_code=413, detail="Login form is too large")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
    form = await request.form()
    try:
        verify_csrf(request, str(form.get("csrf_token", "")))
    except HTTPException:
        request.session.clear()
        set_flash_message(request, "登录页已过期，请重新提交。")
        return RedirectResponse(
            url="/login", status_code=303, headers={"X-Gateway-Auth-Result": "failed"}
        )
    username = str(form.get("username", "")).strip()[:128]
    password = str(form.get("password", ""))
    source = client_ip(request)
    rate_keys = (
        (f"login-ip:{source}", BOOT_AUTH_CONFIG.login_attempts * 3),
        (f"login-account:{source}:{username.lower()[:64]}", BOOT_AUTH_CONFIG.login_attempts),
    )
    for rate_key, limit in rate_keys:
        decision = RATE_LIMITER.check(
            rate_key,
            limit=limit,
            window_seconds=BOOT_AUTH_CONFIG.login_window_seconds,
            block_seconds=BOOT_AUTH_CONFIG.login_block_seconds,
        )
        if not decision.allowed:
            set_flash_message(request, f"登录尝试过多，请在 {decision.retry_after_seconds} 秒后重试。")
            return RedirectResponse(
                url="/login",
                status_code=303,
                headers={"X-Gateway-Auth-Result": "rate_limited"},
            )

    if runtime.password_service is None:
        raise HTTPException(status_code=503, detail="Authentication service unavailable")
    role = runtime.password_service.verify(username, password[:1024])
    if role is None:
        set_flash_message(request, "登录失败：用户名或密码错误。")
        return RedirectResponse(
            url="/login", status_code=303, headers={"X-Gateway-Auth-Result": "failed"}
        )
    for rate_key, _ in rate_keys:
        RATE_LIMITER.reset(rate_key)
    issue_session(request, username, role)
    set_flash_message(request, f"登录成功，当前角色：{role}")
    return RedirectResponse(
        url="/dashboard", status_code=303, headers={"X-Gateway-Auth-Result": "success"}
    )


@app.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    request.session.clear()
    set_flash_message(request, "你已退出登录。")
    return RedirectResponse(url="/login", status_code=303)


@app.post("/dashboard/apps/{app_id}/start")
async def dashboard_start_app(
    request: Request,
    app_id: str,
    back: str | None = None,
    tab: str | None = None,
    state: str | None = None,
    q: str | None = None,
) -> RedirectResponse:
    if not is_authenticated(request):
        return require_login_redirect(request)
    target = get_redirect_target(app_id, back, tab=tab, state=state, q=q)
    if not can_control(request):
        set_flash_message(request, pick_guest_prompt())
        return RedirectResponse(url=target, status_code=303)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    await do_start(app_id)
    return RedirectResponse(url=target, status_code=303)


@app.post("/dashboard/apps/{app_id}/stop")
async def dashboard_stop_app(
    request: Request,
    app_id: str,
    back: str | None = None,
    tab: str | None = None,
    state: str | None = None,
    q: str | None = None,
) -> RedirectResponse:
    if not is_authenticated(request):
        return require_login_redirect(request)
    target = get_redirect_target(app_id, back, tab=tab, state=state, q=q)
    if not can_control(request):
        set_flash_message(request, pick_guest_prompt())
        return RedirectResponse(url=target, status_code=303)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    await do_stop(app_id)
    return RedirectResponse(url=target, status_code=303)


@app.post("/dashboard/apps/{app_id}/restart")
async def dashboard_restart_app(
    request: Request,
    app_id: str,
    back: str | None = None,
    tab: str | None = None,
    state: str | None = None,
    q: str | None = None,
) -> RedirectResponse:
    if not is_authenticated(request):
        return require_login_redirect(request)
    target = get_redirect_target(app_id, back, tab=tab, state=state, q=q)
    if not can_control(request):
        set_flash_message(request, pick_guest_prompt())
        return RedirectResponse(url=target, status_code=303)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    await do_restart(app_id)
    return RedirectResponse(url=target, status_code=303)


@app.post("/dashboard/apps/{app_id}/retry")
async def dashboard_retry_app(
    request: Request,
    app_id: str,
    back: str | None = None,
    tab: str | None = None,
    state: str | None = None,
    q: str | None = None,
) -> RedirectResponse:
    if not is_authenticated(request):
        return require_login_redirect(request)
    target = get_redirect_target(app_id, back, tab=tab, state=state, q=q)
    if not can_control(request):
        set_flash_message(request, pick_guest_prompt())
        return RedirectResponse(url=target, status_code=303)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    manager = get_manager()
    await manager.retry(app_id)
    return RedirectResponse(url=target, status_code=303)


@app.get("/dashboard/apps", response_class=HTMLResponse)
async def dashboard_apps(
    request: Request,
    q: str = Query(default="", max_length=160),
    state: str = Query(default="all", max_length=24),
    tab: str = Query(default="running", max_length=24),
    edit: str = Query(default="", max_length=64),
) -> HTMLResponse:
    if not can_view(request):
        return require_login_redirect(request)
    if state not in {"all", "running", "stopped", "failed"}:
        state = "all"
    manager = get_manager()
    snapshot = visible_apps(request)
    role = current_identity(request)["role"]
    if tab == "registry" and role == "admin":
        editor_app_id = ""
        expected_revision = ""
        manifest_data: dict[str, Any] = {
            "manifest_version": 1,
            "app_id": "new-app",
            "display_name": "New App",
            "mount_path": "/apps/new-app",
            "workdir": "/Users/yuanqilu/dev/new-app",
            "command": ["/usr/bin/python3", "-m", "app.main", "--host", "{host}", "--port", "{port}"],
            "listen_host": "127.0.0.1",
            "health_path": "/health",
            "lifecycle": {"start_policy": "on_demand"},
        }
        if edit:
            try:
                existing = manager.get_app(edit)
            except KeyError:
                set_flash_message(request, "要编辑的应用不存在。")
            else:
                manifest_data = existing.config.model_dump(mode="json", exclude_none=True)
                editor_app_id = edit
                expected_revision = get_app_registry().revision(existing.config)
        content = ui_pages.registry_content(
            rows=get_app_registry().list(),
            csrf_value=csrf_token(request),
            editor_manifest=yaml.safe_dump(manifest_data, allow_unicode=True, sort_keys=False),
            expected_revision=expected_revision,
            editor_app_id=editor_app_id,
        )
    else:
        tab = "running"
        content = ui_pages.apps_content(
            snapshot=snapshot,
            role=role,
            config_for=lambda app_id: manager.get_app(app_id).config,
            csrf_value=csrf_token(request),
            query=q,
            state_filter=state,
        )
    tabs = ui_pages.section_tabs(
        (
            ("running", "运行与健康", "/dashboard/apps?tab=running"),
            ("registry", "应用注册表", "/dashboard/apps?tab=registry"),
        ) if role == "admin" else (("running", "运行与健康", "/dashboard/apps"),),
        tab,
    )
    return render_gateway_page(
        request,
        title="应用",
        description="管理接入 Gateway 的本地 WebUI、生命周期状态和受控入口。",
        content=content,
        active_nav="apps",
        section_tabs=tabs,
        page_actions=f'<a class="button secondary" href="/dashboard/apps?tab={h(tab)}&state={h(state)}">{ui.icon("refresh", size=16)}刷新</a>',
    )


@app.post("/dashboard/apps/registry/save")
async def dashboard_registry_save(request: Request) -> RedirectResponse:
    if not can_control(request):
        return require_login_redirect(request) if not is_authenticated(request) else RedirectResponse("/dashboard/apps", status_code=303)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    try:
        result = get_app_registry().save(
            manifest=str(form.get("manifest", "")),
            actor=current_identity(request)["username"],
            expected_revision=str(form.get("expected_revision", "")),
        )
        set_flash_message(request, f'应用 {result["app"]["app_id"]} 清单已保存。')
    except RegistryError as exc:
        set_flash_message(request, f"清单未保存：{exc}")
    return RedirectResponse("/dashboard/apps?tab=registry", status_code=303)


@app.post("/dashboard/apps/registry/{app_id}/{operation}")
async def dashboard_registry_toggle(request: Request, app_id: str, operation: str) -> RedirectResponse:
    if not can_control(request):
        return require_login_redirect(request) if not is_authenticated(request) else RedirectResponse("/dashboard/apps", status_code=303)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    if operation not in {"enable", "disable"}:
        raise HTTPException(status_code=404, detail="Unknown registry operation")
    try:
        await get_app_registry().set_enabled(
            app_id=app_id,
            enabled=operation == "enable",
            actor=current_identity(request)["username"],
            reason="disabled by administrator",
        )
        set_flash_message(request, f"应用 {app_id} 已{'启用' if operation == 'enable' else '停用'}。")
    except (RegistryError, KeyError, RuntimeError) as exc:
        set_flash_message(request, f"状态未改变：{exc}")
    return RedirectResponse("/dashboard/apps?tab=registry", status_code=303)


@app.get("/dashboard/activity", response_class=HTMLResponse)
async def dashboard_activity(
    request: Request,
    tab: str = Query(default="events", max_length=16),
    app_id: str | None = Query(default=None, max_length=64),
    event_type: str | None = Query(default=None, max_length=128),
    success: str = Query(default="", max_length=8),
    limit: int = Query(default=100, ge=1, le=500),
) -> HTMLResponse:
    if not can_view(request):
        return require_login_redirect(request)
    role = current_identity(request)["role"]
    if tab == "audit" and role != "admin":
        tab = "events"
    if tab not in {"events", "audit"}:
        tab = "events"
    events = visible_events(
        request,
        read_recent_events(limit=limit, app_id=app_id, event_type=event_type),
    )
    if success not in {"", "true", "false"}:
        success = ""
    audit_success = None if not success else success == "true"
    audits = (
        get_security_service().list_audit(
            limit=limit,
            target_app=app_id or "",
            success=audit_success,
        )
        if role == "admin" and tab == "audit"
        else []
    )
    content, tabs = ui_pages.activity_content(
        events=events,
        audits=audits,
        role=role,
        tab=tab,
        app_id=app_id or "",
        event_type=event_type or "",
        limit=limit,
        app_options=[str(item["app_id"]) for item in visible_apps(request)],
        event_types=collect_event_types(),
        audit_success=success,
    )
    return render_gateway_page(
        request,
        title="活动",
        description="按时间追踪应用生命周期、恢复事件和外部 API 调用。",
        content=content,
        active_nav="activity",
        section_tabs=tabs,
        page_actions=f'<a class="button secondary" href="/dashboard/activity?tab={h(tab)}">{ui.icon("refresh", size=16)}刷新</a>',
    )


@app.get("/dashboard/system", response_class=HTMLResponse)
async def dashboard_system(request: Request) -> RedirectResponse:
    if not can_view(request):
        return require_login_redirect(request)
    return RedirectResponse("/dashboard/settings", status_code=308)


@app.get("/dashboard/settings", response_class=HTMLResponse)
async def dashboard_settings(
    request: Request,
    tab: str = Query(default="general", max_length=24),
) -> HTMLResponse:
    if not can_view(request):
        return require_login_redirect(request)
    if not can_control(request):
        raise HTTPException(status_code=403, detail="Administrator role required")
    if tab not in {"general", "notifications", "integrations", "security", "about"}:
        tab = "general"
    manager = get_manager()
    content, tabs, actions = ui_pages.settings_content(
        tab=tab,
        phase=manager.phase,
        config_dir=CONFIG_DIR,
        gateway_config=manager.gateway_config,
        security_summary=get_security_service().security_summary(),
        notification_health=get_notifications().health(),
        tunnel_state=(runtime.tunnel_monitor.snapshot() if runtime.tunnel_monitor else {}),
        version=RELEASE_VERSION,
        csrf_value=csrf_token(request),
    )
    return render_gateway_page(
        request,
        title="设置",
        description="管理 Gateway 行为、通知通道、只读集成与数据保留策略。",
        content=content,
        active_nav="settings",
        section_tabs=tabs,
        page_actions=actions or f'<a class="button secondary" href="/dashboard/settings?tab={h(tab)}">{ui.icon("refresh", size=16)}重新检查</a>',
    )


@app.get("/dashboard/notifications", response_class=HTMLResponse)
async def dashboard_notifications(
    request: Request,
    page: int = Query(default=1, ge=1),
) -> HTMLResponse:
    if not can_view(request):
        return require_login_redirect(request)
    if not can_control(request):
        raise HTTPException(status_code=403, detail="Administrator role required")
    page_data = get_notifications().list(page=page, page_size=30)
    content = ui_pages.notifications_content(
        page_data=page_data, csrf_value=csrf_token(request), page=page
    )
    actions = (
        '<form class="inline-form" method="post" action="/dashboard/notifications/read-all">'
        f'<input type="hidden" name="csrf_token" value="{h(csrf_token(request))}">'
        '<button class="button secondary" type="submit">全部标为已读</button></form>'
    )
    return render_gateway_page(
        request,
        title="通知中心",
        description="查看异常、恢复、审批和邮件投递的持久化记录。",
        content=content,
        active_nav="",
        page_actions=actions,
        breadcrumbs=(("通知中心", ""),),
    )


@app.post("/dashboard/notifications/read-all")
async def dashboard_notifications_read_all(request: Request) -> RedirectResponse:
    if not can_control(request):
        return require_login_redirect(request)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    updated = get_notifications().mark_read()
    set_flash_message(request, f"已将 {updated} 条通知标为已读。")
    return RedirectResponse("/dashboard/notifications", status_code=303)


@app.post("/dashboard/notifications/{notification_id}/read")
async def dashboard_notification_read(request: Request, notification_id: str) -> RedirectResponse:
    if not can_control(request):
        return require_login_redirect(request)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    get_notifications().mark_read(notification_id)
    return RedirectResponse("/dashboard/notifications", status_code=303)


@app.post("/dashboard/notifications/test")
async def dashboard_notification_test(request: Request) -> RedirectResponse:
    if not can_control(request):
        return require_login_redirect(request)
    form = await request.form()
    verify_csrf(request, str(form.get("csrf_token", "")))
    get_notifications().enqueue(
        category="test",
        severity="info",
        title="Home Gateway 测试通知",
        message=f'管理员 {current_identity(request)["username"]} 发起了通知通道测试。',
        dedupe_key="test",
        force=True,
    )
    set_flash_message(request, "测试通知已加入发送队列。")
    return RedirectResponse("/dashboard/settings?tab=notifications", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    if not can_view(request):
        return require_login_redirect(request)

    manager = get_manager()
    snapshot = visible_apps(request)
    summary = summarize_apps(snapshot)
    role = current_identity(request)["role"]
    pending = []
    if role == "admin":
        pending = [
            row for row in get_security_service().list_approvals() if row.get("status") == "pending"
        ]
    content = ui_pages.overview_content(
        snapshot=snapshot,
        summary=summary,
        pending_approvals=pending,
        recent_events=visible_events(request, read_recent_events(limit=20)),
        role=role,
        config_for=lambda app_id: manager.get_app(app_id).config,
        csrf_value=csrf_token(request),
        phase=manager.phase,
    )
    return render_gateway_page(
        request,
        title="概览",
        description="先处理风险与异常，再查看应用和最近活动。",
        content=content,
        active_nav="overview",
        page_actions=f'<a class="button secondary" href="/dashboard">{ui.icon("refresh", size=16)}刷新</a>',
    )



@app.get("/dashboard/apps/{app_id}", response_class=HTMLResponse)
async def dashboard_app_detail(
    request: Request,
    app_id: str,
    tab: str = Query(default="overview", max_length=16),
) -> HTMLResponse:
    if not can_view(request):
        return require_login_redirect(request)

    manager = get_manager()
    try:
        app_state = manager.get_app(app_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown app_id: {app_id}") from exc
    snapshot = {item["app_id"]: item for item in manager.snapshot()}
    item = snapshot.get(app_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Unknown app_id: {app_id}")
    role = current_identity(request)["role"]
    if role not in app_state.config.dashboard.visible_roles or role not in app_state.config.dashboard.allow_detail_roles:
        raise HTTPException(status_code=403, detail="This app detail is not visible to your role")

    if tab not in {"overview", "activity", "logs", "access"}:
        tab = "overview"
    runtime_data: dict[str, Any] = {"snapshot": item}
    if app_state.runtime is not None:
        try:
            runtime_data["runtime"] = app_state.runtime.model_dump()
        except Exception:
            runtime_data["runtime"] = {"repr": repr(app_state.runtime)}
    stdout_path, stderr_path = get_app_log_paths(app_id)
    content, tabs, actions = ui_pages.app_detail_content(
        item=item,
        config=app_state.config,
        runtime_data=runtime_data,
        recent_events=read_recent_events(limit=100, app_id=app_id),
        stdout_tail=tail_file(stdout_path, 50),
        stderr_tail=tail_file(stderr_path, 50),
        tab=tab,
        role=role,
        csrf_value=csrf_token(request),
    )
    return render_gateway_page(
        request,
        title=str(item["display_name"]),
        description=f'{app_id} · 统一入口 {item["mount_path"]}',
        content=content,
        active_nav="apps",
        page_actions=actions,
        breadcrumbs=(("应用", "/dashboard/apps"), (str(item["display_name"]), "")),
        section_tabs=tabs,
    )



@app.get("/dashboard/events", response_class=HTMLResponse)
async def dashboard_events(
    request: Request,
    app_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> HTMLResponse:
    if not can_view(request):
        return require_login_redirect(request)

    query: list[str] = ["tab=events"]
    if app_id:
        query.append(f"app_id={quote(app_id)}")
    if event_type:
        query.append(f"event_type={quote(event_type)}")
    query.append(f"limit={limit}")
    return RedirectResponse(url="/dashboard/activity?" + "&".join(query), status_code=308)



def render_guest_block_page(request: Request, title: str, message: str, app_path: str) -> HTMLResponse:
    content = f"""
    {ui.notice(message, kind="warning", title="无权代理")}
    <section class="surface surface-padded">
      <dl class="detail-list">
        <dt>请求路径</dt><dd><code>{h(app_path)}</code></dd>
        <dt>当前角色</dt><dd>{h(current_identity(request)["role"])}</dd>
        <dt>安全行为</dt><dd>Gateway 不会自动唤醒应用，也不会向上游发送该请求。</dd>
      </dl>
    </section>"""
    return render_gateway_page(
        request,
        title=title,
        description="该访问在到达本地应用之前已被 Gateway 拒绝。",
        content=content,
        active_nav="apps",
        page_actions='<a class="button secondary" href="/dashboard/apps">返回应用</a>',
    )



# =============================================================================
# External API and control-plane routers
# =============================================================================
#
# 注意：
# 这两个 router 必须放在 proxy_catch_all 前面。
# 否则 /api/apps/v1/... 会被旧的 catch-all 当成普通 app path 吃掉。
#
# /api/gateway/v1/...:
#   Gateway 自身只读管理 API。
#
# /api/apps/v1/{app_id}/{path...}:
#   capability-based 受控 API 穿透。
#   第一阶段只允许 admin session。
#
app.include_router(
    build_lease_router(
        get_coordinator=get_lease_coordinator,
        get_security_service=get_security_service,
    )
)

app.include_router(
    build_registry_router(
        get_registry=get_app_registry,
        auth_config=BOOT_AUTH_CONFIG,
    )
)

app.include_router(
    build_notification_router(
        get_notifications=get_notifications,
        auth_config=BOOT_AUTH_CONFIG,
    )
)

app.include_router(
    build_qbt_lease_router(
        get_manager=get_manager,
        get_http_client=get_http_client,
        get_security_service=get_security_service,
    )
)

app.include_router(
    build_operations_router(
        get_operations=get_operations,
        get_recovery=get_recovery,
        auth_config=BOOT_AUTH_CONFIG,
        rate_limiter=RATE_LIMITER,
        render_page=render_gateway_page,
    )
)

app.include_router(
    build_action_approval_router(
        get_security_service=get_security_service,
    )
)

app.include_router(
    build_token_auth_router(
        get_security_service=get_security_service,
        rate_limiter=RATE_LIMITER,
        auth_config=BOOT_AUTH_CONFIG,
    )
)

app.include_router(
    build_grant_auth_router(
        get_security_service=get_security_service,
        rate_limiter=RATE_LIMITER,
        auth_config=BOOT_AUTH_CONFIG,
    )
)

app.include_router(
    build_device_auth_router(
        get_security_service=get_security_service,
        rate_limiter=RATE_LIMITER,
        auth_config=BOOT_AUTH_CONFIG,
    )
)

app.include_router(
    build_admin_security_router(
        get_security_service=get_security_service,
        auth_config=BOOT_AUTH_CONFIG,
        render_page=render_gateway_page,
    )
)

app.include_router(
    build_gateway_v1_router(
        get_manager=get_manager,
    )
)

app.include_router(
    build_api_apps_v1_router(
        get_manager=get_manager,
        get_http_client=get_http_client,
        get_security_service=get_security_service,
        auth_config=BOOT_AUTH_CONFIG,
    )
)


@app.websocket("/{full_path:path}")
async def websocket_proxy(websocket: WebSocket, full_path: str) -> None:
    manager = get_manager()
    path = "/" + full_path
    if not proxy_path_is_canonical(path, websocket.scope.get("raw_path", b"")):
        await websocket.close(code=1008, reason="non-canonical path")
        return
    if path.startswith(("/api/", "/dashboard", "/login", "/logout", "/assets/")):
        await websocket.close(code=1008, reason="route is not a WebSocket app endpoint")
        return
    identity = security_identity(websocket, BOOT_AUTH_CONFIG.session_max_age_seconds)
    if not identity["authenticated"]:
        await websocket.close(code=1008, reason="login required")
        return
    origin = str(websocket.headers.get("origin", "")).rstrip("/")
    if not origin or origin not in set(BOOT_AUTH_CONFIG.trusted_origins):
        await websocket.close(code=1008, reason="origin validation failed")
        return
    if manager.phase != "ready" and manager.gateway_config.recovery_block_requests:
        await websocket.close(code=1013, reason="Gateway is recovering")
        return
    app_state = manager.resolve_by_path(path)
    if app_state is None or not app_state.enabled:
        await websocket.close(code=1008, reason="app is unavailable")
        return
    role = str(identity["role"])
    config = app_state.config
    if role not in config.dashboard.allow_proxy_roles:
        await websocket.close(code=1008, reason="role is not allowed")
        return
    sub_path = path[len(config.mount_path):] or "/"
    ws_config = config.proxy.websocket
    if not ws_config.enabled or not any(
        prefix == "/" or sub_path == prefix or sub_path.startswith(prefix + "/")
        for prefix in ws_config.path_prefixes
    ):
        await websocket.close(code=1008, reason="WebSocket path is not declared")
        return
    if app_state.state != "running" or app_state.runtime is None:
        if role != "admin":
            await websocket.close(code=1008, reason="app is stopped")
            return
        try:
            record = await manager.ensure_started(config.app_id)
        except Exception:
            await websocket.close(code=1011, reason="app failed to start")
            return
    else:
        record = app_state.runtime

    scheme = "wss" if record.internal_url.startswith("https://") else "ws"
    origin_suffix = record.internal_url.split("://", 1)[1]
    target = f"{scheme}://{origin_suffix}{sub_path}"
    if websocket.url.query:
        target += f"?{websocket.url.query}"
    forwarded = build_websocket_upstream_headers(websocket, config.mount_path)
    protocols = [
        value.strip()
        for value in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if value.strip()
    ]
    try:
        async with websocket_connect(
            target,
            additional_headers=forwarded,
            origin=origin,
            subprotocols=protocols or None,
            max_size=ws_config.max_message_bytes,
            open_timeout=float(config.proxy.connect_timeout_seconds),
            ping_interval=20,
            ping_timeout=20,
        ) as upstream:
            await websocket.accept(subprotocol=upstream.subprotocol)
            manager.stream_started(config.app_id)
            manager.touch_request(config.app_id, "WEBSOCKET", sub_path)
            last_activity = [time.monotonic()]

            async def browser_to_upstream() -> None:
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    payload = message.get("bytes")
                    if payload is None:
                        payload = message.get("text", "")
                    payload_size = (
                        len(payload)
                        if isinstance(payload, bytes)
                        else len(payload.encode("utf-8"))
                    )
                    if payload_size > ws_config.max_message_bytes:
                        raise ValueError("WebSocket message exceeds manifest limit")
                    await upstream.send(payload)
                    last_activity[0] = time.monotonic()
                    manager.stream_touched(config.app_id)

            async def upstream_to_browser() -> None:
                async for payload in upstream:
                    if isinstance(payload, bytes):
                        await websocket.send_bytes(payload)
                    else:
                        await websocket.send_text(payload)
                    last_activity[0] = time.monotonic()
                    manager.stream_touched(config.app_id)

            async def idle_watchdog() -> None:
                while True:
                    await asyncio.sleep(min(30, ws_config.idle_timeout_seconds))
                    if time.monotonic() - last_activity[0] >= ws_config.idle_timeout_seconds:
                        raise asyncio.TimeoutError("WebSocket idle timeout")

            tasks = {
                asyncio.create_task(browser_to_upstream()),
                asyncio.create_task(upstream_to_browser()),
                asyncio.create_task(idle_watchdog()),
            }
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
    except asyncio.CancelledError:
        raise
    except ConnectionClosed:
        pass
    except Exception as exc:
        manager.mark_proxy_error(config.app_id, sub_path, f"WebSocket: {exc}")
        manager.events.write(
            "proxy_websocket_error", app_id=config.app_id, path=sub_path, reason=str(exc)[:1000]
        )
        try:
            await websocket.close(code=1011, reason="upstream WebSocket closed")
        except RuntimeError:
            pass
    finally:
        manager.stream_finished(config.app_id)


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
async def proxy_catch_all(request: Request, full_path: str):
    manager = get_manager()
    path = "/" + full_path

    if not proxy_path_is_canonical(path, request.scope.get("raw_path", b"")):
        raise HTTPException(status_code=400, detail="Non-canonical proxy path")

    if (
        path.startswith("/api/")
        or path.startswith("/dashboard")
        or path == "/health"
        or path == "/healthz"
        or path == "/readyz"
        or path == "/docs"
        or path == "/redoc"
        or path == "/openapi.json"
        or path.startswith("/login")
        or path.startswith("/logout")
    ):
        raise HTTPException(status_code=404, detail="Not found")

    if not is_authenticated(request):
        return require_login_redirect(request)

    if manager.phase != "ready" and manager.gateway_config.recovery_block_requests:
        manager.events.write("gateway_recovery_blocked_request", path=path)
        raise HTTPException(status_code=503, detail="Gateway is recovering")

    app_state = manager.resolve_by_path(path)
    if app_state is None:
        raise HTTPException(status_code=404, detail="No app matches this path")

    role = current_identity(request)["role"]
    if role not in app_state.config.dashboard.allow_proxy_roles:
        return render_guest_block_page(
            request=request,
            title="当前角色无权代理此应用",
            message="该应用的 dashboard.allow_proxy_roles 未授权当前角色。",
            app_path=path,
        )
    verify_same_origin(request, BOOT_AUTH_CONFIG.trusted_origins)

    sub_path = path[len(app_state.config.mount_path):] or "/"
    app_is_running = app_state.state == "running" and app_state.runtime is not None

    if not app_is_running:
        if not can_control(request):
            message = pick_guest_prompt()
            return render_guest_block_page(
                request=request,
                title="guest 模式下不会自动唤醒应用",
                message=message,
                app_path=path,
            )
        try:
            record = await manager.ensure_started(app_state.config.app_id)
        except Exception as exc:
            manager.events.write(
                "proxy_start_failed",
                app_id=app_state.config.app_id,
                path=path,
                reason=str(exc),
            )
            return render_upstream_error_page(
                request=request,
                title="应用启动失败",
                app_id=app_state.config.app_id,
                app_path=path,
                upstream_url="(not started)",
                message=str(exc),
            )
    else:
        record = app_state.runtime

    manager.touch_request(app_state.config.app_id, request.method, sub_path)
    manager.touch_user_activity(app_state.config.app_id, sub_path)

    target_url = f"{record.internal_url}{sub_path}"
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    try:
        body = await spool_request_body(
            request,
            max_bytes=app_state.config.proxy.max_request_body_bytes,
            memory_bytes=app_state.config.proxy.memory_spool_bytes,
        )
    except RequestBodyTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    upstream_headers = build_upstream_headers(request, app_state.config.mount_path)

    req = runtime.http_client.build_request(
        request.method,
        target_url,
        headers=upstream_headers,
        content=body.chunks(),
    )

    proxy_config = app_state.config.proxy
    read_timeout: float | None = float(proxy_config.request_timeout_seconds)
    if manager.path_is_streaming(app_state.config.app_id, sub_path):
        read_timeout = (
            None
            if proxy_config.streaming_read_timeout_seconds == 0
            else float(proxy_config.streaming_read_timeout_seconds)
        )
    req.extensions["timeout"] = {
        "connect": float(proxy_config.connect_timeout_seconds),
        "read": read_timeout,
        "write": float(proxy_config.request_timeout_seconds),
        "pool": float(proxy_config.connect_timeout_seconds),
    }

    try:
        upstream_response = await runtime.http_client.send(req, stream=True)
    except httpx.RequestError as exc:
        body.close()
        manager.mark_proxy_error(app_state.config.app_id, sub_path, str(exc))
        manager.events.write(
            "proxy_error",
            app_id=app_state.config.app_id,
            path=sub_path,
            method=request.method,
            reason=str(exc),
            target_url=target_url,
        )
        return render_upstream_error_page(
            request=request,
            title="上游应用当前不可达",
            app_id=app_state.config.app_id,
            app_path=path,
            upstream_url=target_url,
            message=str(exc),
        )

    manager.mark_upstream_status(app_state.config.app_id, upstream_response.status_code)

    if upstream_response.status_code >= 500:
        manager.mark_proxy_error(
            app_state.config.app_id,
            sub_path,
            f"upstream returned {upstream_response.status_code}",
        )
        manager.events.write(
            "proxy_upstream_server_error",
            app_id=app_state.config.app_id,
            path=sub_path,
            method=request.method,
            status_code=upstream_response.status_code,
            target_url=target_url,
        )
    else:
        manager.clear_proxy_error(app_state.config.app_id)

    is_streaming = manager.path_is_streaming(app_state.config.app_id, sub_path)
    filtered_headers = filter_response_headers(upstream_response.headers.multi_items())

    if is_streaming:
        manager.stream_started(app_state.config.app_id)

    async def iterator():
        try:
            async for chunk in upstream_response.aiter_raw():
                if is_streaming:
                    manager.stream_touched(app_state.config.app_id)
                yield chunk
        except httpx.RequestError as exc:
            manager.mark_proxy_error(app_state.config.app_id, sub_path, f"stream interrupted: {exc}")
            manager.events.write(
                "proxy_stream_error",
                app_id=app_state.config.app_id,
                path=sub_path,
                method=request.method,
                reason=str(exc),
                target_url=target_url,
            )
            raise
        finally:
            await upstream_response.aclose()
            body.close()
            if is_streaming:
                manager.stream_finished(app_state.config.app_id)

    return build_streaming_response(
        status_code=upstream_response.status_code,
        iterator=iterator(),
        headers=filtered_headers,
    )
