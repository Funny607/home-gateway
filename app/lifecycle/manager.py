from __future__ import annotations

import asyncio
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional
from zoneinfo import ZoneInfo

import httpx

from app.config.schema import AppConfig, GatewayConfig
from app.events import EventRecorder
from app.lifecycle.healthcheck import check_once, wait_until_healthy
from app.runtime.store import RuntimeRecord, RuntimeStore
from app.utils.ports import find_free_port
from app.utils.processes import (
    force_kill_process_group,
    pid_exists,
    process_identity,
    process_matches_identity,
    terminate_process_group,
)
from app.security.auth import resolve_reference


def _matches_prefix(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


@dataclass
class AppState:
    config: AppConfig
    enabled: bool = True
    state: str = "stopped"
    runtime: Optional[RuntimeRecord] = None
    last_error: str = ""
    process: Optional[subprocess.Popen] = None
    consecutive_failures: int = 0
    last_failure_time: float = 0.0
    last_failure_stage: str = ""
    last_failure_reason: str = ""
    health_failure_streak: int = 0
    restart_attempts: int = 0
    restart_history: list[float] = field(default_factory=list)
    healthy_since: float = 0.0
    next_restart_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class LifecycleManager:
    def __init__(
        self,
        gateway_config: GatewayConfig,
        apps: Dict[str, AppConfig],
        runtime_store: RuntimeStore,
        http_client: httpx.AsyncClient,
        logger,
        events: EventRecorder,
    ) -> None:
        self.gateway_config = gateway_config
        self.runtime_store = runtime_store
        self.http_client = http_client
        self.logger = logger
        self.events = events
        self.phase = "booting"
        self.apps: Dict[str, AppState] = {
            app_id: AppState(config=app_config)
            for app_id, app_config in apps.items()
        }

    def set_phase(self, phase: str) -> None:
        self.phase = phase
        self.events.write("gateway_phase_changed", phase=phase)

    def resolve_by_path(self, path: str) -> Optional[AppState]:
        matched: Optional[AppState] = None
        for app_state in self.apps.values():
            mount = app_state.config.mount_path
            if path == mount or path.startswith(mount + "/"):
                if matched is None or len(mount) > len(matched.config.mount_path):
                    matched = app_state
        return matched

    def snapshot(self) -> list[dict]:
        result = []
        for app_state in self.apps.values():
            record = app_state.runtime
            result.append(
                {
                    "app_id": app_state.config.app_id,
                    "display_name": app_state.config.display_name,
                    "icon": app_state.config.icon or self.gateway_config.default_icon,
                    "mount_path": app_state.config.mount_path,
                    "enabled": app_state.enabled,
                    "start_policy": app_state.config.lifecycle.start_policy,
                    "dependencies": list(app_state.config.lifecycle.dependencies),
                    "state": app_state.state,
                    "last_error": app_state.last_error,
                    "internal_url": record.internal_url if record and record.internal_url else None,
                    "pid": record.pid if record and record.pid > 0 else None,
                    "started_at": record.start_time if record and record.start_time > 0 else None,
                    "last_user_activity_time": record.last_user_activity_time if record and record.last_user_activity_time > 0 else None,
                    "last_stream_activity_time": record.last_stream_activity_time if record and record.last_stream_activity_time > 0 else None,
                    "active_stream_count": record.active_stream_count if record else 0,
                    "consecutive_failures": app_state.consecutive_failures,
                    "last_failure_time": app_state.last_failure_time,
                    "last_failure_stage": app_state.last_failure_stage,
                    "last_failure_reason": app_state.last_failure_reason,
                    "health_failure_streak": app_state.health_failure_streak,
                    "restart_attempts": app_state.restart_attempts,
                    "restart_budget_remaining": max(
                        0, self._restart_limit(app_state) - len(self._recent_restarts(app_state))
                    ),
                    "next_restart_at": app_state.next_restart_at,
                    "last_health_check_time": record.last_health_check_time if record else 0.0,
                    "last_health_check_ok": record.last_health_check_ok if record else True,
                    "request_count": record.request_count if record else 0,
                    "last_request_time": record.last_request_time if record and record.last_request_time > 0 else None,
                    "last_request_path": record.last_request_path if record else "",
                    "last_request_method": record.last_request_method if record else "",
                    "last_proxy_error_time": record.last_proxy_error_time if record and record.last_proxy_error_time > 0 else None,
                    "last_proxy_error_message": record.last_proxy_error_message if record else "",
                    "last_proxy_error_path": record.last_proxy_error_path if record else "",
                    "last_upstream_status": record.last_upstream_status if record else 0,
                }
            )
        return sorted(result, key=lambda item: item["app_id"])

    def get_app(self, app_id: str) -> AppState:
        if app_id not in self.apps:
            raise KeyError(f"unknown app_id: {app_id}")
        return self.apps[app_id]

    def register_app(self, config: AppConfig, *, enabled: bool = True) -> None:
        if config.app_id in self.apps:
            raise ValueError(f"app already registered: {config.app_id}")
        self.apps[config.app_id] = AppState(config=config, enabled=enabled)

    def update_app(self, config: AppConfig) -> None:
        state = self.get_app(config.app_id)
        if state.state not in {"stopped", "failed"} or state.runtime is not None:
            raise RuntimeError("an app must be fully stopped before its manifest is updated")
        state.config = config

    def set_enabled(self, app_id: str, enabled: bool) -> None:
        self.get_app(app_id).enabled = bool(enabled)

    def _restart_limit(self, app_state: AppState) -> int:
        return app_state.config.lifecycle.restart_max_attempts or self.gateway_config.restart_max_attempts

    def _restart_window(self, app_state: AppState) -> int:
        return app_state.config.lifecycle.restart_window_seconds or self.gateway_config.restart_window_seconds

    def _recent_restarts(self, app_state: AppState, now: float | None = None) -> list[float]:
        current = time.time() if now is None else now
        cutoff = current - self._restart_window(app_state)
        app_state.restart_history = [value for value in app_state.restart_history if value >= cutoff]
        app_state.restart_attempts = len(app_state.restart_history)
        return app_state.restart_history

    def _auto_restart_enabled(self, app_state: AppState) -> bool:
        value = app_state.config.lifecycle.auto_restart
        return self.gateway_config.auto_restart_failed_apps if value is None else value

    def _unhealthy_threshold(self, app_state: AppState) -> int:
        return app_state.config.lifecycle.unhealthy_threshold or self.gateway_config.unhealthy_threshold

    def _restart_backoff(self, app_state: AppState, attempt: int) -> int:
        initial = (
            app_state.config.lifecycle.restart_backoff_initial_seconds
            or self.gateway_config.restart_backoff_seconds
        )
        maximum = min(
            app_state.config.lifecycle.restart_backoff_max_seconds,
            self.gateway_config.restart_backoff_max_seconds,
        )
        return min(initial * (2 ** max(0, attempt - 1)), maximum)

    def in_maintenance_window(self, app_state: AppState, now: datetime | None = None) -> bool:
        day_names = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
        for window in app_state.config.lifecycle.maintenance_windows:
            local = now.astimezone(ZoneInfo(window.timezone)) if now else datetime.now(ZoneInfo(window.timezone))
            clock = local.strftime("%H:%M")
            today = day_names[local.weekday()]
            if window.start < window.end:
                if today in window.days and window.start <= clock < window.end:
                    return True
            else:
                previous = day_names[(local - timedelta(days=1)).weekday()]
                if (today in window.days and clock >= window.start) or (
                    previous in window.days and clock < window.end
                ):
                    return True
        return False

    def _new_runtime_record(
        self,
        app_state: AppState,
        *,
        state: str,
        pid: int,
        pgid: int,
        internal_host: str,
        internal_port: int,
        internal_url: str,
        health_url: str,
        start_time: float,
        command_snapshot: str,
    ) -> RuntimeRecord:
        return RuntimeRecord(
            app_id=app_state.config.app_id,
            state=state,
            pid=pid,
            pgid=pgid,
            internal_host=internal_host,
            internal_port=internal_port,
            internal_url=internal_url,
            health_url=health_url,
            start_time=start_time,
            last_user_activity_time=start_time,
            last_stream_activity_time=0.0,
            active_stream_count=0,
            last_error=app_state.last_error,
            command_snapshot=command_snapshot,
            process_identity=process_identity(pid),
            healthy_since=0.0,
            restart_history=list(app_state.restart_history),
            consecutive_failures=app_state.consecutive_failures,
            last_failure_time=app_state.last_failure_time,
            last_failure_stage=app_state.last_failure_stage,
            last_failure_reason=app_state.last_failure_reason,
            last_health_check_time=0.0,
            last_health_check_ok=True,
            request_count=0,
            last_request_time=0.0,
            last_request_path="",
            last_request_method="",
            last_proxy_error_time=0.0,
            last_proxy_error_message="",
            last_proxy_error_path="",
            last_upstream_status=0,
        )

    def _sync_failure_meta_from_runtime(self, app_state: AppState, record: Optional[RuntimeRecord]) -> None:
        if record is None:
            return
        app_state.consecutive_failures = record.consecutive_failures
        app_state.last_failure_time = record.last_failure_time
        app_state.last_failure_stage = record.last_failure_stage
        app_state.last_failure_reason = record.last_failure_reason
        app_state.restart_history = list(record.restart_history)
        app_state.restart_attempts = len(self._recent_restarts(app_state))
        app_state.healthy_since = record.healthy_since
        if record.last_error:
            app_state.last_error = record.last_error

    def _mark_success(
        self,
        app_state: AppState,
        record: RuntimeRecord,
        *,
        reset_restart_budget: bool = False,
    ) -> RuntimeRecord:
        app_state.state = "running"
        app_state.last_error = ""
        app_state.last_failure_stage = ""
        app_state.last_failure_reason = ""
        app_state.last_failure_time = 0.0
        app_state.consecutive_failures = 0
        app_state.health_failure_streak = 0
        if reset_restart_budget:
            app_state.restart_history = []
        app_state.restart_attempts = len(app_state.restart_history)
        app_state.healthy_since = time.time()
        app_state.next_restart_at = 0.0

        record.state = "running"
        record.last_error = ""
        record.consecutive_failures = 0
        record.last_failure_time = 0.0
        record.last_failure_stage = ""
        record.last_failure_reason = ""
        record.healthy_since = app_state.healthy_since
        record.restart_history = list(app_state.restart_history)
        return record

    def _mark_failed(
        self,
        app_state: AppState,
        *,
        stage: str,
        reason: str,
        record: Optional[RuntimeRecord] = None,
        persist: bool = True,
    ) -> None:
        now = time.time()
        app_state.state = "failed"
        app_state.last_error = reason
        app_state.last_failure_stage = stage
        app_state.last_failure_reason = reason
        app_state.last_failure_time = now
        app_state.consecutive_failures += 1

        if record is None:
            record = RuntimeRecord(
                app_id=app_state.config.app_id,
                state="failed",
                pid=0,
                pgid=0,
                internal_host=app_state.config.listen_host,
                internal_port=0,
                internal_url="",
                health_url="",
                start_time=0.0,
                last_user_activity_time=0.0,
                last_stream_activity_time=0.0,
                active_stream_count=0,
                last_error=reason,
                command_snapshot="",
                consecutive_failures=app_state.consecutive_failures,
                last_failure_time=now,
                last_failure_stage=stage,
                last_failure_reason=reason,
                last_health_check_time=now,
                last_health_check_ok=False,
                request_count=0,
                last_request_time=0.0,
                last_request_path="",
                last_request_method="",
                last_proxy_error_time=0.0,
                last_proxy_error_message="",
                last_proxy_error_path="",
                last_upstream_status=0,
            )
        else:
            record.state = "failed"
            record.last_error = reason
            record.last_failure_time = now
            record.last_failure_stage = stage
            record.last_failure_reason = reason
            record.consecutive_failures = app_state.consecutive_failures
            record.last_health_check_time = now
            record.last_health_check_ok = False

        app_state.runtime = record
        record.restart_history = list(app_state.restart_history)
        self.events.write(
            "app_marked_failed",
            app_id=app_state.config.app_id,
            stage=stage,
            reason=reason,
            consecutive_failures=app_state.consecutive_failures,
        )

        if persist:
            self.runtime_store.save(record)

    async def ensure_started(self, app_id: str) -> RuntimeRecord:
        app_state = self.get_app(app_id)
        if not app_state.enabled:
            raise RuntimeError(f"app '{app_id}' is disabled")
        for dependency in app_state.config.lifecycle.dependencies:
            dependency_state = self.get_app(dependency)
            if not dependency_state.enabled:
                raise RuntimeError(f"dependency '{dependency}' is disabled")
            await self.ensure_started(dependency)
        async with app_state.lock:
            if app_state.state == "running" and app_state.runtime is not None:
                healthy, reason = await check_once(self.http_client, app_state.runtime.health_url)
                app_state.runtime.last_health_check_time = time.time()
                app_state.runtime.last_health_check_ok = healthy
                self.runtime_store.save(app_state.runtime)

                if healthy:
                    app_state.health_failure_streak = 0
                    return app_state.runtime
                self.events.write(
                    "app_replacing_unhealthy_process",
                    app_id=app_id,
                    reason=reason,
                )
                await self._terminate_runtime_process(app_state, app_state.runtime)
                self.runtime_store.delete(app_id)
                app_state.runtime = None
                app_state.state = "stopped"

            if app_state.state == "stopping":
                raise RuntimeError(f"app '{app_id}' is stopping")

            if app_state.runtime is not None and app_state.runtime.state == "failed":
                await self._terminate_runtime_process(app_state, app_state.runtime)
                self.runtime_store.delete(app_id)
                app_state.runtime = None

            app_state.state = "starting"
            app_state.last_error = ""
            self.events.write("app_start_requested", app_id=app_id)
            self.logger.info("Starting app %s", app_id)

            try:
                runtime = await self._start_under_lock(app_state)
            except Exception as exc:
                if app_state.state != "failed":
                    self._mark_failed(
                        app_state,
                        stage="start",
                        reason=f"start failed: {exc}",
                        persist=True,
                    )
                raise
            runtime = self._mark_success(app_state, runtime, reset_restart_budget=True)
            app_state.runtime = runtime
            self.runtime_store.save(runtime)

            self.events.write(
                "app_started",
                app_id=app_id,
                pid=runtime.pid,
                port=runtime.internal_port,
                internal_url=runtime.internal_url,
            )
            self.logger.info("App %s started at %s", app_id, runtime.internal_url)
            return runtime

    async def retry(self, app_id: str) -> RuntimeRecord:
        app_state = self.get_app(app_id)
        had_failure = app_state.state == "failed" or bool(app_state.last_error)
        async with app_state.lock:
            if app_state.state == "running" and app_state.runtime is not None:
                return app_state.runtime

            if app_state.runtime is not None and app_state.runtime.state == "failed":
                await self._terminate_runtime_process(app_state, app_state.runtime)
                self.runtime_store.delete(app_id)
                app_state.runtime = None

            app_state.state = "stopped"

        runtime = await self.ensure_started(app_id)
        if had_failure:
            self.events.write("app_recovered", app_id=app_id, reason="manual retry succeeded")
        return runtime

    async def _start_under_lock(self, app_state: AppState) -> RuntimeRecord:
        config = app_state.config
        host = config.listen_host
        port = find_free_port(host)

        command_args, command_snapshot = config.build_command(
            host=host,
            port=str(port),
            app_id=config.app_id,
            mount_path=config.mount_path,
        )

        workdir_path = Path(config.workdir).expanduser().resolve()
        if not workdir_path.is_dir():
            raise RuntimeError(f"app workdir does not exist: {workdir_path}")
        workdir = str(workdir_path)
        app_log_dir = self.gateway_config.log_path / "apps"
        app_log_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = app_log_dir / f"{config.app_id}.stdout.log"
        stderr_path = app_log_dir / f"{config.app_id}.stderr.log"
        self._rotate_log(stdout_path)
        self._rotate_log(stderr_path)

        env = os.environ.copy()
        env.update(config.env)
        for env_name, reference in config.secret_env.items():
            env[env_name] = resolve_reference(reference)
        env["GATEWAY_APP_ID"] = config.app_id
        env["GATEWAY_MOUNT_PATH"] = config.mount_path
        env["GATEWAY_LISTEN_HOST"] = host
        env["GATEWAY_LISTEN_PORT"] = str(port)
        env["WEBUI_APP_ID"] = config.app_id
        env["WEBUI_MOUNT_PATH"] = config.mount_path
        env["WEBUI_HOST"] = host
        env["WEBUI_PORT"] = str(port)
        env["WEBUI_INTERNAL_URL"] = f"http://{host}:{port}"

        stdout_handle = open(stdout_path, "a", encoding="utf-8")
        stderr_handle = open(stderr_path, "a", encoding="utf-8")

        try:
            process = subprocess.Popen(
                command_args,
                cwd=workdir,
                env=env,
                stdout=stdout_handle,
                stderr=stderr_handle,
                start_new_session=True,
            )
        finally:
            stdout_handle.close()
            stderr_handle.close()
        app_state.process = process

        internal_url = f"http://{host}:{port}"
        health_url = f"{internal_url}{config.health_path}"
        now = time.time()

        runtime = self._new_runtime_record(
            app_state,
            state="starting",
            pid=process.pid,
            pgid=process.pid,
            internal_host=host,
            internal_port=port,
            internal_url=internal_url,
            health_url=health_url,
            start_time=now,
            command_snapshot=command_snapshot,
        )

        startup_timeout = config.startup_timeout_seconds or self.gateway_config.default_startup_timeout_seconds
        ok, last_error = await wait_until_healthy(
            client=self.http_client,
            url=health_url,
            timeout_seconds=startup_timeout,
            interval_seconds=self.gateway_config.health_poll_interval_seconds,
        )

        runtime.last_health_check_time = time.time()
        runtime.last_health_check_ok = ok

        if not ok:
            self.logger.error("Startup failed for %s: %s", config.app_id, last_error)
            self.events.write("app_start_failed", app_id=config.app_id, reason=last_error)

            try:
                terminate_process_group(process.pid)
                await asyncio.sleep(1)
            except Exception:
                pass

            try:
                if process.poll() is None:
                    force_kill_process_group(process.pid)
            except Exception:
                pass

            app_state.process = None
            self._mark_failed(
                app_state,
                stage="startup",
                reason=f"startup failed: {last_error}",
                record=runtime,
                persist=True,
            )
            raise RuntimeError(app_state.last_error)

        return runtime

    def _rotate_log(self, path: Path) -> None:
        if not path.exists() or path.stat().st_size < self.gateway_config.max_log_bytes:
            return
        count = self.gateway_config.log_backup_count
        if count <= 0:
            path.write_text("", encoding="utf-8")
            return
        oldest = path.with_name(f"{path.name}.{count}")
        if oldest.exists():
            oldest.unlink()
        for index in range(count - 1, 0, -1):
            source = path.with_name(f"{path.name}.{index}")
            if source.exists():
                source.replace(path.with_name(f"{path.name}.{index + 1}"))
        path.replace(path.with_name(f"{path.name}.1"))

    async def _terminate_runtime_process(self, app_state: AppState, record: RuntimeRecord) -> None:
        if record.pid <= 0 or not pid_exists(record.pid):
            app_state.process = None
            return
        known_child = app_state.process is not None and app_state.process.pid == record.pid
        if not known_child and not process_matches_identity(record.pid, record.process_identity):
            self.events.write(
                "runtime_identity_mismatch",
                app_id=app_state.config.app_id,
                pid=record.pid,
                reason="stale runtime record was not signalled",
            )
            app_state.process = None
            return
        try:
            terminate_process_group(record.pgid or record.pid)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.time() + min(5, app_state.config.graceful_shutdown_seconds)
        while pid_exists(record.pid) and time.time() < deadline:
            await asyncio.sleep(0.2)
        if pid_exists(record.pid):
            try:
                force_kill_process_group(record.pgid or record.pid)
            except (ProcessLookupError, PermissionError):
                pass
        app_state.process = None

    async def stop(self, app_id: str, reason: str = "manual stop") -> None:
        app_state = self.get_app(app_id)
        running_dependents = [
            state.config.app_id
            for state in self.apps.values()
            if app_id in state.config.lifecycle.dependencies and state.state in {"starting", "running"}
        ]
        if running_dependents:
            raise RuntimeError(
                f"cannot stop '{app_id}' while dependents are running: {', '.join(running_dependents)}"
            )
        async with app_state.lock:
            await self._stop_under_lock(app_state, reason=reason)

    async def _stop_under_lock(self, app_state: AppState, reason: str) -> None:
        app_id = app_state.config.app_id

        if app_state.state == "stopped":
            self.runtime_store.delete(app_id)
            app_state.runtime = None
            app_state.process = None
            app_state.last_error = ""
            return

        record = app_state.runtime or self.runtime_store.load(app_id)
        if record is None:
            app_state.state = "stopped"
            app_state.runtime = None
            app_state.process = None
            app_state.last_error = ""
            self.runtime_store.delete(app_id)
            return

        app_state.state = "stopping"
        self.events.write("app_stop_requested", app_id=app_id, reason=reason)
        self.logger.info("Stopping app %s, reason=%s", app_id, reason)

        process = app_state.process
        graceful_timeout = app_state.config.graceful_shutdown_seconds

        already_gone = False
        if process is not None:
            if process.poll() is not None:
                already_gone = True
        else:
            if record.pid <= 0 or not pid_exists(record.pid):
                already_gone = True
            elif not process_matches_identity(record.pid, record.process_identity):
                already_gone = True
                self.events.write(
                    "runtime_identity_mismatch",
                    app_id=app_id,
                    pid=record.pid,
                    reason="stale runtime record was not signalled during stop",
                )

        if already_gone:
            self.logger.info("App %s already stopped before signal handling", app_id)
            app_state.state = "stopped"
            app_state.runtime = None
            app_state.process = None
            app_state.last_error = ""
            self.runtime_store.delete(app_id)
            self.events.write("app_stopped", app_id=app_id, reason=f"{reason} (already stopped)")
            return

        try:
            terminate_process_group(record.pgid)
        except ProcessLookupError:
            already_gone = True
        except PermissionError as exc:
            self.logger.warning("SIGTERM permission issue for %s: %s", app_id, exc)

        if not already_gone:
            if process is not None:
                try:
                    await asyncio.to_thread(process.wait, graceful_timeout)
                except subprocess.TimeoutExpired:
                    pass
                except Exception as exc:
                    self.logger.warning("process.wait failed for %s: %s", app_id, exc)
            else:
                started = time.time()
                while time.time() - started < graceful_timeout:
                    if not pid_exists(record.pid):
                        already_gone = True
                        break
                    await asyncio.sleep(0.5)

        stopped_after_term = False
        if process is not None:
            stopped_after_term = process.poll() is not None
        else:
            stopped_after_term = (not pid_exists(record.pid)) or already_gone

        if not stopped_after_term:
            self.events.write("app_force_kill", app_id=app_id)
            try:
                force_kill_process_group(record.pgid)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                self.logger.warning("SIGKILL permission issue for %s: %s", app_id, exc)
            except Exception as exc:
                self.logger.warning("SIGKILL unexpected error for %s: %s", app_id, exc)

            if process is not None:
                try:
                    await asyncio.to_thread(process.wait, 2)
                except subprocess.TimeoutExpired:
                    pass
                except Exception as exc:
                    self.logger.warning("post-SIGKILL wait failed for %s: %s", app_id, exc)
            else:
                await asyncio.sleep(0.5)

        finally_stopped = False
        if process is not None:
            finally_stopped = process.poll() is not None
        else:
            finally_stopped = not pid_exists(record.pid)

        if finally_stopped:
            app_state.state = "stopped"
            app_state.last_error = ""
            app_state.runtime = None
            app_state.process = None
            self.runtime_store.delete(app_id)
            self.events.write("app_stopped", app_id=app_id, reason=reason)
            return

        app_state.process = None
        self._mark_failed(
            app_state,
            stage="stop",
            reason="stop failed: process still exists after termination attempts",
            record=record,
            persist=True,
        )

    async def monitor_apps_once(self) -> None:
        for app_id, app_state in self.apps.items():
            now = time.time()
            self._recent_restarts(app_state, now)
            if (
                app_state.state == "failed"
                and app_state.enabled
                and self._auto_restart_enabled(app_state)
                and not self.in_maintenance_window(app_state)
            ):
                if (
                    len(app_state.restart_history) < self._restart_limit(app_state)
                    and now >= app_state.next_restart_at
                ):
                    async with app_state.lock:
                        if app_state.state != "failed":
                            continue
                        app_state.restart_history.append(time.time())
                        app_state.restart_attempts = len(app_state.restart_history)
                        attempt = app_state.restart_attempts
                        if app_state.runtime is not None:
                            await self._terminate_runtime_process(app_state, app_state.runtime)
                        self.runtime_store.delete(app_id)
                        app_state.runtime = None
                        app_state.state = "starting"
                        app_state.restart_attempts = attempt
                        self.events.write("app_auto_restart_attempt", app_id=app_id, attempt=attempt)
                        try:
                            runtime = await self._start_under_lock(app_state)
                            runtime = self._mark_success(app_state, runtime)
                            app_state.runtime = runtime
                            self.runtime_store.save(runtime)
                            self.events.write("app_auto_restarted", app_id=app_id, attempt=attempt)
                        except Exception as exc:
                            if app_state.state != "failed":
                                self._mark_failed(
                                    app_state,
                                    stage="auto_restart",
                                    reason=f"auto restart failed: {exc}",
                                    persist=True,
                                )
                            app_state.restart_attempts = len(app_state.restart_history)
                            app_state.next_restart_at = time.time() + self._restart_backoff(
                                app_state, attempt
                            )
                            if app_state.runtime is not None:
                                app_state.runtime.restart_history = list(app_state.restart_history)
                                self.runtime_store.save(app_state.runtime)
                            self.logger.warning(
                                "Auto restart %s/%s failed for %s: %s",
                                attempt,
                                self._restart_limit(app_state),
                                app_id,
                                exc,
                            )
                continue

            if app_state.state != "running" or app_state.runtime is None:
                continue

            async with app_state.lock:
                if app_state.state != "running" or app_state.runtime is None:
                    continue

                record = app_state.runtime

                known_child = (
                    app_state.process is not None
                    and app_state.process.pid == record.pid
                    and app_state.process.poll() is None
                )
                if (
                    record.pid <= 0
                    or not pid_exists(record.pid)
                    or (not known_child and not process_matches_identity(record.pid, record.process_identity))
                ):
                    self.logger.warning("Running app %s disappeared", app_id)
                    self.events.write(
                        "app_runtime_lost",
                        app_id=app_id,
                        stage="process_missing",
                        reason="running process missing during monitor",
                    )
                    self._mark_failed(
                        app_state,
                        stage="process_missing",
                        reason="running process missing during monitor",
                        record=record,
                        persist=True,
                    )
                    app_state.next_restart_at = time.time() + self._restart_backoff(app_state, 1)
                    continue

                healthy, reason = await check_once(self.http_client, record.health_url)
                record.last_health_check_time = time.time()
                record.last_health_check_ok = healthy

                if not healthy:
                    app_state.health_failure_streak += 1
                    if app_state.health_failure_streak == 1:
                        self.logger.warning("Running app %s health check failed: %s", app_id, reason)
                        self.events.write(
                            "app_runtime_unhealthy",
                            app_id=app_id,
                            stage="monitor_health_check",
                            reason=reason,
                            failure_streak=app_state.health_failure_streak,
                        )
                    if app_state.health_failure_streak < self._unhealthy_threshold(app_state):
                        self.runtime_store.save(record)
                        continue
                    await self._terminate_runtime_process(app_state, record)
                    self._mark_failed(
                        app_state,
                        stage="monitor_health_check",
                        reason=f"monitor health check failed: {reason}",
                        record=record,
                        persist=True,
                    )
                    app_state.next_restart_at = time.time() + self._restart_backoff(app_state, 1)
                    continue

                if app_state.health_failure_streak:
                    self.events.write(
                        "app_health_recovered",
                        app_id=app_id,
                        failure_streak=app_state.health_failure_streak,
                    )
                app_state.health_failure_streak = 0
                stable_seconds = min(
                    app_state.config.lifecycle.stable_reset_seconds,
                    self.gateway_config.restart_stable_seconds,
                )
                if (
                    app_state.restart_history
                    and app_state.healthy_since
                    and time.time() - app_state.healthy_since >= stable_seconds
                ):
                    app_state.restart_history = []
                    app_state.restart_attempts = 0
                    record.restart_history = []
                    self.events.write("app_restart_budget_reset", app_id=app_id)
                self.runtime_store.save(record)

    def touch_user_activity(self, app_id: str, path: str) -> None:
        app_state = self.get_app(app_id)
        record = app_state.runtime
        if record is None or record.state != "running":
            return

        activity = app_state.config.activity
        if any(_matches_prefix(path, prefix) for prefix in activity.ignore_prefixes):
            return

        if activity.count_as_user_prefixes and not any(
            _matches_prefix(path, prefix) for prefix in activity.count_as_user_prefixes
        ):
            return

        record.last_user_activity_time = time.time()
        self.runtime_store.save(record)

    def touch_request(self, app_id: str, method: str, path: str) -> None:
        app_state = self.get_app(app_id)
        record = app_state.runtime
        if record is None or record.state != "running":
            return

        record.request_count += 1
        record.last_request_time = time.time()
        record.last_request_method = method
        record.last_request_path = path
        self.runtime_store.save(record)

    def mark_upstream_status(self, app_id: str, status_code: int) -> None:
        app_state = self.get_app(app_id)
        record = app_state.runtime
        if record is None:
            return

        record.last_upstream_status = status_code
        self.runtime_store.save(record)

    def mark_proxy_error(self, app_id: str, path: str, message: str) -> None:
        app_state = self.get_app(app_id)
        record = app_state.runtime
        if record is None:
            return

        record.last_proxy_error_time = time.time()
        record.last_proxy_error_path = path
        record.last_proxy_error_message = message
        self.runtime_store.save(record)

    def clear_proxy_error(self, app_id: str) -> None:
        app_state = self.get_app(app_id)
        record = app_state.runtime
        if record is None:
            return

        record.last_proxy_error_time = 0.0
        record.last_proxy_error_path = ""
        record.last_proxy_error_message = ""
        self.runtime_store.save(record)

    def stream_started(self, app_id: str) -> None:
        app_state = self.get_app(app_id)
        record = app_state.runtime
        if record is None or record.state != "running":
            return
        record.active_stream_count += 1
        record.last_stream_activity_time = time.time()
        self.runtime_store.save(record)

    def stream_touched(self, app_id: str) -> None:
        app_state = self.get_app(app_id)
        record = app_state.runtime
        if record is None or record.state != "running":
            return
        record.last_stream_activity_time = time.time()
        self.runtime_store.save(record)

    def stream_finished(self, app_id: str) -> None:
        app_state = self.get_app(app_id)
        record = app_state.runtime
        if record is None or record.state != "running":
            return
        record.active_stream_count = max(0, record.active_stream_count - 1)
        self.runtime_store.save(record)

    def path_is_streaming(self, app_id: str, sub_path: str) -> bool:
        app_state = self.get_app(app_id)
        prefixes = app_state.config.activity.streaming_prefixes
        return any(_matches_prefix(sub_path, prefix) for prefix in prefixes)

    async def recover(self) -> None:
        self.set_phase("recovering")
        self.logger.info("Gateway recovery started")
        self.events.write("gateway_recovery_started")

        existing_records = {record.app_id: record for record in self.runtime_store.list_records()}

        for app_id, app_state in self.apps.items():
            record = existing_records.get(app_id)
            if record is None:
                app_state.state = "stopped"
                app_state.runtime = None
                app_state.process = None
                app_state.last_error = ""
                continue

            self._sync_failure_meta_from_runtime(app_state, record)

            if not app_state.enabled:
                await self._terminate_runtime_process(app_state, record)
                self.runtime_store.delete(app_id)
                app_state.state = "stopped"
                app_state.runtime = None
                app_state.process = None
                self.events.write("runtime_cleaned", app_id=app_id, reason="app_disabled")
                continue

            identity_matches = process_matches_identity(record.pid, record.process_identity)

            if record.state == "failed":
                if record.pid > 0 and record.health_url and identity_matches:
                    healthy, reason = await check_once(self.http_client, record.health_url)
                    record.last_health_check_time = time.time()
                    record.last_health_check_ok = healthy
                    if healthy:
                        record = self._mark_success(app_state, record)
                        app_state.runtime = record
                        app_state.state = "running"
                        self.runtime_store.save(record)
                        self.events.write(
                            "runtime_restored",
                            app_id=app_id,
                            pid=record.pid,
                            port=record.internal_port,
                            internal_url=record.internal_url,
                        )
                        continue

                    self._mark_failed(
                        app_state,
                        stage="recovery_health_check",
                        reason=f"failed record recovery health check failed: {reason}",
                        record=record,
                        persist=True,
                    )
                    continue

                app_state.state = "failed"
                app_state.runtime = record
                app_state.process = None
                continue

            if record.pid <= 0 or not pid_exists(record.pid) or not identity_matches:
                reason = "pid_missing" if record.pid <= 0 or not pid_exists(record.pid) else "identity_mismatch"
                self.events.write("runtime_cleaned", app_id=app_id, reason=reason)
                self.runtime_store.delete(app_id)
                app_state.state = "stopped"
                app_state.runtime = None
                app_state.process = None
                app_state.last_error = ""
                continue

            healthy, reason = await check_once(self.http_client, record.health_url)
            record.last_health_check_time = time.time()
            record.last_health_check_ok = healthy

            if not healthy:
                self._mark_failed(
                    app_state,
                    stage="recovery_health_check",
                    reason=f"recovery health check failed: {reason}",
                    record=record,
                    persist=True,
                )
                continue

            record = self._mark_success(app_state, record)
            app_state.state = "running"
            app_state.runtime = record
            app_state.process = None
            self.runtime_store.save(record)
            self.events.write(
                "runtime_restored",
                app_id=app_id,
                pid=record.pid,
                port=record.internal_port,
                internal_url=record.internal_url,
            )

        for app_id, app_state in self.apps.items():
            if (
                app_state.enabled
                and app_state.config.lifecycle.start_policy == "always"
                and app_state.state != "running"
            ):
                try:
                    await self.ensure_started(app_id)
                except Exception as exc:
                    self.logger.warning("Always-start recovery failed for %s: %s", app_id, exc)
                    self.events.write(
                        "app_always_start_failed", app_id=app_id, reason=str(exc)[:1000]
                    )

        self.set_phase("ready")
        self.events.write("gateway_recovery_finished")
        self.logger.info("Gateway recovery finished")

    async def idle_scan_once(self) -> None:
        now = time.time()
        for app_state in self.apps.values():
            if app_state.state != "running" or app_state.runtime is None:
                continue

            config = app_state.config
            if not config.allow_auto_stop:
                continue

            record = app_state.runtime
            idle_timeout = (
                self.gateway_config.default_idle_timeout_seconds
                if config.idle_timeout_seconds is None
                else config.idle_timeout_seconds
            )
            if idle_timeout <= 0:
                continue
            stream_silence = config.activity.streaming_silence_seconds

            idle_for = now - record.last_user_activity_time
            stream_active = record.active_stream_count > 0
            recent_stream = (now - record.last_stream_activity_time) < stream_silence if record.last_stream_activity_time > 0 else False

            if idle_for >= idle_timeout and not stream_active and not recent_stream:
                await self.stop(config.app_id, reason="idle timeout")
