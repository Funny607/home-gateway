from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.config.loader import validate_app_collection
from app.config.schema import AppConfig
from app.lifecycle.manager import LifecycleManager
from app.security.service import SecurityService


class RegistryError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class AppRegistry:
    MAX_MANIFEST_BYTES = 256 * 1024

    def __init__(
        self,
        *,
        config_dir: Path,
        manager: LifecycleManager,
        security: SecurityService,
    ) -> None:
        self.config_dir = Path(config_dir)
        self.apps_dir = self.config_dir / "apps"
        self.apps_dir.mkdir(parents=True, exist_ok=True)
        self.manager = manager
        self.security = security

    @staticmethod
    def revision(config: AppConfig) -> str:
        encoded = json.dumps(
            config.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def bootstrap(self) -> None:
        states = self.security.store.registry_states()
        for app_id, state in self.manager.apps.items():
            revision = self.revision(state.config)
            existing = states.get(app_id)
            enabled = bool(existing["enabled"]) if existing is not None else True
            self.manager.set_enabled(app_id, enabled)
            self.security.policy.apps[app_id] = state.config
            if existing is None or existing.get("manifest_revision") != revision:
                self.security.store.set_registry_state(
                    app_id=app_id,
                    enabled=enabled,
                    manifest_revision=revision,
                    updated_by="system",
                    disabled_reason=str((existing or {}).get("disabled_reason", "")),
                )

    def list(self) -> list[dict[str, Any]]:
        states = self.security.store.registry_states()
        result: list[dict[str, Any]] = []
        for app_id, app_state in sorted(self.manager.apps.items()):
            stored = states.get(app_id, {})
            result.append(
                {
                    "app_id": app_id,
                    "display_name": app_state.config.display_name,
                    "mount_path": app_state.config.mount_path,
                    "enabled": app_state.enabled,
                    "state": app_state.state,
                    "manifest_version": app_state.config.manifest_version,
                    "manifest_revision": self.revision(app_state.config),
                    "updated_at": stored.get("updated_at"),
                    "updated_by": stored.get("updated_by", "system"),
                    "disabled_reason": stored.get("disabled_reason", ""),
                    "capabilities": [cap.id for cap in app_state.config.capabilities],
                    "dependencies": list(app_state.config.lifecycle.dependencies),
                }
            )
        return result

    def _parse(self, manifest: str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(manifest, str):
            if len(manifest.encode("utf-8")) > self.MAX_MANIFEST_BYTES:
                raise RegistryError(413, "manifest_too_large", "manifest exceeds 256 KiB")
            try:
                raw = yaml.safe_load(manifest)
            except yaml.YAMLError as exc:
                raise RegistryError(422, "invalid_yaml", str(exc)) from exc
        else:
            raw = manifest
        if not isinstance(raw, dict):
            raise RegistryError(422, "invalid_manifest", "manifest root must be an object")
        return raw

    def preview(self, manifest: str | dict[str, Any]) -> dict[str, Any]:
        raw = self._parse(manifest)
        try:
            config = AppConfig.model_validate(raw)
            candidate = {
                app_id: state.config
                for app_id, state in self.manager.apps.items()
                if app_id != config.app_id
            }
            candidate[config.app_id] = config
            validate_app_collection(candidate)
        except ValidationError as exc:
            raise RegistryError(422, "manifest_validation_failed", str(exc)) from exc
        except ValueError as exc:
            raise RegistryError(409, "manifest_conflict", str(exc)) from exc

        warnings: list[str] = []
        workdir = Path(config.workdir).expanduser()
        if not workdir.is_dir():
            warnings.append(f"工作目录当前不存在：{workdir}")
        try:
            command, _ = config.build_command(
                host=config.listen_host,
                port="12345",
                app_id=config.app_id,
                mount_path=config.mount_path,
            )
            executable = Path(command[0]).expanduser() if "/" in command[0] else None
            if executable is not None and not executable.is_file():
                warnings.append(f"启动程序当前不存在：{executable}")
        except (IndexError, KeyError, ValueError) as exc:
            raise RegistryError(422, "invalid_command", str(exc)) from exc
        return {
            "valid": True,
            "app": config.model_dump(mode="json"),
            "manifest_revision": self.revision(config),
            "warnings": warnings,
            "summary": {
                "capability_count": len(config.capabilities),
                "lease_count": sum(cap.lease_policy is not None for cap in config.capabilities),
                "proxy_limit_bytes": config.proxy.max_request_body_bytes,
                "start_policy": config.lifecycle.start_policy,
            },
        }

    def save(
        self,
        *,
        manifest: str | dict[str, Any],
        actor: str,
        expected_revision: str = "",
    ) -> dict[str, Any]:
        preview = self.preview(manifest)
        config = AppConfig.model_validate(preview["app"])
        existing = self.manager.apps.get(config.app_id)
        if existing is not None:
            current_revision = self.revision(existing.config)
            if expected_revision and expected_revision != current_revision:
                raise RegistryError(
                    409, "manifest_revision_conflict", "manifest changed since it was opened"
                )
            if existing.state not in {"stopped", "failed"} or existing.runtime is not None:
                raise RegistryError(409, "app_not_stopped", "stop the app before updating its manifest")
            if self.security.active_lease_count(config.app_id):
                raise RegistryError(409, "active_leases", "release active leases before updating")

        payload = yaml.safe_dump(
            config.model_dump(mode="json", exclude_none=True),
            allow_unicode=True,
            sort_keys=False,
        )
        path = self.apps_dir / f"{config.app_id}.yaml"
        fd, temp_name = tempfile.mkstemp(prefix=f".{config.app_id}.", suffix=".tmp", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

        if existing is None:
            self.manager.register_app(config)
        else:
            self.manager.update_app(config)
        self.security.policy.apps[config.app_id] = config
        revision = self.revision(config)
        current_state = self.security.store.registry_states().get(config.app_id, {})
        enabled = bool(current_state.get("enabled", True))
        self.manager.set_enabled(config.app_id, enabled)
        self.security.store.set_registry_state(
            app_id=config.app_id,
            enabled=enabled,
            manifest_revision=revision,
            updated_by=actor,
            disabled_reason=str(current_state.get("disabled_reason", "")),
        )
        self.manager.events.write(
            "app_manifest_saved", app_id=config.app_id, actor=actor, revision=revision
        )
        return {**preview, "path": str(path), "enabled": enabled}

    async def set_enabled(
        self, *, app_id: str, enabled: bool, actor: str, reason: str = ""
    ) -> dict[str, Any]:
        try:
            state = self.manager.get_app(app_id)
        except KeyError as exc:
            raise RegistryError(404, "app_not_found", "app is not registered") from exc
        if not enabled:
            if self.security.active_lease_count(app_id):
                raise RegistryError(409, "active_leases", "release active leases before disabling")
            if state.state in {"starting", "running", "stopping"}:
                try:
                    await self.manager.stop(app_id, reason="disabled in registry")
                except RuntimeError as exc:
                    raise RegistryError(409, "app_stop_blocked", str(exc)) from exc
        self.manager.set_enabled(app_id, enabled)
        stored = self.security.store.set_registry_state(
            app_id=app_id,
            enabled=enabled,
            manifest_revision=self.revision(state.config),
            updated_by=actor,
            disabled_reason="" if enabled else reason[:1000],
        )
        self.manager.events.write(
            "app_enabled" if enabled else "app_disabled",
            app_id=app_id,
            actor=actor,
            reason=reason[:1000],
        )
        return {**stored, "enabled": bool(stored["enabled"])}
