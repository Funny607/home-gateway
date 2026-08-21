from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.config.schema import AppConfig, GatewayConfig, LinkConfig, LinksConfig


def _load_yaml(path: Path) -> dict[str, Any]:
    """
    Load one YAML file as a dict.

    Empty YAML files are treated as empty dict.
    Non-dict root values are rejected because all Gateway config files
    are expected to be mapping-style YAML files.
    """
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be an object: {path}")

    return data


def _should_skip_app_config(path: Path) -> bool:
    """
    Decide whether a file under configs/apps should be skipped.

    Rules:
    - Files beginning with "_" are disabled or examples.
    - *.example.yaml, *.sample.yaml, *.template.yaml are examples/templates.
    - Non-yaml files are ignored.
    """
    name = path.name

    if name.startswith("_"):
        return True

    if name.endswith(".example.yaml"):
        return True

    if name.endswith(".sample.yaml"):
        return True

    if name.endswith(".template.yaml"):
        return True

    if path.suffix not in {".yaml", ".yml"}:
        return True

    return False


def _command_is_empty(command: str | list[str]) -> bool:
    """
    Check whether app command is empty.

    command supports both:
    - string form
    - list form
    """
    if isinstance(command, str):
        return not command.strip()

    if isinstance(command, list):
        return len(command) == 0 or all(not str(part).strip() for part in command)

    return True


def _load_gateway_config(config_dir: Path) -> GatewayConfig:
    """
    Load configs/gateway.yaml.
    """
    gateway_path = config_dir / "gateway.yaml"

    if not gateway_path.exists():
        raise FileNotFoundError(f"Gateway config not found: {gateway_path}")

    raw = _load_yaml(gateway_path)
    return GatewayConfig.model_validate(raw)


def _load_apps(config_dir: Path) -> dict[str, AppConfig]:
    """
    Load app configs from configs/apps/*.yaml.

    Example/template files are skipped so that files like:
    - qbt-mode.capability.example.yaml
    - _template.yaml
    will not be parsed as real apps.
    """
    apps_dir = config_dir / "apps"
    apps: dict[str, AppConfig] = {}

    if not apps_dir.exists():
        return apps

    for app_file in sorted(apps_dir.glob("*")):
        if not app_file.is_file():
            continue

        if _should_skip_app_config(app_file):
            continue

        raw = _load_yaml(app_file)
        app = AppConfig.model_validate(raw)

        if app.app_id in apps:
            raise ValueError(f"Duplicate app_id: {app.app_id}")

        apps[app.app_id] = app

    return apps


def _load_links(config_dir: Path) -> list[LinkConfig]:
    """
    Load configs/links.yaml.

    Missing links.yaml is allowed.
    """
    links_path = config_dir / "links.yaml"

    if not links_path.exists():
        return []

    raw = _load_yaml(links_path)
    links_config = LinksConfig.model_validate(raw)
    return links_config.links


def validate_app_collection(apps: dict[str, AppConfig], links: list[LinkConfig] | None = None) -> None:
    """
    Cross-check app and link configs.

    This catches common config mistakes early:
    - duplicate mount_path
    - duplicate link_id
    - link_id conflicts with app_id
    - empty command
    - invalid health_path
    - missing workdir
    """

    seen_mount_paths: dict[str, str] = {}
    seen_capabilities: dict[str, str] = {}

    for app_id, app in apps.items():
        mount_path = str(app.mount_path)

        if mount_path in seen_mount_paths:
            other_app_id = seen_mount_paths[mount_path]
            raise ValueError(
                f"Duplicate mount_path {mount_path!r}: "
                f"{other_app_id!r} and {app_id!r}"
            )

        seen_mount_paths[mount_path] = app_id

        for other_mount, other_app_id in seen_mount_paths.items():
            if other_app_id == app_id:
                continue
            if mount_path.startswith(other_mount + "/") or other_mount.startswith(mount_path + "/"):
                raise ValueError(
                    f"Overlapping mount paths are not allowed: {other_mount!r} and {mount_path!r}"
                )

        if _command_is_empty(app.command):
            raise ValueError(f"App command is empty: {app_id}")

        if not app.health_path.startswith("/"):
            raise ValueError(f"health_path must start with '/': {app_id}")

        if not app.mount_path.startswith("/"):
            raise ValueError(f"mount_path must start with '/': {app_id}")

        for capability in app.capabilities:
            if capability.id in seen_capabilities:
                raise ValueError(
                    f"Duplicate capability id {capability.id!r}: "
                    f"{seen_capabilities[capability.id]!r} and {app_id!r}"
                )
            seen_capabilities[capability.id] = app_id

    # Dependencies are configuration, not imperative Python wiring. Validate
    # the complete graph here so a fourth app cannot introduce a boot-time
    # cycle or reference a silently missing service.
    for app_id, app in apps.items():
        for dependency in app.lifecycle.dependencies:
            if dependency not in apps:
                raise ValueError(f"App {app_id!r} depends on unknown app {dependency!r}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(app_id: str, chain: list[str]) -> None:
        if app_id in visiting:
            cycle = " -> ".join([*chain, app_id])
            raise ValueError(f"App lifecycle dependency cycle: {cycle}")
        if app_id in visited:
            return
        visiting.add(app_id)
        for dependency in apps[app_id].lifecycle.dependencies:
            visit(dependency, [*chain, app_id])
        visiting.remove(app_id)
        visited.add(app_id)

    for app_id in apps:
        visit(app_id, [])

    # An identical route claimed by two capabilities is ambiguous and could
    # make the selected policy depend on YAML ordering.
    shared_resources: dict[str, tuple[str, str]] = {}
    for app_id, app in apps.items():
        claimed: dict[tuple[str, str, str], str] = {}
        for capability in app.capabilities:
            for route in capability.routes:
                matcher = (
                    "path" if route.path is not None else
                    "path_prefix" if route.path_prefix is not None else
                    "path_regex"
                )
                value = route.path or route.path_prefix or route.path_regex or ""
                key = (route.method, matcher, value)
                previous = claimed.get(key)
                if previous and previous != capability.id:
                    raise ValueError(
                        f"Ambiguous capability route in {app_id!r}: {key} is declared by "
                        f"{previous!r} and {capability.id!r}"
                    )
                claimed[key] = capability.id
            if capability.lease_policy is not None:
                resource_key = capability.lease_policy.resource_key
                signature = capability.lease_policy.model_dump_json(
                    exclude={"max_lease_seconds", "heartbeat_interval_seconds"}
                )
                previous = shared_resources.get(resource_key)
                if previous is not None and previous[1] != signature:
                    raise ValueError(
                        f"Lease capabilities sharing resource {resource_key!r} must use the same "
                        f"adapter ({previous[0]!r} conflicts with {capability.id!r})"
                    )
                shared_resources[resource_key] = (capability.id, signature)

    seen_link_ids: set[str] = set()

    for link in links or []:
        if link.link_id in seen_link_ids:
            raise ValueError(f"Duplicate link_id: {link.link_id}")

        seen_link_ids.add(link.link_id)

        if link.link_id in apps:
            raise ValueError(f"link_id conflicts with app_id: {link.link_id}")


def load_configs(config_dir: str | Path) -> tuple[GatewayConfig, dict[str, AppConfig], list[LinkConfig]]:
    """
    Load all Gateway configs.

    Returns:
        gateway_config, apps, links
    """
    config_path = Path(config_dir)

    gateway_config = _load_gateway_config(config_path)
    apps = _load_apps(config_path)
    links = _load_links(config_path)

    validate_app_collection(apps, links)

    return gateway_config, apps, links
