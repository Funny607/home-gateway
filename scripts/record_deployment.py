from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config.loader import load_configs
from app.security.auth import load_auth_config, resolve_reference
from app.security.db import SecurityStore, now_ts


def main() -> None:
    os.chdir(ROOT)
    gateway, _, _ = load_configs(ROOT / "configs")
    auth = load_auth_config(ROOT / "configs" / "auth.yaml")
    store = SecurityStore(gateway.api_audit_db, pepper=resolve_reference(auth.database_pepper_ref))
    current = store.get_system_state("deployment_history", [])
    history = current if isinstance(current, list) else []
    entry = {
        "version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        "installed_at": now_ts(),
        "project_dir": str(ROOT),
        "upgrade_source": os.environ.get("GATEWAY_UPGRADE_SOURCE", "")[:1000],
    }
    if not history or history[-1].get("version") != entry["version"] or history[-1].get("project_dir") != entry["project_dir"]:
        history.append(entry)
    store.set_system_state("deployment_history", history[-20:])
    print(f"Deployment recorded: {entry['version']}")


if __name__ == "__main__":
    main()
