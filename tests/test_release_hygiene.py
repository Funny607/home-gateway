from __future__ import annotations

import re
import os
import importlib.util
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent


class ReleaseHygieneTests(unittest.TestCase):
    def test_release_builder_preserves_runtime_source_package(self) -> None:
        module_path = ROOT / "scripts" / "build_release.py"
        spec = importlib.util.spec_from_file_location("gateway_build_release", module_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertTrue(module.included(ROOT / "app" / "runtime" / "store.py"))
        self.assertIn("runtime", module.EXCLUDED_TOP_LEVEL)
        self.assertNotIn("runtime", module.EXCLUDED_ANYWHERE)

    def test_release_contains_no_runtime_or_backup_artifacts(self) -> None:
        if os.environ.get("GATEWAY_INSTALLED_UAT") == "1":
            self.skipTest("release cleanliness is checked before installation")
        forbidden_parts = {".venv", "__pycache__", ".DS_Store"}
        forbidden_suffixes = {".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".pyc"}
        offenders = []
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT)
            if any(part in forbidden_parts for part in relative.parts) or relative.parts[0] in {"runtime", "logs"}:
                offenders.append(str(relative))
            if path.is_file() and (
                any(path.name.endswith(suffix) for suffix in forbidden_suffixes)
                or ".bak" in path.name
            ):
                offenders.append(str(relative))
        self.assertEqual(offenders, [])

    def test_yaml_contains_references_not_plaintext_secrets(self) -> None:
        pattern = re.compile(
            r"^\s*(?:password|session_secret|device_secret|access_token)\s*:", re.I | re.M
        )
        offenders = [
            str(path.relative_to(ROOT))
            for path in (ROOT / "configs").rglob("*.yaml")
            if pattern.search(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_yaml_secret_references_use_keychain_or_environment(self) -> None:
        offenders = []

        def walk(value, path: str) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    current = f"{path}.{key}" if path else str(key)
                    if str(key).endswith("_ref") and (
                        not isinstance(child, str)
                        or not child.startswith(("keychain:", "env:"))
                    ):
                        offenders.append(current)
                    walk(child, current)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f"{path}[{index}]")

        for source in (ROOT / "configs").rglob("*.yaml"):
            walk(yaml.safe_load(source.read_text(encoding="utf-8")) or {}, str(source.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_deployment_never_binds_all_interfaces(self) -> None:
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "deploy").iterdir()
            if path.is_file()
        )
        self.assertNotIn("0.0.0.0", text)
        self.assertIn("--host 127.0.0.1", text)

    def test_dependency_lock_is_exact(self) -> None:
        lines = [
            line.strip()
            for line in (ROOT / "requirements.lock.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertTrue(lines)
        self.assertTrue(all("==" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
