from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.security.db import SCHEMA_VERSION, SecurityStore


class DatabaseMigrationTests(unittest.TestCase):
    def test_legacy_database_is_backed_up_and_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.sqlite3"
            conn = sqlite3.connect(path)
            conn.executescript(
                """
                CREATE TABLE api_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL,
                    request_id TEXT NOT NULL, actor_type TEXT NOT NULL, actor_name TEXT,
                    device_id TEXT, source_id TEXT, client_name TEXT, grant_id TEXT,
                    token_id TEXT, target_app TEXT, capability TEXT, method TEXT NOT NULL,
                    path TEXT NOT NULL, upstream_path TEXT, status_code INTEGER,
                    success INTEGER NOT NULL, duration_ms INTEGER, error_code TEXT,
                    risk_level TEXT, raw_json TEXT
                );
                INSERT INTO api_audit (
                    created_at, request_id, actor_type, method, path, success
                ) VALUES (1, 'legacy-request', 'legacy', 'GET', '/old', 1);
                CREATE TABLE trusted_device (
                    id INTEGER PRIMARY KEY, device_id TEXT, device_name TEXT, device_type TEXT,
                    source_id TEXT, public_key TEXT, trust_level TEXT, status TEXT,
                    created_at INTEGER, last_seen_at INTEGER, last_ip TEXT, user_agent TEXT
                );
                INSERT INTO trusted_device (
                    device_id, device_name, device_type, trust_level, status, created_at
                ) VALUES ('legacy-device', 'Old', 'test', 'trusted', 'active', 1);
                """
            )
            conn.commit()
            conn.close()

            store = SecurityStore(path, pepper="p" * 48)
            report = store.integrity_report()
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["schema_version"], SCHEMA_VERSION)
            backups = list((path.parent / "backups").glob("*.pre-stage1-v1.*.sqlite3"))
            self.assertEqual(len(backups), 1)
            audit = store.fetch_one("SELECT * FROM api_audit WHERE request_id='legacy-request'")
            self.assertIsNotNone(audit)
            device = store.fetch_one("SELECT * FROM trusted_device WHERE device_id='legacy-device'")
            self.assertEqual(device["status"], "re_registration_required")
            with store.read() as check:
                self.assertEqual(check.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                self.assertIsNone(
                    check.execute(
                        "SELECT 1 FROM sqlite_master WHERE name LIKE 'legacy_v0_%'"
                    ).fetchone()
                )
                indexes = {
                    row[0] for row in check.execute(
                        "SELECT name FROM sqlite_master WHERE type='index'"
                    ).fetchall()
                }
            self.assertIn("idx_token_grant", indexes)

    def test_stage1_database_is_backed_up_and_upgraded_to_stage5(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.sqlite3"
            conn = sqlite3.connect(path, isolation_level=None)
            conn.execute("BEGIN")
            seed = object.__new__(SecurityStore)
            seed._migration_v1(conn)
            conn.execute("PRAGMA user_version=1")
            conn.execute(
                "INSERT INTO schema_migration(version, applied_at, description) VALUES (1, 1, 'test')"
            )
            conn.commit()
            conn.close()

            store = SecurityStore(path, pepper="q" * 48)
            self.assertEqual(store.integrity_report()["schema_version"], SCHEMA_VERSION)
            backups = list((path.parent / "backups").glob("*.pre-stage5-v4.*.sqlite3"))
            self.assertEqual(len(backups), 1)
            with store.read() as check:
                lease_columns = {
                    row[1] for row in check.execute("PRAGMA table_info(lease_record)")
                }
                tables = {
                    row[0] for row in check.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            self.assertIn("resource_key", lease_columns)
            self.assertIn("notification_record", tables)
            self.assertIn("app_registry_state", tables)
            self.assertIn("recovery_code", tables)
            self.assertIn("emergency_token", tables)
            with store.read() as check:
                approval_columns = {row[1] for row in check.execute("PRAGMA table_info(approval_request)")}
                token_columns = {row[1] for row in check.execute("PRAGMA table_info(token_record)")}
            self.assertIn("action_hash", approval_columns)
            self.assertIn("bound_body_sha256", token_columns)

    def test_stage3_database_is_backed_up_and_upgraded_to_schema_v4(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.sqlite3"
            conn = sqlite3.connect(path, isolation_level=None)
            conn.execute("BEGIN")
            seed = object.__new__(SecurityStore)
            seed._migration_v1(conn)
            seed._migration_v2(conn)
            seed._migration_v3(conn)
            conn.execute("PRAGMA user_version=3")
            conn.executemany(
                "INSERT INTO schema_migration(version, applied_at, description) VALUES (?, 1, 'test')",
                [(1,), (2,), (3,)],
            )
            conn.commit()
            conn.close()

            store = SecurityStore(path, pepper="s" * 48)
            self.assertEqual(store.integrity_report()["schema_version"], SCHEMA_VERSION)
            backups = list((path.parent / "backups").glob("*.pre-stage5-v4.*.sqlite3"))
            self.assertEqual(len(backups), 1)
            with store.read() as check:
                tables = {
                    row[0] for row in check.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            self.assertIn("recovery_code", tables)
            self.assertIn("emergency_token", tables)


if __name__ == "__main__":
    unittest.main()
