from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 4
MANAGED_TABLES = (
    "api_audit",
    "trusted_device",
    "approval_request",
    "grant_record",
    "token_record",
    "lease_record",
    "notification_record",
    "app_registry_state",
    "system_state",
    "recovery_code",
    "emergency_token",
)


def now_ts() -> int:
    return int(time.time())


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def json_loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return default


SENSITIVE_FIELD_MARKERS = (
    "password",
    "secret",
    "token",
    "authorization",
    "cookie",
    "credential",
    "private_key",
)


def redact_metadata(value: Any, *, depth: int = 0) -> Any:
    """Bound and redact metadata before it reaches audit, UI, or email."""
    if depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (raw_key, raw_value) in enumerate(value.items()):
            if index >= 100:
                result["_truncated"] = True
                break
            key = str(raw_key)[:160]
            if any(marker in key.lower() for marker in SENSITIVE_FIELD_MARKERS):
                result[key] = "[redacted]"
            else:
                result[key] = redact_metadata(raw_value, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_metadata(item, depth=depth + 1) for item in list(value)[:100]]
    if isinstance(value, str):
        return value[:2000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:2000]


class SecurityStore:
    """Single SQLite boundary for identity, policy records, tokens, leases, and audit."""

    def __init__(self, db_path: Path, *, pepper: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if len(pepper) < 32:
            raise ValueError("database pepper must contain at least 32 characters")
        self._pepper = pepper.encode("utf-8")
        self._migration_lock = threading.Lock()
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def digest(self, kind: str, secret: str) -> str:
        return hmac.new(self._pepper, f"{kind}\0{secret}".encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_digest(self, kind: str, secret: str, encoded: str) -> bool:
        return hmac.compare_digest(self.digest(kind, secret), str(encoded))

    def _table_exists(self, conn: sqlite3.Connection, name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone()
        return row is not None

    def _backup_database(self, label: str) -> Path | None:
        if not self.db_path.exists() or self.db_path.stat().st_size == 0:
            return None
        backup_dir = self.db_path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = backup_dir / f"{self.db_path.stem}.{label}.{stamp}{self.db_path.suffix}"
        if not target.exists():
            source = sqlite3.connect(str(self.db_path), timeout=5.0)
            destination = sqlite3.connect(str(target), timeout=5.0)
            try:
                source.backup(destination)
            finally:
                destination.close()
                source.close()
        return target

    def migrate(self) -> None:
        with self._migration_lock:
            with self.read() as conn:
                version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                legacy = version == 0 and any(self._table_exists(conn, table) for table in MANAGED_TABLES)
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema {version} is newer than this Gateway supports ({SCHEMA_VERSION})"
                )
            if legacy:
                self._backup_database("pre-stage1-v1")
            elif 0 < version < SCHEMA_VERSION:
                self._backup_database(f"pre-stage5-v{SCHEMA_VERSION}")
            with self.transaction() as conn:
                version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                if version == 0:
                    self._migration_v1(conn)
                    conn.execute("PRAGMA user_version=1")
                    conn.execute(
                        "INSERT INTO schema_migration(version, applied_at, description) VALUES (?, ?, ?)",
                        (1, now_ts(), "Stage 1 transactional security schema"),
                    )
                    version = 1
                if version == 1:
                    self._migration_v2(conn)
                    conn.execute("PRAGMA user_version=2")
                    conn.execute(
                        "INSERT INTO schema_migration(version, applied_at, description) VALUES (?, ?, ?)",
                        (2, now_ts(), "Stage 2 registry, generic lease, and notification schema"),
                    )
                    version = 2
                if version == 2:
                    self._migration_v3(conn)
                    conn.execute("PRAGMA user_version=3")
                    conn.execute(
                        "INSERT INTO schema_migration(version, applied_at, description) VALUES (?, ?, ?)",
                        (3, now_ts(), "Stage 3 payload-bound action approval schema"),
                    )
                    version = 3
                if version == 3:
                    self._migration_v4(conn)
                    conn.execute("PRAGMA user_version=4")
                    conn.execute(
                        "INSERT INTO schema_migration(version, applied_at, description) VALUES (?, ?, ?)",
                        (4, now_ts(), "Stage 4 recovery code and constrained emergency access schema"),
                    )

    def _migration_v1(self, conn: sqlite3.Connection) -> None:
        legacy_tables: dict[str, str] = {}
        for table in MANAGED_TABLES:
            if self._table_exists(conn, table):
                legacy_name = f"legacy_v0_{table}"
                if self._table_exists(conn, legacy_name):
                    conn.execute(f'DROP TABLE "{legacy_name}"')
                conn.execute(f'ALTER TABLE "{table}" RENAME TO "{legacy_name}"')
                legacy_tables[table] = legacy_name

        self._execute_script(
            conn,
            """
            CREATE TABLE IF NOT EXISTS schema_migration (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL,
                description TEXT NOT NULL
            );

            CREATE TABLE trusted_device (
                device_id TEXT PRIMARY KEY,
                secret_hash TEXT NOT NULL,
                credential_version INTEGER NOT NULL DEFAULT 1,
                device_name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                source_id TEXT NOT NULL DEFAULT '',
                public_key TEXT NOT NULL DEFAULT '',
                trust_level TEXT NOT NULL CHECK (trust_level IN ('untrusted','paired','trusted','privileged')),
                status TEXT NOT NULL CHECK (status IN ('pending','active','revoked','re_registration_required')),
                created_at INTEGER NOT NULL,
                trusted_at INTEGER,
                trusted_by TEXT,
                trust_expires_at INTEGER,
                revoked_at INTEGER,
                revoked_by TEXT,
                revoke_reason TEXT,
                last_seen_at INTEGER,
                last_ip TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                raw_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE approval_request (
                approval_id TEXT PRIMARY KEY,
                approval_type TEXT NOT NULL CHECK (approval_type IN ('device_registration','grant','action')),
                target_app TEXT NOT NULL DEFAULT '',
                device_id TEXT,
                pending_grant_id TEXT,
                requested_capabilities TEXT NOT NULL DEFAULT '[]',
                risk_level TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','cancelled')),
                requested_ttl_seconds INTEGER NOT NULL,
                required_trust_level TEXT NOT NULL,
                required_approval_methods TEXT NOT NULL DEFAULT '[]',
                request_code_hash TEXT UNIQUE,
                reason TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                approved_at INTEGER,
                approved_by TEXT,
                approval_method TEXT,
                denied_at INTEGER,
                denied_by TEXT,
                policy_json TEXT NOT NULL DEFAULT '{}',
                raw_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (device_id) REFERENCES trusted_device(device_id) ON DELETE RESTRICT
            );

            CREATE TABLE grant_record (
                grant_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                target_app TEXT NOT NULL,
                capabilities TEXT NOT NULL,
                grant_type TEXT NOT NULL CHECK (grant_type IN ('session','long_lived','one_time')),
                risk_level TEXT NOT NULL,
                required_trust_level TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                revoked_by TEXT,
                revoke_reason TEXT,
                approved_by TEXT,
                approval_method TEXT,
                approval_id TEXT,
                one_time_consumed_at INTEGER,
                last_used_at INTEGER,
                policy_json TEXT NOT NULL DEFAULT '{}',
                raw_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (device_id) REFERENCES trusted_device(device_id) ON DELETE RESTRICT,
                FOREIGN KEY (approval_id) REFERENCES approval_request(approval_id) ON DELETE SET NULL
            );

            CREATE TABLE token_record (
                token_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                token_type TEXT NOT NULL CHECK (token_type IN ('access','one_time')),
                grant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                target_app TEXT NOT NULL,
                capabilities TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                revoked_by TEXT,
                revoke_reason TEXT,
                consumed_at INTEGER,
                last_used_at INTEGER,
                source_id TEXT NOT NULL DEFAULT '',
                client_name TEXT NOT NULL DEFAULT '',
                raw_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (grant_id) REFERENCES grant_record(grant_id) ON DELETE CASCADE,
                FOREIGN KEY (device_id) REFERENCES trusted_device(device_id) ON DELETE RESTRICT
            );

            CREATE TABLE lease_record (
                lease_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                target_app TEXT NOT NULL,
                capability TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('activating','active','releasing','released','expired','failed')),
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                max_expires_at INTEGER NOT NULL,
                last_heartbeat_at INTEGER,
                released_at INTEGER,
                release_reason TEXT,
                raw_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (device_id) REFERENCES trusted_device(device_id) ON DELETE RESTRICT,
                FOREIGN KEY (grant_id) REFERENCES grant_record(grant_id) ON DELETE CASCADE
            );

            CREATE TABLE api_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                request_id TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_name TEXT NOT NULL DEFAULT '',
                device_id TEXT NOT NULL DEFAULT '',
                source_id TEXT NOT NULL DEFAULT '',
                client_name TEXT NOT NULL DEFAULT '',
                grant_id TEXT NOT NULL DEFAULT '',
                token_id TEXT NOT NULL DEFAULT '',
                target_app TEXT NOT NULL DEFAULT '',
                capability TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                upstream_path TEXT NOT NULL DEFAULT '',
                status_code INTEGER,
                success INTEGER NOT NULL CHECK (success IN (0,1)),
                duration_ms INTEGER,
                error_code TEXT NOT NULL DEFAULT '',
                risk_level TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                raw_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX idx_device_status_trust ON trusted_device(status, trust_level);
            CREATE INDEX idx_device_trust_expiry ON trusted_device(trust_expires_at);
            CREATE INDEX idx_approval_status_expiry ON approval_request(status, expires_at);
            CREATE INDEX idx_approval_device ON approval_request(device_id, created_at DESC);
            CREATE INDEX idx_grant_device_expiry ON grant_record(device_id, expires_at);
            CREATE INDEX idx_grant_app ON grant_record(target_app, created_at DESC);
            CREATE INDEX idx_token_device_expiry ON token_record(device_id, expires_at);
            CREATE INDEX idx_token_grant ON token_record(grant_id);
            CREATE UNIQUE INDEX idx_active_lease_device_capability
                ON lease_record(device_id, capability)
                WHERE status IN ('activating','active','releasing');
            CREATE INDEX idx_lease_expiry ON lease_record(status, expires_at);
            CREATE INDEX idx_api_audit_request_id ON api_audit(request_id);
            CREATE INDEX idx_api_audit_created_at ON api_audit(created_at DESC);
            CREATE INDEX idx_api_audit_device ON api_audit(device_id, created_at DESC);
            CREATE INDEX idx_api_audit_target_cap ON api_audit(target_app, capability, created_at DESC);
            """
        )

        legacy_audit = legacy_tables.get("api_audit")
        if legacy_audit:
            source_columns = {
                str(row[1]) for row in conn.execute(f'PRAGMA table_info("{legacy_audit}")').fetchall()
            }
            columns = [
                "created_at", "request_id", "actor_type", "actor_name", "device_id",
                "source_id", "client_name", "grant_id", "token_id", "target_app",
                "capability", "method", "path", "upstream_path", "status_code",
                "success", "duration_ms", "error_code", "risk_level", "client_ip",
                "user_agent", "raw_json",
            ]
            nullable = {"status_code", "duration_ms"}
            numeric_defaults = {"created_at": "0", "success": "0"}
            expressions: list[str] = []
            for column in columns:
                if column in source_columns:
                    if column in nullable:
                        expressions.append(f'"{column}"')
                    elif column in numeric_defaults:
                        expressions.append(f'COALESCE("{column}", {numeric_defaults[column]})')
                    elif column == "raw_json":
                        expressions.append('COALESCE("raw_json", \'{}\')')
                    else:
                        expressions.append(f'COALESCE("{column}", \'\')')
                elif column in nullable:
                    expressions.append("NULL")
                elif column in numeric_defaults:
                    expressions.append(numeric_defaults[column])
                elif column == "raw_json":
                    expressions.append("'{}'")
                else:
                    expressions.append("''")
            conn.execute(
                f"INSERT INTO api_audit ({','.join(columns)}) "
                f"SELECT {','.join(expressions)} FROM \"{legacy_audit}\""
            )

        legacy_devices = legacy_tables.get("trusted_device")
        if legacy_devices:
            rows = conn.execute(f'SELECT * FROM "{legacy_devices}"').fetchall()
            for row in rows:
                data = dict(row)
                device_id = str(data.get("device_id") or "")
                if not device_id:
                    continue
                conn.execute(
                    """
                    INSERT OR IGNORE INTO trusted_device (
                        device_id, secret_hash, device_name, device_type, source_id, public_key,
                        trust_level, status, created_at, last_seen_at, last_ip, user_agent, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, 'untrusted', 're_registration_required', ?, ?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        self.digest("device", secrets.token_urlsafe(32)),
                        str(data.get("device_name") or "Legacy device"),
                        str(data.get("device_type") or "legacy"),
                        str(data.get("source_id") or ""),
                        str(data.get("public_key") or ""),
                        int(data.get("created_at") or now_ts()),
                        data.get("last_seen_at"),
                        str(data.get("last_ip") or ""),
                        str(data.get("user_agent") or ""),
                        json_dumps({"migration": "credentials invalidated", "legacy": data}),
                    ),
                )

        # The complete v0 database remains in the timestamped backup. Keeping
        # stale security tables in the active database risks accidental reads.
        for table in reversed(MANAGED_TABLES):
            legacy_name = legacy_tables.get(table)
            if legacy_name and self._table_exists(conn, legacy_name):
                conn.execute(f'DROP TABLE "{legacy_name}"')

    def _migration_v2(self, conn: sqlite3.Connection) -> None:
        lease_columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(lease_record)").fetchall()
        }
        additions = (
            ("resource_key", "TEXT NOT NULL DEFAULT ''"),
            ("reconcile_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("next_reconcile_at", "INTEGER NOT NULL DEFAULT 0"),
            ("last_reconcile_at", "INTEGER"),
            ("last_reconcile_error", "TEXT NOT NULL DEFAULT ''"),
        )
        for name, definition in additions:
            if name not in lease_columns:
                conn.execute(f"ALTER TABLE lease_record ADD COLUMN {name} {definition}")
        conn.execute(
            "UPDATE lease_record SET resource_key=capability WHERE resource_key='' OR resource_key IS NULL"
        )

        self._execute_script(
            conn,
            """
            CREATE TABLE IF NOT EXISTS app_registry_state (
                app_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
                manifest_revision TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL,
                updated_by TEXT NOT NULL DEFAULT 'system',
                disabled_reason TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS notification_record (
                notification_id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('info','success','warning','danger')),
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                dedupe_key TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK (status IN ('queued','sending','sent','failed','in_app')),
                email_requested INTEGER NOT NULL DEFAULT 1 CHECK (email_requested IN (0,1)),
                created_at INTEGER NOT NULL,
                last_occurrence_at INTEGER NOT NULL,
                repeat_count INTEGER NOT NULL DEFAULT 1,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                sent_at INTEGER,
                read_at INTEGER,
                last_error TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS system_state (
                state_key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL DEFAULT '{}',
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_lease_resource_status
                ON lease_record(resource_key, status, expires_at);
            CREATE INDEX IF NOT EXISTS idx_lease_reconcile
                ON lease_record(status, next_reconcile_at, created_at);
            CREATE INDEX IF NOT EXISTS idx_notification_status_retry
                ON notification_record(status, next_attempt_at, created_at);
            CREATE INDEX IF NOT EXISTS idx_notification_dedupe
                ON notification_record(dedupe_key, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_notification_unread
                ON notification_record(read_at, created_at DESC);
            """,
        )

    def _migration_v3(self, conn: sqlite3.Connection) -> None:
        approval_columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(approval_request)").fetchall()
        }
        for name, definition in (
            ("grant_id", "TEXT"),
            ("capability", "TEXT NOT NULL DEFAULT ''"),
            ("action_method", "TEXT NOT NULL DEFAULT ''"),
            ("action_path", "TEXT NOT NULL DEFAULT ''"),
            ("body_sha256", "TEXT NOT NULL DEFAULT ''"),
            ("payload_preview", "TEXT NOT NULL DEFAULT ''"),
            ("action_hash", "TEXT NOT NULL DEFAULT ''"),
            ("consumed_at", "INTEGER"),
        ):
            if name not in approval_columns:
                conn.execute(f"ALTER TABLE approval_request ADD COLUMN {name} {definition}")

        token_columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(token_record)").fetchall()
        }
        for name, definition in (
            ("action_approval_id", "TEXT"),
            ("bound_action_hash", "TEXT NOT NULL DEFAULT ''"),
            ("bound_method", "TEXT NOT NULL DEFAULT ''"),
            ("bound_path", "TEXT NOT NULL DEFAULT ''"),
            ("bound_body_sha256", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in token_columns:
                conn.execute(f"ALTER TABLE token_record ADD COLUMN {name} {definition}")

        self._execute_script(
            conn,
            """
            CREATE INDEX IF NOT EXISTS idx_action_approval_grant
                ON approval_request(grant_id, created_at DESC);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_action_approval_active_hash
                ON approval_request(device_id, grant_id, action_hash)
                WHERE approval_type='action' AND status IN ('pending','approved') AND consumed_at IS NULL;
            CREATE INDEX IF NOT EXISTS idx_token_action_approval
                ON token_record(action_approval_id);
            """,
        )

    def _migration_v4(self, conn: sqlite3.Connection) -> None:
        self._execute_script(
            conn,
            """
            CREATE TABLE IF NOT EXISTS recovery_code (
                code_id TEXT PRIMARY KEY,
                code_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                used_at INTEGER,
                used_by TEXT NOT NULL DEFAULT '',
                revoked_at INTEGER,
                generation INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS emergency_token (
                token_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_used_at INTEGER,
                revoked_at INTEGER,
                reason TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_recovery_code_active
                ON recovery_code(used_at, revoked_at, created_at);
            CREATE INDEX IF NOT EXISTS idx_emergency_token_active
                ON emergency_token(expires_at, revoked_at);
            """,
        )

    @staticmethod
    def _execute_script(conn: sqlite3.Connection, script: str) -> None:
        """Execute migration DDL without sqlite3.executescript's implicit COMMIT."""
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                conn.execute(statement)

    def expire_records(self, conn: sqlite3.Connection | None = None) -> None:
        own = conn is None
        context = self.transaction() if own else None
        if own:
            with context as active:
                self.expire_records(active)
            return
        assert conn is not None
        now = now_ts()
        conn.execute(
            """
            UPDATE trusted_device
            SET status='revoked', revoked_at=COALESCE(revoked_at, ?),
                revoked_by='system', revoke_reason='trust expired'
            WHERE status='active' AND trust_expires_at IS NOT NULL AND trust_expires_at<=?
            """,
            (now, now),
        )
        conn.execute(
            """
            UPDATE lease_record
            SET status='releasing', release_reason=CASE
                WHEN release_reason='' OR release_reason IS NULL THEN 'device trust expired; recovery required'
                ELSE release_reason END,
                next_reconcile_at=0
            WHERE status IN ('activating','active','releasing') AND device_id IN (
                SELECT device_id FROM trusted_device
                WHERE status!='active' OR (trust_expires_at IS NOT NULL AND trust_expires_at<=?)
            )
            """,
            (now,),
        )
        conn.execute(
            """
            UPDATE lease_record
            SET status='releasing', release_reason=CASE
                WHEN release_reason='' OR release_reason IS NULL THEN 'grant expired or revoked; recovery required'
                ELSE release_reason END,
                next_reconcile_at=0
            WHERE status IN ('activating','active','releasing') AND grant_id IN (
                SELECT grant_id FROM grant_record
                WHERE revoked_at IS NOT NULL OR expires_at<=?
            )
            """,
            (now,),
        )
        conn.execute(
            "UPDATE approval_request SET status='expired' WHERE status='pending' AND expires_at<=?",
            (now,),
        )
        conn.execute(
            """
            UPDATE trusted_device
            SET status='revoked', revoked_at=COALESCE(revoked_at, ?),
                revoked_by='system', revoke_reason='registration approval expired'
            WHERE status='pending' AND device_id IN (
                SELECT device_id FROM approval_request
                WHERE approval_type='device_registration' AND status='expired'
            )
            """,
            (now,),
        )
        conn.execute(
            """
            UPDATE token_record
            SET revoked_at=COALESCE(revoked_at, ?), revoked_by='system', revoke_reason='device trust expired'
            WHERE revoked_at IS NULL AND device_id IN (
                SELECT device_id FROM trusted_device
                WHERE status!='active' OR (trust_expires_at IS NOT NULL AND trust_expires_at<=?)
            )
            """,
            (now, now),
        )

    def fetch_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self.read() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def fetch_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.read() as conn:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]

    def write_api_audit(self, **fields: Any) -> None:
        raw = fields.pop("raw", None)
        values = {
            "created_at": now_ts(),
            "request_id": "",
            "actor_type": "unknown",
            "actor_name": "",
            "device_id": "",
            "source_id": "",
            "client_name": "",
            "grant_id": "",
            "token_id": "",
            "target_app": "",
            "capability": "",
            "method": "",
            "path": "",
            "upstream_path": "",
            "status_code": None,
            "success": False,
            "duration_ms": None,
            "error_code": "",
            "risk_level": "",
            "client_ip": "",
            "user_agent": "",
            "raw_json": json_dumps(redact_metadata(raw or {})),
        }
        values.update(fields)
        values["success"] = 1 if values["success"] else 0
        columns = tuple(values)
        placeholders = ",".join("?" for _ in columns)
        with self.transaction() as conn:
            conn.execute(
                f"INSERT INTO api_audit ({','.join(columns)}) VALUES ({placeholders})",
                tuple(values[column] for column in columns),
            )

    def registry_states(self) -> dict[str, dict[str, Any]]:
        return {
            str(row["app_id"]): row
            for row in self.fetch_all("SELECT * FROM app_registry_state ORDER BY app_id")
        }

    def set_registry_state(
        self,
        *,
        app_id: str,
        enabled: bool,
        manifest_revision: str,
        updated_by: str,
        disabled_reason: str = "",
    ) -> dict[str, Any]:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO app_registry_state (
                    app_id, enabled, manifest_revision, updated_at, updated_by, disabled_reason
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(app_id) DO UPDATE SET
                    enabled=excluded.enabled,
                    manifest_revision=excluded.manifest_revision,
                    updated_at=excluded.updated_at,
                    updated_by=excluded.updated_by,
                    disabled_reason=excluded.disabled_reason
                """,
                (
                    app_id,
                    1 if enabled else 0,
                    manifest_revision,
                    now_ts(),
                    updated_by[:120],
                    disabled_reason[:1000],
                ),
            )
            row = conn.execute(
                "SELECT * FROM app_registry_state WHERE app_id=?", (app_id,)
            ).fetchone()
        return dict(row)

    def get_system_state(self, key: str, default: Any = None) -> Any:
        row = self.fetch_one("SELECT value_json FROM system_state WHERE state_key=?", (key,))
        return json_loads(row["value_json"], default) if row else default

    def set_system_state(self, key: str, value: Any) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO system_state(state_key, value_json, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(state_key) DO UPDATE SET
                    value_json=excluded.value_json, updated_at=excluded.updated_at
                """,
                (key[:160], json_dumps(redact_metadata(value)), now_ts()),
            )

    def prune(self, *, audit_retention_days: int, notification_retention_days: int) -> dict[str, int]:
        now = now_ts()
        audit_cutoff = now - max(1, audit_retention_days) * 86400
        notification_cutoff = now - max(1, notification_retention_days) * 86400
        with self.transaction() as conn:
            audit_count = conn.execute(
                "DELETE FROM api_audit WHERE created_at<?", (audit_cutoff,)
            ).rowcount
            notification_count = conn.execute(
                "DELETE FROM notification_record WHERE created_at<?", (notification_cutoff,)
            ).rowcount
        return {"audit": int(audit_count), "notifications": int(notification_count)}

    def integrity_report(self) -> dict[str, Any]:
        with self.read() as conn:
            integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_key_errors = [dict(row) for row in conn.execute("PRAGMA foreign_key_check").fetchall()]
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        return {
            "ok": integrity == "ok" and not foreign_key_errors and version == SCHEMA_VERSION,
            "integrity": integrity,
            "foreign_key_errors": foreign_key_errors,
            "schema_version": version,
        }
