from __future__ import annotations

import asyncio
import secrets
from pathlib import Path
from typing import Any

from app.config.schema import NotificationConfig
from app.security.db import SecurityStore, json_dumps, json_loads, now_ts, redact_metadata


def _clean_text(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").replace("\x00", " ").split())
    return text[:limit]


class NotificationService:
    """Durable notification outbox with a fixed-argv Local Mailer boundary."""

    def __init__(self, store: SecurityStore, config: NotificationConfig, logger) -> None:
        self.store = store
        self.config = config
        self.logger = logger
        self._suppress_obsolete_tunnel_mail()

    def _suppress_obsolete_tunnel_mail(self) -> int:
        """Prevent pre-upgrade transient tunnel messages from being retried as email."""
        suppressed = 0
        with self.store.transaction() as conn:
            rows = conn.execute(
                """
                SELECT notification_id, category, metadata_json
                FROM notification_record
                WHERE status IN ('queued','failed','sending')
                  AND category IN ('tunnel_failure','tunnel_recovery')
                """
            ).fetchall()
            for row in rows:
                metadata = json_loads(row["metadata_json"], {})
                event_type = str(metadata.get("event_type", "")) if isinstance(metadata, dict) else ""
                obsolete = row["category"] == "tunnel_recovery" or (
                    row["category"] == "tunnel_failure" and event_type == "tunnel_unhealthy"
                )
                if not obsolete:
                    continue
                cursor = conn.execute(
                    """
                    UPDATE notification_record
                    SET status='in_app', email_requested=0, next_attempt_at=0,
                        last_error='suppressed by delayed tunnel alert policy'
                    WHERE notification_id=?
                    """,
                    (row["notification_id"],),
                )
                suppressed += int(cursor.rowcount)
        return suppressed

    def enqueue(
        self,
        *,
        category: str,
        severity: str,
        title: str,
        message: str,
        dedupe_key: str = "",
        email_requested: bool = True,
        metadata: dict[str, Any] | None = None,
        force: bool = False,
        once: bool = False,
    ) -> dict[str, Any]:
        category = _clean_text(category, 80).lower() or "system"
        severity = severity if severity in {"info", "success", "warning", "danger"} else "info"
        title = _clean_text(title, 180) or "Home Gateway 通知"
        message = _clean_text(message, 4000)
        dedupe_key = _clean_text(dedupe_key, 240)
        now = now_ts()
        wants_email = bool(
            email_requested
            and self.config.enabled
            and category in set(self.config.send_categories)
        )
        with self.store.transaction() as conn:
            if dedupe_key and not force:
                existing = conn.execute(
                    """
                    SELECT * FROM notification_record
                    WHERE dedupe_key=? AND (? OR last_occurrence_at>=?)
                    ORDER BY last_occurrence_at DESC LIMIT 1
                    """,
                    (dedupe_key, 1 if once else 0, now - self.config.cooldown_seconds),
                ).fetchone()
                if existing is not None:
                    conn.execute(
                        """
                        UPDATE notification_record
                        SET last_occurrence_at=?, repeat_count=repeat_count+1,
                            severity=?, title=?, message=?, metadata_json=?
                        WHERE notification_id=?
                        """,
                        (
                            now,
                            severity,
                            title,
                            message,
                            json_dumps(redact_metadata(metadata or {})),
                            existing["notification_id"],
                        ),
                    )
                    row = conn.execute(
                        "SELECT * FROM notification_record WHERE notification_id=?",
                        (existing["notification_id"],),
                    ).fetchone()
                    return self.public(dict(row), deduplicated=True)

            notification_id = f"ntf_{secrets.token_urlsafe(18)}"
            status = "queued" if wants_email else "in_app"
            conn.execute(
                """
                INSERT INTO notification_record (
                    notification_id, category, severity, title, message, dedupe_key,
                    status, email_requested, created_at, last_occurrence_at,
                    next_attempt_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    notification_id,
                    category,
                    severity,
                    title,
                    message,
                    dedupe_key,
                    status,
                    1 if email_requested else 0,
                    now,
                    now,
                    now if wants_email else 0,
                    json_dumps(redact_metadata(metadata or {})),
                ),
            )
            row = conn.execute(
                "SELECT * FROM notification_record WHERE notification_id=?", (notification_id,)
            ).fetchone()
        return self.public(dict(row))

    @staticmethod
    def public(row: dict[str, Any], *, deduplicated: bool = False) -> dict[str, Any]:
        item = dict(row)
        item["email_requested"] = bool(item.get("email_requested"))
        item["metadata"] = json_loads(item.pop("metadata_json", "{}"), {})
        item["deduplicated"] = deduplicated
        return item

    def list(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        category: str = "",
        status: str = "",
        unread_only: bool = False,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if category:
            clauses.append("category=?")
            params.append(category[:80])
        if status:
            clauses.append("status=?")
            params.append(status[:24])
        if unread_only:
            clauses.append("read_at IS NULL")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_page = max(1, int(page))
        safe_size = max(1, min(int(page_size), 200))
        total_row = self.store.fetch_one(
            f"SELECT COUNT(*) AS count FROM notification_record{where}", tuple(params)
        )
        rows = self.store.fetch_all(
            f"""
            SELECT * FROM notification_record{where}
            ORDER BY last_occurrence_at DESC, notification_id DESC LIMIT ? OFFSET ?
            """,
            (*params, safe_size, (safe_page - 1) * safe_size),
        )
        total = int((total_row or {}).get("count", 0))
        return {
            "items": [self.public(row) for row in rows],
            "page": safe_page,
            "page_size": safe_size,
            "total": total,
            "total_pages": max(1, (total + safe_size - 1) // safe_size),
            "unread": self.unread_count(),
        }

    def unread_count(self) -> int:
        row = self.store.fetch_one(
            "SELECT COUNT(*) AS count FROM notification_record WHERE read_at IS NULL"
        )
        return int((row or {}).get("count", 0))

    def mark_read(self, notification_id: str | None = None) -> int:
        now = now_ts()
        with self.store.transaction() as conn:
            if notification_id:
                cursor = conn.execute(
                    "UPDATE notification_record SET read_at=COALESCE(read_at, ?) WHERE notification_id=?",
                    (now, notification_id),
                )
            else:
                cursor = conn.execute(
                    "UPDATE notification_record SET read_at=? WHERE read_at IS NULL", (now,)
                )
            return int(cursor.rowcount)

    def _claim_next(self) -> dict[str, Any] | None:
        now = now_ts()
        with self.store.transaction() as conn:
            # A crash after claim should not strand a message forever.
            conn.execute(
                """
                UPDATE notification_record
                SET status='failed', next_attempt_at=?, last_error='worker interrupted'
                WHERE status='sending' AND next_attempt_at<?
                """,
                (now, now - 300),
            )
            row = conn.execute(
                """
                SELECT * FROM notification_record
                WHERE status IN ('queued','failed') AND next_attempt_at<=? AND attempts<?
                ORDER BY created_at, notification_id LIMIT 1
                """,
                (now, self.config.max_attempts),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """
                UPDATE notification_record
                SET status='sending', attempts=attempts+1, next_attempt_at=?
                WHERE notification_id=?
                """,
                (now + 300, row["notification_id"]),
            )
            claimed = conn.execute(
                "SELECT * FROM notification_record WHERE notification_id=?",
                (row["notification_id"],),
            ).fetchone()
        return dict(claimed)

    async def worker_once(self) -> bool:
        row = self._claim_next()
        if row is None:
            return False
        notification_id = str(row["notification_id"])
        command = [
            self.config.python_executable,
            self.config.command,
            "send",
            "--to",
            self.config.recipient,
            "--prefix",
            self.config.subject_prefix,
            "--subject",
            _clean_text(row["title"], 180),
            "--body",
            _clean_text(row["message"], 4000),
        ]
        error = ""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            if process.returncode != 0:
                detail = (stderr or stdout).decode("utf-8", errors="replace")
                error = _clean_text(detail, 1000) or f"Local Mailer exited {process.returncode}"
        except asyncio.TimeoutError:
            if "process" in locals():
                process.kill()
                await process.communicate()
            error = "Local Mailer timed out after 60 seconds"
        except (OSError, ValueError) as exc:
            error = _clean_text(exc, 1000)

        now = now_ts()
        with self.store.transaction() as conn:
            current = conn.execute(
                "SELECT attempts FROM notification_record WHERE notification_id=?",
                (notification_id,),
            ).fetchone()
            attempts = int(current["attempts"]) if current else self.config.max_attempts
            if not error:
                conn.execute(
                    """
                    UPDATE notification_record
                    SET status='sent', sent_at=?, next_attempt_at=0, last_error=''
                    WHERE notification_id=?
                    """,
                    (now, notification_id),
                )
            else:
                delay = min(
                    self.config.retry_backoff_seconds * (2 ** max(0, attempts - 1)), 3600
                )
                conn.execute(
                    """
                    UPDATE notification_record
                    SET status='failed', next_attempt_at=?, last_error=?
                    WHERE notification_id=?
                    """,
                    (now + delay, error, notification_id),
                )
                self.logger.warning("Notification %s failed: %s", notification_id, error)
        return True

    def health(self) -> dict[str, Any]:
        counts = {
            str(row["status"]): int(row["count"])
            for row in self.store.fetch_all(
                "SELECT status, COUNT(*) AS count FROM notification_record GROUP BY status"
            )
        }
        return {
            "enabled": self.config.enabled,
            "provider": self.config.provider,
            "recipient": self.config.recipient,
            "python_available": Path(self.config.python_executable).is_file(),
            "mailer_available": Path(self.config.command).is_file(),
            "counts": counts,
            "unread": self.unread_count(),
        }

    def handle_event(self, event: dict[str, Any]) -> None:
        event_type = str(event.get("event_type", ""))
        app_id = _clean_text(event.get("app_id", ""), 64)
        resource = _clean_text(event.get("resource_key", ""), 128)
        reason = _clean_text(event.get("reason") or event.get("message") or "", 1000)
        outage_seconds = max(0, int(event.get("outage_seconds", 0) or 0))
        outage_minutes = max(60, outage_seconds // 60) if outage_seconds else 60
        mapping: dict[str, tuple[str, str, str, str, bool]] = {
            "app_marked_failed": (
                "app_failure", "danger", f"应用 {app_id or 'unknown'} 异常", reason or "应用启动或健康检查失败。", True
            ),
            "app_recovered": (
                "app_recovery", "success", f"应用 {app_id or 'unknown'} 已恢复", "应用已通过健康检查并恢复服务。", True
            ),
            "app_auto_restarted": (
                "app_recovery", "success", f"应用 {app_id or 'unknown'} 已自动恢复", "自动重启后已恢复服务。", True
            ),
            "app_health_recovered": (
                "app_recovery", "success", f"应用 {app_id or 'unknown'} 健康检查已恢复", "应用再次通过健康检查。", True
            ),
            "lease_reconcile_failed": (
                "lease_failure", "danger", f"租约资源 {resource or 'unknown'} 恢复失败", reason or "资源状态尚未安全释放。", True
            ),
            "lease_recovered": (
                "lease_recovery", "success", f"租约资源 {resource or 'unknown'} 已恢复", "租约资源已回到预期状态。", True
            ),
            "tunnel_unhealthy": (
                "tunnel_failure", "danger", "公网隧道暂时不可用", reason or "连续健康检查未通过。", False
            ),
            "tunnel_recovered": (
                "tunnel_recovery", "success", "公网隧道已恢复", "公网健康检查已恢复正常。", False
            ),
            "tunnel_recovery_failed": (
                "tunnel_failure",
                "danger",
                "公网隧道恢复失败（已持续 1 小时）",
                f"公网隧道已连续异常 {outage_minutes} 分钟，自动恢复仍未成功。最近错误：{reason or '未知'}",
                True,
            ),
        }
        selected = mapping.get(event_type)
        if selected is None:
            return
        category, severity, title, message, email_requested = selected
        subject = app_id or resource or "gateway"
        once = False
        if event_type == "tunnel_recovery_failed":
            failure_started_at = max(0, int(event.get("failure_started_at", 0) or 0))
            subject = f"gateway:{failure_started_at or 'current'}"
            once = True
        self.enqueue(
            category=category,
            severity=severity,
            title=title,
            message=message,
            dedupe_key=f"{category}:{subject}",
            email_requested=email_requested,
            metadata={
                "event_type": event_type,
                "app_id": app_id,
                "resource_key": resource,
                "failure_started_at": event.get("failure_started_at", 0),
                "outage_seconds": outage_seconds,
                "consecutive_failures": event.get("consecutive_failures", 0),
            },
            once=once,
        )

    def scan_pending_approvals(self) -> int:
        rows = self.store.fetch_all(
            """
            SELECT approval_id, approval_type, target_app, reason, expires_at
            FROM approval_request WHERE status='pending' ORDER BY created_at
            """
        )
        for row in rows:
            self.enqueue(
                category="approval_pending",
                severity="warning",
                title="有新的访问审批待处理",
                message=_clean_text(row.get("reason") or row.get("approval_type"), 1000),
                dedupe_key=f"approval_pending:{row['approval_id']}",
                metadata={
                    "approval_id": row["approval_id"],
                    "target_app": row["target_app"],
                    "expires_at": row["expires_at"],
                },
                once=True,
            )
        return len(rows)
