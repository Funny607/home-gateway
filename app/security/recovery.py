from __future__ import annotations

import secrets
import sqlite3
from typing import Any

from app.security.db import SecurityStore, now_ts
from app.security.service import SecurityError


def _code() -> str:
    raw = secrets.token_hex(12).upper()
    return "RCV-" + "-".join(raw[index:index + 4] for index in range(0, len(raw), 4))


class RecoveryService:
    """Constrained emergency access. It never creates an admin browser session."""

    def __init__(self, store: SecurityStore, *, verifier_secret: str, token_ttl_seconds: int = 900) -> None:
        self.store = store
        self.verifier_secret = verifier_secret
        self.token_ttl_seconds = max(60, min(int(token_ttl_seconds), 1800))

    def generate_codes(self, *, count: int = 8) -> list[str]:
        count = max(4, min(int(count), 20))
        codes = [_code() for _ in range(count)]
        now = now_ts()
        with self.store.transaction() as conn:
            generation_row = conn.execute(
                "SELECT COALESCE(MAX(generation), 0) + 1 FROM recovery_code"
            ).fetchone()
            generation = int(generation_row[0])
            conn.execute(
                "UPDATE recovery_code SET revoked_at=COALESCE(revoked_at, ?) WHERE used_at IS NULL",
                (now,),
            )
            for code in codes:
                conn.execute(
                    "INSERT INTO recovery_code(code_id, code_hash, created_at, generation) VALUES (?, ?, ?, ?)",
                    (f"rcv_{secrets.token_urlsafe(12)}", self.store.digest("recovery-code", code), now, generation),
                )
        return codes

    def status(self) -> dict[str, Any]:
        active = self.store.fetch_one(
            "SELECT COUNT(*) AS count FROM recovery_code WHERE used_at IS NULL AND revoked_at IS NULL"
        )
        emergency = self.store.fetch_one(
            "SELECT COUNT(*) AS count FROM emergency_token WHERE revoked_at IS NULL AND expires_at>?",
            (now_ts(),),
        )
        disabled = bool(self.store.get_system_state("external_api_disabled", False))
        return {
            "active_recovery_codes": int((active or {}).get("count", 0)),
            "active_emergency_tokens": int((emergency or {}).get("count", 0)),
            "external_api_disabled": disabled,
            "configured": bool(self.verifier_secret),
        }

    def activate(self, *, recovery_code: str, reason: str = "") -> dict[str, Any]:
        if not self.verifier_secret:
            raise SecurityError(503, "breakglass_unavailable", "break-glass verifier is not configured")
        now = now_ts()
        with self.store.transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM recovery_code WHERE used_at IS NULL AND revoked_at IS NULL"
            ).fetchall()
            matched: sqlite3.Row | None = None
            for row in rows:
                if self.store.verify_digest("recovery-code", recovery_code.strip().upper(), row["code_hash"]):
                    matched = row
                    break
            if matched is None:
                raise SecurityError(403, "recovery_code_invalid", "recovery code is invalid or already used")
            used = conn.execute(
                "UPDATE recovery_code SET used_at=?, used_by='break-glass' WHERE code_id=? AND used_at IS NULL AND revoked_at IS NULL",
                (now, matched["code_id"]),
            ).rowcount
            if used != 1:
                raise SecurityError(409, "recovery_code_race", "recovery code was consumed concurrently")
            token_id = f"bgt_{secrets.token_urlsafe(18)}"
            secret = secrets.token_urlsafe(32)
            token = f"{token_id}.{secret}"
            conn.execute(
                "INSERT INTO emergency_token(token_id, token_hash, issued_at, expires_at, reason) VALUES (?, ?, ?, ?, ?)",
                (token_id, self.store.digest("emergency-token", token), now, now + self.token_ttl_seconds, reason[:500]),
            )
        self._audit(
            actor=f"recovery-code:{matched['code_id']}",
            path="/api/emergency/v1/activate",
            raw={"reason": reason[:500], "expires_at": now + self.token_ttl_seconds},
        )
        return {
            "emergency_token": token, "expires_at": now + self.token_ttl_seconds,
            "allowed_actions": ["status", "create-backup", "disable-external-api", "revoke-all-access"],
            "warning": "token is shown once and cannot create an admin session",
        }

    def verify_token(self, token: str) -> dict[str, Any]:
        if not token or "." not in token or len(token) > 512:
            raise SecurityError(401, "invalid_emergency_token", "emergency token is invalid")
        token_id = token.split(".", 1)[0]
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM emergency_token WHERE token_id=?", (token_id,)).fetchone()
            now = now_ts()
            if row is None or not self.store.verify_digest("emergency-token", token, row["token_hash"]):
                raise SecurityError(401, "invalid_emergency_token", "emergency token is invalid")
            if row["revoked_at"] is not None or int(row["expires_at"]) <= now:
                raise SecurityError(401, "emergency_token_expired", "emergency token is expired or revoked")
            conn.execute("UPDATE emergency_token SET last_used_at=? WHERE token_id=?", (now, token_id))
            return {"token_id": token_id, "expires_at": row["expires_at"]}

    def revoke_all_external_access(self, *, actor: str) -> dict[str, int]:
        now = now_ts()
        with self.store.transaction() as conn:
            grants = conn.execute(
                "UPDATE grant_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='break-glass revoke all' WHERE revoked_at IS NULL",
                (now, actor),
            ).rowcount
            tokens = conn.execute(
                "UPDATE token_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='break-glass revoke all' WHERE revoked_at IS NULL",
                (now, actor),
            ).rowcount
            approvals = conn.execute(
                "UPDATE approval_request SET status='cancelled', denied_at=?, denied_by=? WHERE status='pending'",
                (now, actor),
            ).rowcount
            leases = conn.execute(
                "UPDATE lease_record SET status='releasing', release_reason='break-glass revoke all; recovery required' WHERE status IN ('activating','active','releasing')",
            ).rowcount
        result = {"grants_revoked": grants, "tokens_revoked": tokens, "approvals_cancelled": approvals, "leases_releasing": leases}
        self._audit(actor=actor, path="/api/emergency/v1/revoke-all-access", raw=result)
        return result

    def set_external_api_disabled(self, disabled: bool, *, actor: str = "administrator") -> None:
        self.store.set_system_state("external_api_disabled", bool(disabled))
        self._audit(
            actor=actor,
            path="/api/emergency/v1/disable-external-api" if disabled else "/dashboard/operations/external-api/enable",
            raw={"disabled": bool(disabled)},
        )

    def external_api_disabled(self) -> bool:
        return bool(self.store.get_system_state("external_api_disabled", False))

    def revoke_emergency_tokens(self) -> int:
        with self.store.transaction() as conn:
            return conn.execute(
                "UPDATE emergency_token SET revoked_at=? WHERE revoked_at IS NULL",
                (now_ts(),),
            ).rowcount

    def _audit(self, *, actor: str, path: str, raw: dict[str, Any]) -> None:
        self.store.write_api_audit(
            request_id=f"emergency-{secrets.token_hex(8)}",
            actor_type="breakglass",
            actor_name=actor[:120],
            method="POST",
            path=path,
            status_code=200,
            success=True,
            risk_level="critical",
            raw=raw,
        )
