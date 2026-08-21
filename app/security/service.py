from __future__ import annotations

import secrets
import sqlite3
import string
import re
import hmac
from typing import Any

from app.security.actions import canonical_action, validate_payload_preview
from app.security.db import SecurityStore, json_dumps, json_loads, now_ts
from app.security.policy import PolicyDecision, PolicyDenied, PolicyEngine, TRUST_RANK
from app.security.totp import verify as verify_totp


class SecurityError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def _new_secret(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def _human_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    raw = "".join(secrets.choice(alphabet) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def _row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


class SecurityService:
    def __init__(
        self,
        store: SecurityStore,
        policy: PolicyEngine,
        *,
        totp_secret: str = "",
        desktop_approver_secret: str = "",
    ) -> None:
        self.store = store
        self.policy = policy
        self.totp_secret = totp_secret
        self.desktop_approver_secret = desktop_approver_secret

    @staticmethod
    def public_device(data: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any] | None:
        if data is None:
            return None
        row = dict(data)
        for key in ("secret_hash", "raw_json", "public_key"):
            row.pop(key, None)
        return row

    @staticmethod
    def public_approval(data: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any] | None:
        if data is None:
            return None
        row = dict(data)
        row["requested_capabilities"] = json_loads(row.get("requested_capabilities"), [])
        row["required_approval_methods"] = json_loads(row.get("required_approval_methods"), [])
        row["policy"] = json_loads(row.pop("policy_json", "{}"), {})
        row.pop("request_code_hash", None)
        row.pop("raw_json", None)
        return row

    def _route_allows(self, app_id: str, capability_id: str, method: str, path: str) -> bool:
        capability = self.policy.capability(app_id, capability_id)
        path_only = path.split("?", 1)[0]
        for route in capability.routes:
            if route.method != method:
                continue
            if route.path is not None and path_only == route.path:
                return True
            if route.path_prefix is not None and (
                path_only == route.path_prefix or path_only.startswith(route.path_prefix + "/")
            ):
                return True
            if route.path_regex is not None and re.fullmatch(route.path_regex, path_only):
                return True
        return False

    @staticmethod
    def public_grant(data: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any] | None:
        if data is None:
            return None
        row = dict(data)
        row["capabilities"] = json_loads(row.get("capabilities"), [])
        row["policy"] = json_loads(row.pop("policy_json", "{}"), {})
        row.pop("raw_json", None)
        return row

    @staticmethod
    def public_token(data: dict[str, Any] | sqlite3.Row | None) -> dict[str, Any] | None:
        if data is None:
            return None
        row = dict(data)
        row["capabilities"] = json_loads(row.get("capabilities"), [])
        row.pop("token_hash", None)
        row.pop("raw_json", None)
        return row

    def _authenticate_device(
        self,
        conn: sqlite3.Connection,
        *,
        device_id: str,
        device_secret: str,
        allow_pending: bool = False,
        client_ip: str = "",
        user_agent: str = "",
    ) -> sqlite3.Row:
        self.store.expire_records(conn)
        row = conn.execute("SELECT * FROM trusted_device WHERE device_id=?", (device_id,)).fetchone()
        if row is None or not self.store.verify_digest("device", device_secret, row["secret_hash"]):
            raise SecurityError(401, "invalid_device_credentials", "device credentials are invalid")
        if row["status"] == "pending" and allow_pending:
            return row
        if row["status"] != "active":
            raise SecurityError(403, "device_not_active", "device is not active")
        now = now_ts()
        if row["trust_expires_at"] is not None and int(row["trust_expires_at"]) <= now:
            conn.execute(
                "UPDATE trusted_device SET status='revoked', revoked_at=?, revoked_by='system', revoke_reason='trust expired' WHERE device_id=?",
                (now, device_id),
            )
            self.store.expire_records(conn)
            raise SecurityError(403, "device_trust_expired", "device trust has expired")
        conn.execute(
            "UPDATE trusted_device SET last_seen_at=?, last_ip=?, user_agent=? WHERE device_id=?",
            (now, client_ip[:128], user_agent[:512], device_id),
        )
        return row

    def authenticate_device(
        self,
        *,
        device_id: str,
        device_secret: str,
        allow_pending: bool = False,
        client_ip: str = "",
        user_agent: str = "",
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            return dict(
                self._authenticate_device(
                    conn,
                    device_id=device_id,
                    device_secret=device_secret,
                    allow_pending=allow_pending,
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
            )

    def register_device(
        self,
        *,
        device_name: str,
        device_type: str,
        source_id: str = "",
        public_key: str = "",
        client_ip: str = "",
        user_agent: str = "",
    ) -> dict[str, Any]:
        device_name = device_name.strip()
        device_type = device_type.strip().lower()
        if not 1 <= len(device_name) <= 120:
            raise SecurityError(422, "invalid_device_name", "device_name must contain 1..120 characters")
        if not 1 <= len(device_type) <= 64:
            raise SecurityError(422, "invalid_device_type", "device_type must contain 1..64 characters")
        if len(public_key) > 8192:
            raise SecurityError(422, "public_key_too_large", "public_key is too large")
        device_id = _new_id("dev")
        device_secret = _new_secret("gwd")
        approval_id = _new_id("apr")
        request_code = _human_code()
        now = now_ts()
        expires_at = now + 900
        approval_methods = ["web-admin"]
        if self.totp_secret:
            approval_methods.append("totp")
        if self.desktop_approver_secret:
            approval_methods.append("desktop")
        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO trusted_device (
                    device_id, secret_hash, device_name, device_type, source_id, public_key,
                    trust_level, status, created_at, last_ip, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, 'untrusted', 'pending', ?, ?, ?)
                """,
                (
                    device_id,
                    self.store.digest("device", device_secret),
                    device_name,
                    device_type,
                    source_id[:120],
                    public_key,
                    now,
                    client_ip[:128],
                    user_agent[:512],
                ),
            )
            conn.execute(
                """
                INSERT INTO approval_request (
                    approval_id, approval_type, device_id, risk_level, status,
                    requested_ttl_seconds, required_trust_level, required_approval_methods,
                    request_code_hash, reason, created_at, expires_at, policy_json
                ) VALUES (?, 'device_registration', ?, 'medium', 'pending', 0, 'paired', ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    device_id,
                    json_dumps(approval_methods),
                    self.store.digest("request-code", request_code),
                    f"Register {device_name}",
                    now,
                    expires_at,
                    json_dumps({"requested_trust_level": "paired"}),
                ),
            )
        return {
            "device_id": device_id,
            "device_secret": device_secret,
            "approval_id": approval_id,
            "request_code": request_code,
            "status": "pending",
            "expires_at": expires_at,
            "warning": "device_secret is shown once; store it securely",
        }

    def device_registration_status(self, *, device_id: str, device_secret: str) -> dict[str, Any]:
        with self.store.transaction() as conn:
            device = self._authenticate_device(
                conn, device_id=device_id, device_secret=device_secret, allow_pending=True
            )
            approval = conn.execute(
                "SELECT * FROM approval_request WHERE device_id=? AND approval_type='device_registration' ORDER BY created_at DESC LIMIT 1",
                (device_id,),
            ).fetchone()
            return {
                "device": self.public_device(device),
                "approval": self.public_approval(approval),
            }

    def _device_by_id_active(self, conn: sqlite3.Connection, device_id: str) -> sqlite3.Row:
        self.store.expire_records(conn)
        row = conn.execute("SELECT * FROM trusted_device WHERE device_id=?", (device_id,)).fetchone()
        if row is None:
            raise SecurityError(404, "device_not_found", "device was not found")
        if row["status"] != "active":
            raise SecurityError(409, "device_not_active", "device is not active")
        if row["trust_expires_at"] is not None and int(row["trust_expires_at"]) <= now_ts():
            raise SecurityError(409, "device_trust_expired", "device trust has expired")
        return row

    def _insert_grant(
        self,
        conn: sqlite3.Connection,
        *,
        grant_id: str,
        device_id: str,
        decision: PolicyDecision,
        actor: str,
        approval_method: str,
        approval_id: str | None,
    ) -> sqlite3.Row:
        now = now_ts()
        conn.execute(
            """
            INSERT INTO grant_record (
                grant_id, device_id, target_app, capabilities, grant_type, risk_level,
                required_trust_level, created_at, expires_at, approved_by, approval_method,
                approval_id, policy_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                grant_id,
                device_id,
                decision.target_app,
                json_dumps(list(decision.capabilities)),
                decision.grant_type,
                decision.risk_level,
                decision.required_trust_level,
                now,
                now + decision.ttl_seconds,
                actor,
                approval_method,
                approval_id,
                json_dumps(decision.to_dict()),
            ),
        )
        return conn.execute("SELECT * FROM grant_record WHERE grant_id=?", (grant_id,)).fetchone()

    def _create_grant_request(
        self,
        conn: sqlite3.Connection,
        *,
        device: sqlite3.Row,
        decision: PolicyDecision,
        reason: str,
    ) -> dict[str, Any]:
        grant_id = _new_id("grt")
        if not decision.approval_required:
            row = self._insert_grant(
                conn,
                grant_id=grant_id,
                device_id=device["device_id"],
                decision=decision,
                actor="policy-engine",
                approval_method="automatic",
                approval_id=None,
            )
            return {"status": "granted", "grant": self.public_grant(row)}

        approval_id = _new_id("apr")
        request_code = _human_code()
        now = now_ts()
        approval_expires_at = now + min(900, decision.ttl_seconds)
        conn.execute(
            """
            INSERT INTO approval_request (
                approval_id, approval_type, target_app, device_id, pending_grant_id,
                requested_capabilities, risk_level, status, requested_ttl_seconds,
                required_trust_level, required_approval_methods, request_code_hash,
                reason, created_at, expires_at, policy_json
            ) VALUES (?, 'grant', ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval_id,
                decision.target_app,
                device["device_id"],
                grant_id,
                json_dumps(list(decision.capabilities)),
                decision.risk_level,
                decision.ttl_seconds,
                decision.required_trust_level,
                json_dumps(list(decision.approval_methods)),
                self.store.digest("request-code", request_code),
                reason[:1000],
                now,
                approval_expires_at,
                json_dumps(decision.to_dict()),
            ),
        )
        return {
            "status": "pending_approval",
            "approval_id": approval_id,
            "request_code": request_code,
            "expires_at": approval_expires_at,
            "policy": decision.to_dict(),
        }

    def request_grant(
        self,
        *,
        device_id: str,
        device_secret: str,
        target_app: str,
        capabilities: list[str],
        requested_ttl_seconds: int,
        grant_type: str,
        reason: str,
        client_ip: str = "",
        user_agent: str = "",
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            device = self._authenticate_device(
                conn,
                device_id=device_id,
                device_secret=device_secret,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            try:
                decision = self.policy.evaluate_grant(
                    app_id=target_app,
                    capability_ids=capabilities,
                    device_trust_level=device["trust_level"],
                    requested_ttl_seconds=requested_ttl_seconds,
                    grant_type=grant_type,
                )
            except PolicyDenied as exc:
                raise SecurityError(403, exc.code, str(exc)) from exc
            return self._create_grant_request(
                conn, device=device, decision=decision, reason=reason
            )

    def admin_request_grant(
        self,
        *,
        device_id: str,
        target_app: str,
        capabilities: list[str],
        requested_ttl_seconds: int,
        grant_type: str,
        reason: str,
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            device = self._device_by_id_active(conn, device_id)
            try:
                decision = self.policy.evaluate_grant(
                    app_id=target_app,
                    capability_ids=capabilities,
                    device_trust_level=device["trust_level"],
                    requested_ttl_seconds=requested_ttl_seconds,
                    grant_type=grant_type,
                )
            except PolicyDenied as exc:
                raise SecurityError(403, exc.code, str(exc)) from exc
            return self._create_grant_request(
                conn, device=device, decision=decision, reason=reason
            )

    def grant_request_status(
        self, *, approval_id: str, device_id: str, device_secret: str
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            self._authenticate_device(
                conn, device_id=device_id, device_secret=device_secret, allow_pending=True
            )
            approval = conn.execute(
                "SELECT * FROM approval_request WHERE approval_id=? AND device_id=?",
                (approval_id, device_id),
            ).fetchone()
            if approval is None:
                raise SecurityError(404, "approval_not_found", "approval request was not found")
            grant = None
            if approval["status"] == "approved":
                grant = conn.execute(
                    "SELECT * FROM grant_record WHERE approval_id=?", (approval_id,)
                ).fetchone()
            return {
                "approval": self.public_approval(approval),
                "grant": self.public_grant(grant),
            }

    def _current_decision_for_grant(
        self, grant: sqlite3.Row, device: sqlite3.Row
    ) -> PolicyDecision:
        snapshot = json_loads(grant["policy_json"], {})
        try:
            decision = self.policy.revalidate_snapshot(
                snapshot, device_trust_level=device["trust_level"]
            )
        except PolicyDenied as exc:
            raise SecurityError(403, "policy_changed", str(exc)) from exc
        original_ttl = int(snapshot.get("ttl_seconds", 0) or 0)
        if decision.ttl_seconds < original_ttl:
            raise SecurityError(403, "policy_changed", "grant no longer satisfies current TTL policy")
        return decision

    def request_action_approval(
        self,
        *,
        device_id: str,
        device_secret: str,
        grant_id: str,
        capability: str,
        method: str,
        path: str,
        body_sha256: str,
        payload_preview: str = "",
        reason: str = "",
    ) -> dict[str, Any]:
        try:
            method, path, body_sha256, action_hash = canonical_action(method, path, body_sha256)
        except ValueError as exc:
            raise SecurityError(422, "invalid_action", str(exc)) from exc
        now = now_ts()
        with self.store.transaction() as conn:
            device = self._authenticate_device(
                conn, device_id=device_id, device_secret=device_secret
            )
            grant = conn.execute(
                "SELECT * FROM grant_record WHERE grant_id=? AND device_id=?",
                (grant_id, device_id),
            ).fetchone()
            if grant is None:
                raise SecurityError(404, "grant_not_found", "grant was not found for this device")
            if grant["revoked_at"] is not None or int(grant["expires_at"]) <= now:
                raise SecurityError(403, "grant_inactive", "grant is expired or revoked")
            capabilities = json_loads(grant["capabilities"], [])
            if capability not in capabilities:
                raise SecurityError(403, "capability_denied", "grant does not contain this capability")
            decision = self._current_decision_for_grant(grant, device)
            if not decision.per_action_approval:
                raise SecurityError(409, "action_approval_not_required", "capability does not use per-action approval")
            if not self._route_allows(grant["target_app"], capability, method, path):
                raise SecurityError(403, "route_not_allowed", "method and path are not declared by capability")
            try:
                payload_preview = validate_payload_preview(
                    payload_preview, required=decision.payload_preview_required
                )
            except ValueError as exc:
                raise SecurityError(422, "invalid_payload_preview", str(exc)) from exc
            existing = conn.execute(
                """
                SELECT * FROM approval_request
                WHERE approval_type='action' AND device_id=? AND grant_id=? AND action_hash=?
                  AND status IN ('pending','approved') AND consumed_at IS NULL AND expires_at>?
                """,
                (device_id, grant_id, action_hash, now),
            ).fetchone()
            if existing is not None:
                return {"approval": self.public_approval(existing), "request_code": None, "deduplicated": True}
            approval_id = _new_id("act")
            request_code = _human_code()
            expires_at = min(now + 300, int(grant["expires_at"]))
            conn.execute(
                """
                INSERT INTO approval_request (
                    approval_id, approval_type, target_app, device_id, grant_id,
                    requested_capabilities, capability, risk_level, status,
                    requested_ttl_seconds, required_trust_level, required_approval_methods,
                    request_code_hash, reason, created_at, expires_at, policy_json,
                    action_method, action_path, body_sha256, payload_preview, action_hash
                ) VALUES (?, 'action', ?, ?, ?, ?, ?, ?, 'pending', 120, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id, grant["target_app"], device_id, grant_id,
                    json_dumps([capability]), capability, decision.risk_level,
                    decision.required_trust_level, json_dumps(list(decision.approval_methods)),
                    self.store.digest("request-code", request_code), reason[:1000], now,
                    expires_at, json_dumps(decision.to_dict()), method, path, body_sha256,
                    payload_preview, action_hash,
                ),
            )
            approval = conn.execute(
                "SELECT * FROM approval_request WHERE approval_id=?", (approval_id,)
            ).fetchone()
            return {
                "approval": self.public_approval(approval),
                "request_code": request_code,
                "warning": "request_code is shown once and the approval expires in five minutes",
            }

    def action_request_status(
        self, *, approval_id: str, device_id: str, device_secret: str
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            self._authenticate_device(conn, device_id=device_id, device_secret=device_secret)
            approval = conn.execute(
                "SELECT * FROM approval_request WHERE approval_id=? AND device_id=? AND approval_type='action'",
                (approval_id, device_id),
            ).fetchone()
            if approval is None:
                raise SecurityError(404, "approval_not_found", "action approval was not found")
            return {"approval": self.public_approval(approval)}

    def issue_token(
        self,
        *,
        device_id: str,
        device_secret: str,
        grant_id: str,
        requested_ttl_seconds: int = 900,
        source_id: str = "",
        client_name: str = "",
        client_ip: str = "",
        user_agent: str = "",
        action_approval_id: str = "",
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            device = self._authenticate_device(
                conn,
                device_id=device_id,
                device_secret=device_secret,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            grant = conn.execute(
                "SELECT * FROM grant_record WHERE grant_id=?", (grant_id,)
            ).fetchone()
            now = now_ts()
            if grant is None or grant["device_id"] != device_id:
                raise SecurityError(404, "grant_not_found", "grant was not found for this device")
            if grant["revoked_at"] is not None:
                raise SecurityError(403, "grant_revoked", "grant has been revoked")
            if int(grant["expires_at"]) <= now:
                raise SecurityError(403, "grant_expired", "grant has expired")
            if grant["one_time_consumed_at"] is not None:
                raise SecurityError(403, "grant_consumed", "one-time grant has already been consumed")
            decision = self._current_decision_for_grant(grant, device)
            action_approval = None
            if decision.per_action_approval:
                if not action_approval_id:
                    raise SecurityError(403, "action_approval_required", "an approved action binding is required")
                action_approval = conn.execute(
                    """
                    SELECT * FROM approval_request
                    WHERE approval_id=? AND approval_type='action' AND device_id=? AND grant_id=?
                    """,
                    (action_approval_id, device_id, grant_id),
                ).fetchone()
                if action_approval is None or action_approval["status"] != "approved":
                    raise SecurityError(403, "action_not_approved", "action approval is not approved")
                if action_approval["consumed_at"] is not None or int(action_approval["expires_at"]) <= now:
                    raise SecurityError(403, "action_approval_inactive", "action approval expired or was consumed")
                existing_action_token = conn.execute(
                    """
                    SELECT 1 FROM token_record
                    WHERE action_approval_id=? AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at>?
                    """,
                    (action_approval_id, now),
                ).fetchone()
                if existing_action_token:
                    raise SecurityError(409, "action_token_exists", "an unused token already exists for this action")
            if grant["grant_type"] == "one_time":
                existing = conn.execute(
                    """
                    SELECT 1 FROM token_record
                    WHERE grant_id=? AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at>?
                    """,
                    (grant_id, now),
                ).fetchone()
                if existing:
                    raise SecurityError(409, "one_time_token_exists", "an unused one-time token already exists")
            requested = requested_ttl_seconds if requested_ttl_seconds > 0 else 900
            ttl = min(requested, 900, int(grant["expires_at"]) - now)
            if action_approval is not None:
                ttl = min(ttl, 120, int(action_approval["expires_at"]) - now)
            if device["trust_expires_at"] is not None:
                ttl = min(ttl, int(device["trust_expires_at"]) - now)
            if ttl <= 0:
                raise SecurityError(403, "token_ttl_denied", "token cannot outlive its grant or device trust")
            token_id = _new_id("tok")
            secret = _new_secret("gwt")
            access_token = f"{token_id}.{secret}"
            token_type = "one_time" if decision.one_time else "access"
            conn.execute(
                """
                INSERT INTO token_record (
                    token_id, token_hash, token_type, grant_id, device_id, target_app,
                    capabilities, issued_at, expires_at, source_id, client_name,
                    action_approval_id, bound_action_hash, bound_method, bound_path, bound_body_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_id,
                    self.store.digest("access-token", access_token),
                    token_type,
                    grant_id,
                    device_id,
                    grant["target_app"],
                    grant["capabilities"],
                    now,
                    now + ttl,
                    source_id[:120],
                    client_name[:120],
                    action_approval_id or None,
                    action_approval["action_hash"] if action_approval is not None else "",
                    action_approval["action_method"] if action_approval is not None else "",
                    action_approval["action_path"] if action_approval is not None else "",
                    action_approval["body_sha256"] if action_approval is not None else "",
                ),
            )
            token = conn.execute("SELECT * FROM token_record WHERE token_id=?", (token_id,)).fetchone()
            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ttl,
                "token": self.public_token(token),
                "warning": "access_token is shown once",
            }

    def verify_access_token(
        self,
        access_token: str,
        *,
        target_app: str | None = None,
        capability: str | None = None,
        consume: bool = False,
        method: str | None = None,
        path: str | None = None,
        body_sha256: str | None = None,
    ) -> dict[str, Any]:
        if not access_token or "." not in access_token or len(access_token) > 512:
            raise SecurityError(401, "invalid_token", "access token is invalid")
        token_id = access_token.split(".", 1)[0]
        with self.store.transaction() as conn:
            self.store.expire_records(conn)
            token = conn.execute(
                """
                SELECT t.*, g.revoked_at AS grant_revoked_at, g.expires_at AS grant_expires_at,
                       g.one_time_consumed_at, g.policy_json,
                       d.status AS device_status, d.trust_level, d.trust_expires_at,
                       d.device_name, d.source_id AS device_source_id
                FROM token_record t
                JOIN grant_record g ON g.grant_id=t.grant_id
                JOIN trusted_device d ON d.device_id=t.device_id
                WHERE t.token_id=?
                """,
                (token_id,),
            ).fetchone()
            now = now_ts()
            if token is None or not self.store.verify_digest(
                "access-token", access_token, token["token_hash"]
            ):
                raise SecurityError(401, "invalid_token", "access token is invalid")
            if token["revoked_at"] is not None or token["grant_revoked_at"] is not None:
                raise SecurityError(401, "token_revoked", "access token or grant has been revoked")
            if int(token["expires_at"]) <= now or int(token["grant_expires_at"]) <= now:
                raise SecurityError(401, "token_expired", "access token has expired")
            if token["device_status"] != "active":
                raise SecurityError(403, "device_not_active", "token device is not active")
            if token["trust_expires_at"] is not None and int(token["trust_expires_at"]) <= now:
                raise SecurityError(403, "device_trust_expired", "token device trust has expired")
            if token["consumed_at"] is not None or token["one_time_consumed_at"] is not None:
                raise SecurityError(401, "token_consumed", "one-time token has already been consumed")
            capabilities = json_loads(token["capabilities"], [])
            if target_app is not None and token["target_app"] != target_app:
                raise SecurityError(403, "token_target_mismatch", "token is not valid for this app")
            if capability is not None and capability not in capabilities:
                raise SecurityError(403, "capability_denied", "token does not contain this capability")
            if token["bound_action_hash"]:
                if method is None or path is None or body_sha256 is None:
                    if consume:
                        raise SecurityError(403, "action_binding_required", "bound method, path, and body hash are required")
                else:
                    try:
                        actual_method, actual_path, actual_body, actual_hash = canonical_action(
                            method, path, body_sha256
                        )
                    except ValueError as exc:
                        raise SecurityError(422, "invalid_action", str(exc)) from exc
                    if not (
                        hmac.compare_digest(actual_hash, token["bound_action_hash"])
                        and actual_method == token["bound_method"]
                        and actual_path == token["bound_path"]
                        and actual_body == token["bound_body_sha256"]
                    ):
                        raise SecurityError(403, "action_binding_mismatch", "request does not match approved action")
            grant_like = {
                "policy_json": token["policy_json"],
            }
            try:
                decision = self.policy.revalidate_snapshot(
                    json_loads(grant_like["policy_json"], {}),
                    device_trust_level=token["trust_level"],
                )
            except PolicyDenied as exc:
                raise SecurityError(403, "policy_changed", str(exc)) from exc
            if consume and token["token_type"] == "one_time":
                updated = conn.execute(
                    "UPDATE token_record SET consumed_at=?, last_used_at=? WHERE token_id=? AND consumed_at IS NULL",
                    (now, now, token_id),
                ).rowcount
                if updated != 1:
                    raise SecurityError(409, "token_race", "one-time token was consumed concurrently")
                conn.execute(
                    "UPDATE grant_record SET one_time_consumed_at=CASE WHEN grant_type='one_time' THEN ? ELSE one_time_consumed_at END, last_used_at=? WHERE grant_id=?",
                    (now, now, token["grant_id"]),
                )
                if token["action_approval_id"]:
                    updated = conn.execute(
                        "UPDATE approval_request SET consumed_at=? WHERE approval_id=? AND consumed_at IS NULL",
                        (now, token["action_approval_id"]),
                    ).rowcount
                    if updated != 1:
                        raise SecurityError(409, "action_approval_race", "action approval was consumed concurrently")
            else:
                conn.execute(
                    "UPDATE token_record SET last_used_at=? WHERE token_id=?", (now, token_id)
                )
                conn.execute(
                    "UPDATE grant_record SET last_used_at=? WHERE grant_id=?", (now, token["grant_id"])
                )
            return {
                "actor_type": "device_token",
                "actor_name": token["device_name"],
                "device_id": token["device_id"],
                "source_id": token["source_id"] or token["device_source_id"],
                "client_name": token["client_name"],
                "grant_id": token["grant_id"],
                "token_id": token_id,
                "target_app": token["target_app"],
                "capabilities": capabilities,
                "risk_level": decision.risk_level,
                "expires_at": token["expires_at"],
                "token_type": token["token_type"],
            }

    def revoke_token_by_device(
        self, *, device_id: str, device_secret: str, token_id: str
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            self._authenticate_device(
                conn, device_id=device_id, device_secret=device_secret
            )
            token = conn.execute(
                "SELECT * FROM token_record WHERE token_id=? AND device_id=?",
                (token_id, device_id),
            ).fetchone()
            if token is None:
                raise SecurityError(404, "token_not_found", "token was not found for this device")
            now = now_ts()
            conn.execute(
                "UPDATE token_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='device request' WHERE token_id=?",
                (now, device_id, token_id),
            )
            return {"ok": True, "token_id": token_id, "revoked_at": token["revoked_at"] or now}

    def revoke_current_token(self, access_token: str) -> dict[str, Any]:
        token = self.verify_access_token(access_token)
        with self.store.transaction() as conn:
            now = now_ts()
            conn.execute(
                "UPDATE token_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='self revoke' WHERE token_id=?",
                (now, token["device_id"], token["token_id"]),
            )
        return {"ok": True, "token_id": token["token_id"], "revoked_at": now}

    def approve(
        self,
        *,
        approval_id: str,
        approved_by: str,
        approval_method: str = "web-admin",
        device_trust_level: str = "paired",
        trust_ttl_seconds: int = 31536000,
        request_code: str = "",
        totp_code: str = "",
        desktop_verified: bool = False,
    ) -> dict[str, Any]:
        self.store.expire_records()
        with self.store.transaction() as conn:
            approval = conn.execute(
                "SELECT * FROM approval_request WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if approval is None:
                raise SecurityError(404, "approval_not_found", "approval request was not found")
            if approval["status"] != "pending":
                raise SecurityError(409, "approval_not_pending", f"approval is {approval['status']}")
            if int(approval["expires_at"]) <= now_ts():
                conn.execute(
                    "UPDATE approval_request SET status='expired' WHERE approval_id=?",
                    (approval_id,),
                )
                raise SecurityError(409, "approval_expired", "approval request has expired")
            methods = json_loads(approval["required_approval_methods"], [])
            if approval_method not in methods:
                raise SecurityError(
                    403,
                    "approval_method_denied",
                    f"{approval_method} is not permitted; required methods: {methods}",
                )
            if approval_method == "desktop" and not desktop_verified:
                raise SecurityError(403, "desktop_verification_required", "desktop helper verification is required")
            if approval_method == "totp":
                if not self.totp_secret:
                    raise SecurityError(503, "totp_unavailable", "TOTP is not configured")
                counter = verify_totp(self.totp_secret, totp_code)
                if counter is None:
                    raise SecurityError(403, "totp_invalid", "TOTP code is invalid")
                last_counter = int(self.store.get_system_state("totp_last_counter", -1))
                if counter <= last_counter:
                    raise SecurityError(409, "totp_replayed", "TOTP code has already been used")
            if approval_method != "desktop" and approval["request_code_hash"] and (
                not request_code
                or not self.store.verify_digest(
                    "request-code", request_code.strip().upper(), approval["request_code_hash"]
                )
            ):
                raise SecurityError(403, "request_code_invalid", "approval request code is invalid")
            now = now_ts()
            result: dict[str, Any]
            if approval["approval_type"] == "device_registration":
                if device_trust_level not in TRUST_RANK or device_trust_level == "untrusted":
                    raise SecurityError(422, "invalid_trust_level", "approved devices must be paired or higher")
                ttl = max(300, min(int(trust_ttl_seconds), 31536000))
                updated = conn.execute(
                    """
                    UPDATE trusted_device
                    SET status='active', trust_level=?, trusted_at=?, trusted_by=?, trust_expires_at=?
                    WHERE device_id=? AND status='pending'
                    """,
                    (device_trust_level, now, approved_by, now + ttl, approval["device_id"]),
                ).rowcount
                if updated != 1:
                    raise SecurityError(409, "device_not_pending", "device is not pending approval")
                result = {
                    "device": self.public_device(
                        conn.execute(
                            "SELECT * FROM trusted_device WHERE device_id=?", (approval["device_id"],)
                        ).fetchone()
                    )
                }
            elif approval["approval_type"] == "grant":
                device = self._device_by_id_active(conn, approval["device_id"])
                snapshot = json_loads(approval["policy_json"], {})
                try:
                    decision = self.policy.revalidate_snapshot(
                        snapshot, device_trust_level=device["trust_level"]
                    )
                except PolicyDenied as exc:
                    raise SecurityError(403, "policy_changed", str(exc)) from exc
                if approval_method not in decision.approval_methods:
                    raise SecurityError(403, "policy_changed", "approval method is no longer allowed")
                grant = self._insert_grant(
                    conn,
                    grant_id=approval["pending_grant_id"],
                    device_id=approval["device_id"],
                    decision=decision,
                    actor=approved_by,
                    approval_method=approval_method,
                    approval_id=approval_id,
                )
                result = {"grant": self.public_grant(grant)}
            elif approval["approval_type"] == "action":
                device = self._device_by_id_active(conn, approval["device_id"])
                grant = conn.execute(
                    "SELECT * FROM grant_record WHERE grant_id=? AND device_id=?",
                    (approval["grant_id"], approval["device_id"]),
                ).fetchone()
                if grant is None or grant["revoked_at"] is not None or int(grant["expires_at"]) <= now:
                    raise SecurityError(403, "grant_inactive", "parent grant is expired or revoked")
                decision = self._current_decision_for_grant(grant, device)
                if not decision.per_action_approval or approval_method not in decision.approval_methods:
                    raise SecurityError(403, "policy_changed", "action approval policy changed")
                result = {}
            else:
                raise SecurityError(409, "unsupported_approval", "unsupported approval type")
            conn.execute(
                """
                UPDATE approval_request
                SET status='approved', approved_at=?, approved_by=?, approval_method=?
                WHERE approval_id=? AND status='pending'
                """,
                (now, approved_by, approval_method, approval_id),
            )
            if approval_method == "totp":
                conn.execute(
                    """
                    INSERT INTO system_state(state_key, value_json, updated_at) VALUES ('totp_last_counter', ?, ?)
                    ON CONFLICT(state_key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
                    """,
                    (json_dumps(counter), now),
                )
            result["approval"] = self.public_approval(
                conn.execute(
                    "SELECT * FROM approval_request WHERE approval_id=?", (approval_id,)
                ).fetchone()
            )
            return result

    def deny(self, *, approval_id: str, denied_by: str, reason: str = "") -> dict[str, Any]:
        self.store.expire_records()
        with self.store.transaction() as conn:
            approval = conn.execute(
                "SELECT * FROM approval_request WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if approval is None:
                raise SecurityError(404, "approval_not_found", "approval request was not found")
            if approval["status"] != "pending":
                raise SecurityError(409, "approval_not_pending", f"approval is {approval['status']}")
            now = now_ts()
            conn.execute(
                "UPDATE approval_request SET status='denied', denied_at=?, denied_by=?, raw_json=? WHERE approval_id=?",
                (now, denied_by, json_dumps({"deny_reason": reason[:1000]}), approval_id),
            )
            if approval["approval_type"] == "device_registration":
                conn.execute(
                    "UPDATE trusted_device SET status='revoked', revoked_at=?, revoked_by=?, revoke_reason=? WHERE device_id=? AND status='pending'",
                    (now, denied_by, reason[:1000] or "registration denied", approval["device_id"]),
                )
            return {
                "approval": self.public_approval(
                    conn.execute(
                        "SELECT * FROM approval_request WHERE approval_id=?", (approval_id,)
                    ).fetchone()
                )
            }

    def create_manual_device(
        self,
        *,
        device_name: str,
        device_type: str,
        trust_level: str,
        trust_ttl_seconds: int,
        created_by: str,
        source_id: str = "",
    ) -> dict[str, Any]:
        if trust_level not in {"paired", "trusted", "privileged"}:
            raise SecurityError(422, "invalid_trust_level", "invalid device trust level")
        if not device_name.strip() or not device_type.strip():
            raise SecurityError(422, "invalid_device", "device_name and device_type are required")
        now = now_ts()
        ttl = max(300, min(int(trust_ttl_seconds), 31536000))
        device_id = _new_id("dev")
        device_secret = _new_secret("gwd")
        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO trusted_device (
                    device_id, secret_hash, device_name, device_type, source_id,
                    trust_level, status, created_at, trusted_at, trusted_by, trust_expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
                """,
                (
                    device_id,
                    self.store.digest("device", device_secret),
                    device_name.strip()[:120],
                    device_type.strip().lower()[:64],
                    source_id[:120],
                    trust_level,
                    now,
                    now,
                    created_by,
                    now + ttl,
                ),
            )
            device = conn.execute(
                "SELECT * FROM trusted_device WHERE device_id=?", (device_id,)
            ).fetchone()
        return {
            "device": self.public_device(device),
            "device_secret": device_secret,
            "warning": "device_secret is shown once",
        }

    def revoke_device(self, *, device_id: str, revoked_by: str, reason: str) -> dict[str, Any]:
        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM trusted_device WHERE device_id=?", (device_id,)
            ).fetchone()
            if row is None:
                raise SecurityError(404, "device_not_found", "device was not found")
            now = now_ts()
            conn.execute(
                "UPDATE trusted_device SET status='revoked', revoked_at=?, revoked_by=?, revoke_reason=? WHERE device_id=?",
                (now, revoked_by, reason[:1000] or "admin revoke", device_id),
            )
            conn.execute(
                "UPDATE grant_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='device revoked' WHERE device_id=?",
                (now, revoked_by, device_id),
            )
            conn.execute(
                "UPDATE token_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='device revoked' WHERE device_id=?",
                (now, revoked_by, device_id),
            )
            conn.execute(
                "UPDATE lease_record SET status='releasing', release_reason='device revoked; recovery required' WHERE device_id=? AND status IN ('activating','active','releasing')",
                (device_id,),
            )
            return {
                "device": self.public_device(
                    conn.execute(
                        "SELECT * FROM trusted_device WHERE device_id=?", (device_id,)
                    ).fetchone()
                )
            }

    def update_device(
        self,
        *,
        device_id: str,
        updated_by: str,
        device_name: str | None = None,
        trust_level: str | None = None,
        trust_ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM trusted_device WHERE device_id=?", (device_id,)).fetchone()
            if row is None:
                raise SecurityError(404, "device_not_found", "device was not found")
            if row["status"] != "active":
                raise SecurityError(409, "device_not_active", "only active devices can be updated")
            name = row["device_name"] if device_name is None else device_name.strip()
            level = row["trust_level"] if trust_level is None else trust_level.strip().lower()
            if not 1 <= len(name) <= 120:
                raise SecurityError(422, "invalid_device_name", "device_name must contain 1..120 characters")
            if level not in {"paired", "trusted", "privileged"}:
                raise SecurityError(422, "invalid_trust_level", "invalid device trust level")
            expires_at = row["trust_expires_at"]
            if trust_ttl_seconds is not None:
                ttl = max(300, min(int(trust_ttl_seconds), 31536000))
                expires_at = now_ts() + ttl
            changed_trust = level != row["trust_level"]
            conn.execute(
                "UPDATE trusted_device SET device_name=?, trust_level=?, trust_expires_at=?, trusted_by=?, trusted_at=? WHERE device_id=?",
                (name, level, expires_at, updated_by, now_ts(), device_id),
            )
            if changed_trust:
                now = now_ts()
                conn.execute(
                    "UPDATE grant_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='device trust changed' WHERE device_id=?",
                    (now, updated_by, device_id),
                )
                conn.execute(
                    "UPDATE token_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='device trust changed' WHERE device_id=?",
                    (now, updated_by, device_id),
                )
                conn.execute(
                    "UPDATE lease_record SET status='releasing', release_reason='device trust changed; recovery required' WHERE device_id=? AND status IN ('activating','active','releasing')",
                    (device_id,),
                )
            return {"device": self.public_device(conn.execute(
                "SELECT * FROM trusted_device WHERE device_id=?", (device_id,)
            ).fetchone()), "grants_revoked": changed_trust}

    def rotate_device_secret(self, *, device_id: str, rotated_by: str) -> dict[str, Any]:
        secret = _new_secret("gwd")
        now = now_ts()
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM trusted_device WHERE device_id=?", (device_id,)).fetchone()
            if row is None:
                raise SecurityError(404, "device_not_found", "device was not found")
            if row["status"] != "active":
                raise SecurityError(409, "device_not_active", "only active devices can rotate credentials")
            conn.execute(
                "UPDATE trusted_device SET secret_hash=?, credential_version=credential_version+1, trusted_by=? WHERE device_id=?",
                (self.store.digest("device", secret), rotated_by, device_id),
            )
            conn.execute(
                "UPDATE grant_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='device credential rotated' WHERE device_id=?",
                (now, rotated_by, device_id),
            )
            conn.execute(
                "UPDATE token_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='device credential rotated' WHERE device_id=?",
                (now, rotated_by, device_id),
            )
            conn.execute(
                "UPDATE lease_record SET status='releasing', release_reason='device credential rotated; recovery required' WHERE device_id=? AND status IN ('activating','active','releasing')",
                (device_id,),
            )
            device = conn.execute("SELECT * FROM trusted_device WHERE device_id=?", (device_id,)).fetchone()
        return {
            "device": self.public_device(device), "device_secret": secret,
            "warning": "device_secret is shown once; all prior grants and tokens were revoked",
        }

    def approval_status_for_device(
        self, *, approval_id: str, device_id: str, device_secret: str
    ) -> dict[str, Any]:
        with self.store.transaction() as conn:
            self._authenticate_device(
                conn, device_id=device_id, device_secret=device_secret, allow_pending=True
            )
            row = conn.execute(
                "SELECT * FROM approval_request WHERE approval_id=? AND device_id=?",
                (approval_id, device_id),
            ).fetchone()
            if row is None:
                raise SecurityError(404, "approval_not_found", "approval request was not found")
            return {"approval": self.public_approval(row)}

    def revoke_grant(self, *, grant_id: str, revoked_by: str, reason: str) -> dict[str, Any]:
        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM grant_record WHERE grant_id=?", (grant_id,)
            ).fetchone()
            if row is None:
                raise SecurityError(404, "grant_not_found", "grant was not found")
            now = now_ts()
            conn.execute(
                "UPDATE grant_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason=? WHERE grant_id=?",
                (now, revoked_by, reason[:1000] or "admin revoke", grant_id),
            )
            conn.execute(
                "UPDATE token_record SET revoked_at=COALESCE(revoked_at, ?), revoked_by=?, revoke_reason='grant revoked' WHERE grant_id=?",
                (now, revoked_by, grant_id),
            )
            conn.execute(
                "UPDATE lease_record SET status='releasing', release_reason='grant revoked; recovery required' WHERE grant_id=? AND status IN ('activating','active','releasing')",
                (grant_id,),
            )
            return {
                "grant": self.public_grant(
                    conn.execute(
                        "SELECT * FROM grant_record WHERE grant_id=?", (grant_id,)
                    ).fetchone()
                )
            }

    def list_devices(self) -> list[dict[str, Any]]:
        self.store.expire_records()
        return [
            self.public_device(row) or {}
            for row in self.store.fetch_all(
                "SELECT * FROM trusted_device ORDER BY created_at DESC"
            )
        ]

    def list_grants(self) -> list[dict[str, Any]]:
        self.store.expire_records()
        return [
            self.public_grant(row) or {}
            for row in self.store.fetch_all(
                "SELECT * FROM grant_record ORDER BY created_at DESC"
            )
        ]

    def list_approvals(self) -> list[dict[str, Any]]:
        self.store.expire_records()
        return [
            self.public_approval(row) or {}
            for row in self.store.fetch_all(
                "SELECT * FROM approval_request ORDER BY created_at DESC"
            )
        ]

    def list_audit(
        self,
        *,
        limit: int = 100,
        target_app: str = "",
        device_id: str = "",
        success: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Backward-compatible bounded audit list."""
        return self.query_audit(
            page=1,
            page_size=limit,
            target_app=target_app,
            device_id=device_id,
            success=success,
        )["items"]

    def query_audit(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
        target_app: str = "",
        device_id: str = "",
        success: bool | None = None,
        actor_type: str = "",
        capability: str = "",
        request_id: str = "",
        since: int | None = None,
        until: int | None = None,
        status_code: int | None = None,
        max_page_size: int = 500,
    ) -> dict[str, Any]:
        """Return a stable, newest-first audit page without sensitive transport data."""
        clauses: list[str] = []
        params: list[Any] = []
        if target_app:
            clauses.append("target_app=?")
            params.append(target_app[:64])
        if device_id:
            clauses.append("device_id=?")
            params.append(device_id[:160])
        if success is not None:
            clauses.append("success=?")
            params.append(1 if success else 0)
        if actor_type:
            clauses.append("actor_type=?")
            params.append(actor_type[:64])
        if capability:
            clauses.append("capability=?")
            params.append(capability[:160])
        if request_id:
            clauses.append("request_id=?")
            params.append(request_id[:160])
        if since is not None:
            clauses.append("created_at>=?")
            params.append(int(since))
        if until is not None:
            clauses.append("created_at<=?")
            params.append(int(until))
        if status_code is not None:
            clauses.append("status_code=?")
            params.append(int(status_code))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_page = max(1, int(page))
        safe_limit = max(1, min(int(page_size), int(max_page_size)))
        offset = (safe_page - 1) * safe_limit
        total_row = self.store.fetch_one(
            f"SELECT COUNT(*) AS count FROM api_audit{where}", tuple(params)
        )
        rows = self.store.fetch_all(
            f"SELECT * FROM api_audit{where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (*params, safe_limit, offset),
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["success"] = bool(item.get("success"))
            item["raw"] = json_loads(item.pop("raw_json", "{}"), {})
            item.pop("user_agent", None)
            item.pop("client_ip", None)
            result.append(item)
        total = int((total_row or {}).get("count", 0))
        return {
            "items": result,
            "page": safe_page,
            "page_size": safe_limit,
            "total": total,
            "total_pages": max(1, (total + safe_limit - 1) // safe_limit),
        }

    def list_leases(self, *, limit: int = 200, active_only: bool = False) -> list[dict[str, Any]]:
        where = " WHERE status IN ('activating','active','releasing')" if active_only else ""
        rows = self.store.fetch_all(
            f"SELECT * FROM lease_record{where} ORDER BY created_at DESC LIMIT ?",
            (max(1, min(int(limit), 500)),),
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json_loads(item.pop("raw_json", "{}"), {})
            result.append(item)
        return result

    def security_summary(self) -> dict[str, Any]:
        self.store.expire_records()
        counts: dict[str, int] = {}
        for key, table in (
            ("devices", "trusted_device"),
            ("grants", "grant_record"),
            ("approvals", "approval_request"),
            ("tokens", "token_record"),
            ("leases", "lease_record"),
            ("audit_events", "api_audit"),
        ):
            row = self.store.fetch_one(f"SELECT COUNT(*) AS count FROM {table}")
            counts[key] = int((row or {}).get("count", 0))
        pending = self.store.fetch_one(
            "SELECT COUNT(*) AS count FROM approval_request WHERE status='pending'"
        )
        active_tokens = self.store.fetch_one(
            "SELECT COUNT(*) AS count FROM token_record WHERE revoked_at IS NULL AND consumed_at IS NULL AND expires_at>?",
            (now_ts(),),
        )
        active_leases = self.store.fetch_one(
            "SELECT COUNT(*) AS count FROM lease_record WHERE status IN ('activating','active','releasing')"
        )
        unread_notifications = self.store.fetch_one(
            "SELECT COUNT(*) AS count FROM notification_record WHERE read_at IS NULL"
        )
        return {
            **counts,
            "pending_approvals": int((pending or {}).get("count", 0)),
            "active_tokens": int((active_tokens or {}).get("count", 0)),
            "active_leases": int((active_leases or {}).get("count", 0)),
            "unread_notifications": int((unread_notifications or {}).get("count", 0)),
            "database": self.store.integrity_report(),
        }

    def active_lease_count(self, target_app: str) -> int:
        row = self.store.fetch_one(
            """
            SELECT COUNT(*) AS count FROM lease_record
            WHERE target_app=? AND status IN ('activating','active','releasing')
            """,
            (target_app,),
        )
        return int((row or {}).get("count", 0))
