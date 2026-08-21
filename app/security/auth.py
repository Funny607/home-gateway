from __future__ import annotations

import hmac
import os
import secrets
import subprocess
import time
from pathlib import Path
from typing import Literal

import yaml
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AuthUserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password_hash_ref: str
    role: Literal["guest", "admin"]

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 64:
            raise ValueError("username must contain 1..64 characters")
        return value

    @field_validator("password_hash_ref")
    @classmethod
    def validate_reference(cls, value: str) -> str:
        if not (value.startswith("env:") or value.startswith("keychain:")):
            raise ValueError("password_hash_ref must use env: or keychain:")
        return value


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_secret_ref: str
    database_pepper_ref: str
    totp_secret_ref: str | None = None
    totp_issuer: str = "Home Gateway"
    totp_account: str = "607"
    desktop_approver_secret_ref: str | None = None
    breakglass_secret_ref: str | None = None
    session_max_age_seconds: int = 28800
    secure_cookies: bool = True
    same_site: Literal["lax", "strict"] = "strict"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    trusted_origins: list[str] = Field(default_factory=list)
    login_attempts: int = 5
    login_window_seconds: int = 300
    login_block_seconds: int = 900
    public_api_attempts: int = 30
    public_api_window_seconds: int = 60
    users: list[AuthUserConfig]

    @field_validator(
        "session_secret_ref", "database_pepper_ref", "totp_secret_ref",
        "desktop_approver_secret_ref", "breakglass_secret_ref",
    )
    @classmethod
    def validate_session_ref(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not (value.startswith("env:") or value.startswith("keychain:")):
            raise ValueError("session_secret_ref must use env: or keychain:")
        return value

    @field_validator(
        "session_max_age_seconds",
        "login_attempts",
        "login_window_seconds",
        "login_block_seconds",
        "public_api_attempts",
        "public_api_window_seconds",
    )
    @classmethod
    def validate_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("security limits must be positive")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def validate_hosts(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in values:
            value = str(raw).strip().lower()
            if not value or "/" in value or "://" in value or value == "*":
                raise ValueError(f"invalid allowed host: {raw}")
            normalized.append(value)
        return sorted(set(normalized))

    @field_validator("trusted_origins")
    @classmethod
    def validate_origins(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in values:
            value = str(raw).strip().rstrip("/")
            if not (value.startswith("https://") or value.startswith("http://127.0.0.1") or value.startswith("http://localhost")):
                raise ValueError(f"untrusted origin scheme or host: {raw}")
            normalized.append(value)
        return sorted(set(normalized))

    @model_validator(mode="after")
    def validate_users(self) -> "AuthConfig":
        usernames = [user.username for user in self.users]
        if len(usernames) != len(set(usernames)):
            raise ValueError("duplicate auth username")
        if not any(user.role == "admin" for user in self.users):
            raise ValueError("at least one admin user is required")
        return self


def load_auth_config(path: Path) -> AuthConfig:
    if not path.exists():
        raise RuntimeError(f"authentication config is missing: {path}")
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise RuntimeError("authentication config root must be an object")
    return AuthConfig.model_validate(raw)


def resolve_reference(reference: str) -> str:
    if reference.startswith("env:"):
        name = reference[4:]
        value = os.environ.get(name, "")
        if not value:
            raise RuntimeError(f"required environment secret is missing: {name}")
        return value
    if reference.startswith("keychain:"):
        parts = reference.split(":", 2)
        if len(parts) != 3 or not parts[1] or not parts[2]:
            raise RuntimeError("keychain reference must be keychain:SERVICE:ACCOUNT")
        completed = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-w", "-s", parts[1], "-a", parts[2]],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            raise RuntimeError(f"required Keychain secret is missing: {parts[1]}/{parts[2]}")
        return completed.stdout.strip()
    raise RuntimeError("unsupported secret reference")


def resolve_session_secret(config: AuthConfig) -> str:
    value = resolve_reference(config.session_secret_ref)
    if len(value) < 32:
        raise RuntimeError("GATEWAY_SESSION_SECRET must contain at least 32 characters")
    return value


class PasswordService:
    def __init__(self, users: list[AuthUserConfig]) -> None:
        self._hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
        self._users: dict[str, tuple[str, str]] = {}
        self._dummy_hash = self._hasher.hash("gateway-dummy-password")
        for user in users:
            encoded = resolve_reference(user.password_hash_ref)
            if not encoded.startswith("$argon2id$"):
                raise RuntimeError(f"password hash for {user.username!r} is not Argon2id")
            self._users[user.username] = (encoded, user.role)

    @classmethod
    def hash_password(cls, password: str) -> str:
        if len(password) < 12:
            raise ValueError("password must contain at least 12 characters")
        return PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2).hash(password)

    def verify(self, username: str, password: str) -> str | None:
        encoded, role = self._users.get(username, (self._dummy_hash, ""))
        try:
            ok = self._hasher.verify(encoded, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            ok = False
        if ok and username in self._users:
            if self._hasher.check_needs_rehash(encoded):
                # Hash rotation is intentionally explicit because the source is Keychain/env.
                pass
            return role
        return None


def issue_session(request: Request, username: str, role: str) -> None:
    request.session.clear()
    request.session.update(
        {
            "authenticated": True,
            "username": username,
            "role": role,
            "issued_at": int(time.time()),
            "csrf_token": secrets.token_urlsafe(32),
        }
    )


def current_identity(request: Request, max_age_seconds: int) -> dict[str, str | bool]:
    try:
        authenticated = bool(request.session.get("authenticated"))
    except AssertionError:
        authenticated = False
    if not authenticated:
        return {"authenticated": False, "username": "", "role": "anonymous"}
    issued_at = int(request.session.get("issued_at", 0) or 0)
    role = str(request.session.get("role", ""))
    username = str(request.session.get("username", ""))
    if issued_at <= 0 or int(time.time()) - issued_at > max_age_seconds or role not in {"guest", "admin"} or not username:
        request.session.clear()
        return {"authenticated": False, "username": "", "role": "anonymous"}
    return {"authenticated": True, "username": username, "role": role}


def csrf_token(request: Request) -> str:
    value = str(request.session.get("csrf_token", ""))
    if not value:
        value = secrets.token_urlsafe(32)
        request.session["csrf_token"] = value
    return value


def verify_csrf(request: Request, submitted: str | None) -> None:
    expected = str(request.session.get("csrf_token", ""))
    if not expected or not submitted or not hmac.compare_digest(expected, str(submitted)):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def verify_same_origin(request: Request, trusted_origins: list[str]) -> None:
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return
    origin = str(request.headers.get("origin", "")).rstrip("/")
    if not origin or origin not in set(trusted_origins):
        raise HTTPException(status_code=403, detail="Origin validation failed")


def require_admin(request: Request, max_age_seconds: int) -> str:
    identity = current_identity(request, max_age_seconds)
    if not identity["authenticated"]:
        raise HTTPException(status_code=401, detail="Login required")
    if identity["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return str(identity["username"])
