from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import Request


@dataclass(frozen=True)
class ApiActor:
    """
    API 调用者身份。

    第一阶段先支持 session：admin/guest/anonymous。
    后续 Trusted Device / Grant / Access Token 加入后，actor_type 会扩展为 device。
    """

    actor_type: str
    actor_name: str
    role: str
    device_id: str = ""
    source_id: str = ""
    client_name: str = ""
    grant_id: str = ""
    token_id: str = ""
    capabilities: set[str] = field(default_factory=set)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin" or "gateway:admin" in self.capabilities

    @property
    def is_authenticated(self) -> bool:
        return self.actor_type != "anonymous"


def resolve_actor_from_session(request: Request) -> ApiActor:
    """
    从浏览器 session 解析 actor。

    - admin session 拥有 gateway:admin
    - guest session 只有查看页面权限，不允许调用 external API 穿透
    - anonymous 不允许
    """

    try:
        authenticated = bool(request.session.get("authenticated"))
        username = str(request.session.get("username", ""))
        role = str(request.session.get("role", "guest"))
    except AssertionError:
        authenticated = False
        username = ""
        role = "anonymous"

    if not authenticated:
        return ApiActor(actor_type="anonymous", actor_name="", role="anonymous")

    if role == "admin":
        return ApiActor(
            actor_type="session",
            actor_name=username or "admin",
            role="admin",
            capabilities={"gateway:admin"},
        )

    return ApiActor(
        actor_type="session",
        actor_name=username or "guest",
        role="guest",
        capabilities=set(),
    )
