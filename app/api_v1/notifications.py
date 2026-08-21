from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Query, Request

from app.notifications.service import NotificationService
from app.security.auth import AuthConfig, require_admin, verify_csrf


def build_notification_router(
    *, get_notifications: Callable[[], NotificationService], auth_config: AuthConfig
) -> APIRouter:
    router = APIRouter(prefix="/api/notifications/v1", tags=["notifications"])

    @router.get("")
    async def list_notifications(
        request: Request,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
        category: str = Query(default="", max_length=80),
        status: str = Query(default="", max_length=24),
        unread_only: bool = False,
    ):
        require_admin(request, auth_config.session_max_age_seconds)
        return {
            "ok": True,
            **get_notifications().list(
                page=page,
                page_size=page_size,
                category=category,
                status=status,
                unread_only=unread_only,
            ),
        }

    @router.post("/{notification_id}/read")
    async def mark_read(request: Request, notification_id: str):
        require_admin(request, auth_config.session_max_age_seconds)
        verify_csrf(request, request.headers.get("x-csrf-token"))
        return {"ok": True, "updated": get_notifications().mark_read(notification_id)}

    @router.post("/read-all")
    async def mark_all_read(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        verify_csrf(request, request.headers.get("x-csrf-token"))
        return {"ok": True, "updated": get_notifications().mark_read()}

    @router.post("/test")
    async def test_notification(request: Request):
        username = require_admin(request, auth_config.session_max_age_seconds)
        verify_csrf(request, request.headers.get("x-csrf-token"))
        item = get_notifications().enqueue(
            category="test",
            severity="info",
            title="Home Gateway 测试通知",
            message=f"管理员 {username} 发起了通知通道测试。",
            dedupe_key="test",
            metadata={"actor": username},
            force=True,
        )
        return {"ok": True, "notification": item}

    @router.get("/health")
    async def health(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, **get_notifications().health()}

    return router
