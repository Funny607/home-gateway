from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Request

from app.api_v1.actor import resolve_actor_from_session
from app.api_v1.errors import gateway_error
from app.api_v1.request_id import get_request_id
from app.lifecycle.manager import LifecycleManager


def build_gateway_v1_router(*, get_manager: Callable[[], LifecycleManager]) -> APIRouter:
    """Gateway 自身管理 API v1。第一阶段先做只读接口。"""

    router = APIRouter(prefix="/api/gateway/v1", tags=["gateway-v1"])

    def require_admin_or_read_session(request: Request):
        request_id = get_request_id(request)
        actor = resolve_actor_from_session(request)
        if not actor.is_authenticated:
            return None, gateway_error(
                code="UNAUTHORIZED",
                message="Login is required.",
                request_id=request_id,
            )
        return actor, None

    @router.get("/health")
    async def gateway_health(request: Request):
        actor, error = require_admin_or_read_session(request)
        if error is not None:
            return error
        manager = get_manager()
        return {
            "ok": True,
            "request_id": get_request_id(request),
            "status": "ok",
            "phase": manager.phase,
        }

    @router.get("/apps")
    async def gateway_apps(request: Request):
        actor, error = require_admin_or_read_session(request)
        if error is not None:
            return error
        visible = [
            item
            for item in get_manager().snapshot()
            if actor.role in get_manager().get_app(item["app_id"]).config.dashboard.visible_roles
        ]
        return {
            "ok": True,
            "request_id": get_request_id(request),
            "apps": visible,
        }

    @router.get("/apps/{app_id}")
    async def gateway_app_detail(request: Request, app_id: str):
        actor, error = require_admin_or_read_session(request)
        if error is not None:
            return error
        manager = get_manager()
        if app_id not in manager.apps:
            return gateway_error(
                code="APP_NOT_FOUND",
                message=f"Unknown app_id: {app_id}",
                request_id=get_request_id(request),
            )
        dashboard = manager.get_app(app_id).config.dashboard
        if actor.role not in dashboard.visible_roles or actor.role not in dashboard.allow_detail_roles:
            return gateway_error(
                code="FORBIDDEN",
                message="This app is not visible to your role.",
                request_id=get_request_id(request),
                status_code=403,
            )
        item = next((x for x in manager.snapshot() if x["app_id"] == app_id), None)
        return {
            "ok": True,
            "request_id": get_request_id(request),
            "app": item,
            "capabilities": [
                {
                    "id": cap.id,
                    "title": cap.title,
                    "risk": cap.risk,
                    "gateway_managed": cap.gateway_managed,
                    "routes": [route.model_dump() for route in cap.routes],
                    "audit": cap.audit,
                    "activity": cap.activity,
                    "auto_start": cap.auto_start,
                }
                for cap in manager.get_app(app_id).config.capabilities
            ],
        }

    return router
