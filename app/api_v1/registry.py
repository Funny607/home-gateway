from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.registry.service import AppRegistry, RegistryError
from app.security.auth import AuthConfig, require_admin, verify_csrf
from app.security.http import read_json_object, reject_unknown_fields
from app.security.service import SecurityError


def _failure(exc: RegistryError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"ok": False, "error": exc.code, "message": str(exc)},
    )


def _security_failure(exc: SecurityError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"ok": False, "error": exc.code, "message": str(exc)},
    )


def build_registry_router(
    *, get_registry: Callable[[], AppRegistry], auth_config: AuthConfig
) -> APIRouter:
    router = APIRouter(prefix="/api/registry/v1", tags=["app-registry"])

    def admin(request: Request) -> str:
        username = require_admin(request, auth_config.session_max_age_seconds)
        verify_csrf(request, request.headers.get("x-csrf-token"))
        return username

    @router.get("/apps")
    async def list_apps(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, "items": get_registry().list()}

    @router.post("/preview")
    async def preview(request: Request):
        try:
            admin(request)
            payload = await read_json_object(
                request, max_bytes=AppRegistry.MAX_MANIFEST_BYTES + 8192
            )
            reject_unknown_fields(payload, {"manifest"})
            return {"ok": True, **get_registry().preview(payload.get("manifest", {}))}
        except RegistryError as exc:
            return _failure(exc)
        except SecurityError as exc:
            return _security_failure(exc)

    @router.put("/apps/{app_id}")
    async def save(request: Request, app_id: str):
        try:
            username = admin(request)
            payload = await read_json_object(
                request, max_bytes=AppRegistry.MAX_MANIFEST_BYTES + 8192
            )
            reject_unknown_fields(payload, {"manifest", "expected_revision"})
            preview_result = get_registry().preview(payload.get("manifest", {}))
            if preview_result["app"]["app_id"] != app_id:
                raise RegistryError(409, "app_id_mismatch", "path and manifest app_id do not match")
            result = get_registry().save(
                manifest=payload.get("manifest", {}),
                actor=username,
                expected_revision=str(payload.get("expected_revision", "")),
            )
            return {"ok": True, **result}
        except RegistryError as exc:
            return _failure(exc)
        except SecurityError as exc:
            return _security_failure(exc)

    @router.post("/apps/{app_id}/enable")
    async def enable(request: Request, app_id: str):
        try:
            username = admin(request)
            return {
                "ok": True,
                "app": await get_registry().set_enabled(
                    app_id=app_id, enabled=True, actor=username
                ),
            }
        except RegistryError as exc:
            return _failure(exc)

    @router.post("/apps/{app_id}/disable")
    async def disable(request: Request, app_id: str):
        try:
            username = admin(request)
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {"reason"})
            return {
                "ok": True,
                "app": await get_registry().set_enabled(
                    app_id=app_id,
                    enabled=False,
                    actor=username,
                    reason=str(payload.get("reason", "disabled by administrator")),
                ),
            }
        except RegistryError as exc:
            return _failure(exc)
        except SecurityError as exc:
            return _security_failure(exc)

    return router
