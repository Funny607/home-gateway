from __future__ import annotations

import time
from collections.abc import Callable

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from app.api_v1.actor import ApiActor
from app.api_v1.capabilities import find_capability_for_request
from app.api_v1.errors import gateway_error
from app.api_v1.request_id import get_or_create_request_id
from app.config.schema import CapabilityConfig
from app.lifecycle.manager import LifecycleManager
from app.proxy.reverse_proxy import (
    RequestBodyTooLarge,
    build_api_upstream_headers,
    filter_api_response_headers,
    spool_request_body,
)
from app.proxy.path_security import proxy_path_is_canonical
from app.security.auth import AuthConfig, current_identity, verify_csrf
from app.security.http import bearer_token, client_ip
from app.security.service import SecurityError, SecurityService


def _token_actor(data: dict) -> ApiActor:
    return ApiActor(
        actor_type="device_token",
        actor_name=str(data.get("actor_name", "")),
        role="device",
        device_id=str(data.get("device_id", "")),
        source_id=str(data.get("source_id", "")),
        client_name=str(data.get("client_name", "")),
        grant_id=str(data.get("grant_id", "")),
        token_id=str(data.get("token_id", "")),
        capabilities=set(data.get("capabilities", [])),
    )


def _anonymous_actor() -> ApiActor:
    return ApiActor(actor_type="anonymous", actor_name="", role="anonymous")


def build_api_apps_v1_router(
    *,
    get_manager: Callable[[], LifecycleManager],
    get_http_client: Callable[[], httpx.AsyncClient],
    get_security_service: Callable[[], SecurityService],
    auth_config: AuthConfig,
) -> APIRouter:
    router = APIRouter(prefix="/api/apps/v1", tags=["external-api-apps-v1"])

    def audit(
        *,
        request: Request,
        request_id: str,
        actor: ApiActor,
        capability: CapabilityConfig | None,
        app_id: str,
        upstream_path: str,
        status_code: int,
        success: bool,
        started_at: float,
        error_code: str = "",
        raw: dict | None = None,
    ) -> None:
        try:
            get_security_service().store.write_api_audit(
                request_id=request_id,
                actor_type=actor.actor_type,
                actor_name=actor.actor_name,
                device_id=actor.device_id,
                source_id=actor.source_id,
                client_name=actor.client_name,
                grant_id=actor.grant_id,
                token_id=actor.token_id,
                target_app=app_id,
                capability=capability.id if capability else "",
                method=request.method,
                path=str(request.url.path),
                upstream_path=upstream_path,
                status_code=status_code,
                success=success,
                duration_ms=int((time.monotonic() - started_at) * 1000),
                error_code=error_code,
                risk_level=capability.risk if capability else "",
                client_ip=client_ip(request),
                user_agent=request.headers.get("user-agent", "")[:512],
                raw=(raw or {}) if capability is None or capability.audit else {},
            )
        except Exception as exc:
            get_manager().logger.exception("Security audit write failed: %s", exc)

    def error(
        *,
        request: Request,
        request_id: str,
        actor: ApiActor,
        capability: CapabilityConfig | None,
        app_id: str,
        upstream_path: str,
        status: int,
        code: str,
        message: str,
        started_at: float,
    ):
        audit(
            request=request,
            request_id=request_id,
            actor=actor,
            capability=capability,
            app_id=app_id,
            upstream_path=upstream_path,
            status_code=status,
            success=False,
            started_at=started_at,
            error_code=code,
        )
        return gateway_error(code=code, message=message, request_id=request_id, status_code=status)

    @router.api_route(
        "/{app_id}/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def app_api_proxy(request: Request, app_id: str, full_path: str):
        request_id = get_or_create_request_id(request)
        started_at = time.monotonic()
        manager = get_manager()
        actor = _anonymous_actor()
        capability: CapabilityConfig | None = None
        upstream_path = "/" + full_path.lstrip("/")
        access_token = ""

        if bool(get_security_service().store.get_system_state("external_api_disabled", False)):
            return error(
                request=request, request_id=request_id, actor=actor, capability=None,
                app_id=app_id, upstream_path=upstream_path, status=503,
                code="EXTERNAL_API_DISABLED",
                message="External app API is disabled by emergency policy",
                started_at=started_at,
            )

        if manager.phase != "ready" and manager.gateway_config.recovery_block_requests:
            return error(
                request=request,
                request_id=request_id,
                actor=actor,
                capability=None,
                app_id=app_id,
                upstream_path=upstream_path,
                status=503,
                code="GATEWAY_RECOVERING",
                message="Gateway recovery is still in progress",
                started_at=started_at,
            )

        if not proxy_path_is_canonical(
            upstream_path, request.scope.get("raw_path", b"")
        ):
            return error(
                request=request,
                request_id=request_id,
                actor=actor,
                capability=None,
                app_id=app_id,
                upstream_path=upstream_path,
                status=400,
                code="NON_CANONICAL_PATH",
                message="Encoded separators, dot segments, backslashes, and duplicate slashes are rejected",
                started_at=started_at,
            )

        if app_id not in manager.apps:
            return error(
                request=request, request_id=request_id, actor=actor, capability=None,
                app_id=app_id, upstream_path=upstream_path, status=404,
                code="APP_NOT_FOUND", message="Target app is not registered", started_at=started_at,
            )
        app_state = manager.get_app(app_id)
        config = app_state.config
        if not config.api.enabled:
            return error(
                request=request, request_id=request_id, actor=actor, capability=None,
                app_id=app_id, upstream_path=upstream_path, status=403,
                code="ROUTE_NOT_ALLOWED", message="External API is disabled for this app", started_at=started_at,
            )
        match = find_capability_for_request(config, request.method, upstream_path)
        if match is None:
            return error(
                request=request, request_id=request_id, actor=actor, capability=None,
                app_id=app_id, upstream_path=upstream_path, status=403,
                code="ROUTE_NOT_ALLOWED", message="No capability declares this method and path", started_at=started_at,
            )
        capability = match.capability

        authorization = request.headers.get("authorization", "")
        if authorization:
            try:
                access_token = bearer_token(request)
                token_data = get_security_service().verify_access_token(
                    access_token,
                    target_app=app_id,
                    capability=capability.id,
                    consume=False,
                )
                actor = _token_actor(token_data)
            except SecurityError as exc:
                return error(
                    request=request, request_id=request_id, actor=actor, capability=capability,
                    app_id=app_id, upstream_path=upstream_path, status=exc.status_code,
                    code=exc.code.upper(), message=str(exc), started_at=started_at,
                )
        else:
            identity = current_identity(request, auth_config.session_max_age_seconds)
            if not identity["authenticated"]:
                return error(
                    request=request, request_id=request_id, actor=actor, capability=capability,
                    app_id=app_id, upstream_path=upstream_path, status=401,
                    code="UNAUTHORIZED", message="Admin session or Bearer token is required", started_at=started_at,
                )
            actor = ApiActor(
                actor_type="session",
                actor_name=str(identity["username"]),
                role=str(identity["role"]),
                capabilities={"gateway:admin"} if identity["role"] == "admin" else set(),
            )
            if not actor.is_admin:
                return error(
                    request=request, request_id=request_id, actor=actor, capability=capability,
                    app_id=app_id, upstream_path=upstream_path, status=403,
                    code="CAPABILITY_DENIED", message="Guest sessions cannot call external app APIs", started_at=started_at,
                )
            if capability.risk in {"high", "critical"} or (
                capability.action_policy is not None
                and capability.action_policy.per_action_approval
            ):
                return error(
                    request=request,
                    request_id=request_id,
                    actor=actor,
                    capability=capability,
                    app_id=app_id,
                    upstream_path=upstream_path,
                    status=403,
                    code="APPROVAL_REQUIRED",
                    message="High-risk capability requires an approved device grant and short-lived token",
                    started_at=started_at,
                )
            if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                try:
                    verify_csrf(request, request.headers.get("x-csrf-token"))
                except Exception:
                    return error(
                        request=request, request_id=request_id, actor=actor, capability=capability,
                        app_id=app_id, upstream_path=upstream_path, status=403,
                        code="CSRF_FAILED", message="X-CSRF-Token is required for admin mutations", started_at=started_at,
                    )

        try:
            body = await spool_request_body(
                request,
                max_bytes=config.api.max_request_body_bytes,
                memory_bytes=min(config.proxy.memory_spool_bytes, config.api.max_request_body_bytes),
            )
        except RequestBodyTooLarge:
            return error(
                request=request, request_id=request_id, actor=actor, capability=capability,
                app_id=app_id, upstream_path=upstream_path, status=413,
                code="REQUEST_TOO_LARGE", message="Request body exceeds app API policy", started_at=started_at,
            )
        except ValueError:
            return error(
                request=request, request_id=request_id, actor=actor, capability=capability,
                app_id=app_id, upstream_path=upstream_path, status=400,
                code="INVALID_CONTENT_LENGTH", message="Content-Length is invalid", started_at=started_at,
            )

        if access_token:
            bound_path = upstream_path + (f"?{request.url.query}" if request.url.query else "")
            try:
                token_data = get_security_service().verify_access_token(
                    access_token,
                    target_app=app_id,
                    capability=capability.id,
                    consume=True,
                    method=request.method,
                    path=bound_path,
                    body_sha256=body.sha256_hex,
                )
                actor = _token_actor(token_data)
            except SecurityError as exc:
                body.close()
                return error(
                    request=request, request_id=request_id, actor=actor, capability=capability,
                    app_id=app_id, upstream_path=upstream_path, status=exc.status_code,
                    code=exc.code.upper(), message=str(exc), started_at=started_at,
                )

        app_is_running = app_state.state == "running" and app_state.runtime is not None
        auto_start = capability.auto_start if capability.auto_start is not None else config.api.auto_start
        if not app_is_running:
            if not auto_start:
                body.close()
                return error(
                    request=request, request_id=request_id, actor=actor, capability=capability,
                    app_id=app_id, upstream_path=upstream_path, status=409,
                    code="APP_NOT_RUNNING", message="Target app is stopped and capability auto-start is disabled", started_at=started_at,
                )
            try:
                record = await manager.ensure_started(app_id)
            except Exception as exc:
                body.close()
                return error(
                    request=request, request_id=request_id, actor=actor, capability=capability,
                    app_id=app_id, upstream_path=upstream_path, status=502,
                    code="APP_START_FAILED", message=str(exc), started_at=started_at,
                )
        else:
            record = app_state.runtime

        target_url = f"{record.internal_url}{upstream_path}"
        if request.url.query:
            target_url += f"?{request.url.query}"
        headers = build_api_upstream_headers(
            request,
            app_id=app_id,
            capability_id=capability.id,
            actor_type=actor.actor_type,
            actor_name=actor.actor_name,
            device_id=actor.device_id,
            source_id=actor.source_id,
            request_id=request_id,
        )
        timeout = float(config.api.timeout_seconds)
        try:
            upstream_request = get_http_client().build_request(
                request.method, target_url, headers=headers, content=body.chunks()
            )
            upstream_request.extensions["timeout"] = {
                "connect": timeout, "read": timeout, "write": timeout, "pool": timeout
            }
            upstream_response = await get_http_client().send(upstream_request, stream=True)
        except httpx.TimeoutException:
            body.close()
            manager.mark_proxy_error(app_id, upstream_path, "upstream timed out")
            return error(
                request=request, request_id=request_id, actor=actor, capability=capability,
                app_id=app_id, upstream_path=upstream_path, status=504,
                code="UPSTREAM_TIMEOUT", message="Target app timed out", started_at=started_at,
            )
        except httpx.RequestError as exc:
            body.close()
            manager.mark_proxy_error(app_id, upstream_path, str(exc))
            return error(
                request=request, request_id=request_id, actor=actor, capability=capability,
                app_id=app_id, upstream_path=upstream_path, status=502,
                code="UPSTREAM_ERROR", message=str(exc), started_at=started_at,
            )

        if capability.activity != "ignore":
            manager.touch_request(app_id, request.method, upstream_path)
        if capability.activity == "user":
            manager.touch_user_activity(app_id, upstream_path)
        manager.mark_upstream_status(app_id, upstream_response.status_code)
        if upstream_response.status_code >= 500:
            manager.mark_proxy_error(
                app_id,
                upstream_path,
                f"upstream returned {upstream_response.status_code}",
            )
        else:
            manager.clear_proxy_error(app_id)
        success = upstream_response.status_code < 500
        audit(
            request=request,
            request_id=request_id,
            actor=actor,
            capability=capability,
            app_id=app_id,
            upstream_path=upstream_path,
            status_code=upstream_response.status_code,
            success=success,
            started_at=started_at,
            error_code="" if success else "UPSTREAM_ERROR",
            raw={"match_type": match.match_type},
        )
        response_headers = filter_api_response_headers(upstream_response.headers.multi_items())
        response_headers.update(
            {
                "X-Gateway-Request-Id": request_id,
                "X-Gateway-Capability": capability.id,
                "X-Gateway-Actor-Type": actor.actor_type,
            }
        )

        async def iterator():
            try:
                async for chunk in upstream_response.aiter_raw():
                    yield chunk
            except httpx.RequestError as exc:
                manager.mark_proxy_error(app_id, upstream_path, f"stream interrupted: {exc}")
                audit(
                    request=request,
                    request_id=request_id,
                    actor=actor,
                    capability=capability,
                    app_id=app_id,
                    upstream_path=upstream_path,
                    status_code=502,
                    success=False,
                    started_at=started_at,
                    error_code="UPSTREAM_STREAM_ERROR",
                    raw={"reason": str(exc)},
                )
                raise
            finally:
                await upstream_response.aclose()
                body.close()

        return StreamingResponse(iterator(), status_code=upstream_response.status_code, headers=response_headers)

    return router
