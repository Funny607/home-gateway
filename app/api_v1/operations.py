from __future__ import annotations

import hmac
import html
from collections.abc import Callable
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from app.operations.service import OperationsService
from app.security.auth import AuthConfig, csrf_token, require_admin, verify_csrf
from app.security.http import client_ip, read_json_object, reject_unknown_fields, security_error_response
from app.security.rate_limit import SlidingWindowRateLimiter
from app.security.recovery import RecoveryService
from app.security.service import SecurityError
from app.ui import design as ui
from app.ui.pages import format_ts


def _h(value) -> str:
    return html.escape("" if value is None else str(value))


def _emergency_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "breakglass" or not token:
        raise SecurityError(401, "emergency_token_required", "Authorization: BreakGlass token is required")
    return token.strip()


def build_operations_router(
    *,
    get_operations: Callable[[], OperationsService],
    get_recovery: Callable[[], RecoveryService],
    auth_config: AuthConfig,
    rate_limiter: SlidingWindowRateLimiter,
    render_page: Callable[..., HTMLResponse],
) -> APIRouter:
    router = APIRouter(tags=["operations"])

    @router.get("/dashboard/operations", response_class=HTMLResponse, response_model=None)
    async def operations_page(request: Request):
        try:
            username = require_admin(request, auth_config.session_max_age_seconds)
        except HTTPException:
            return RedirectResponse("/login", status_code=303)
        operations = get_operations()
        recovery = get_recovery()
        status = operations.status()
        recovery_status = recovery.status()
        backups = operations.list_backups()[:10]
        diagnostics = operations.list_diagnostics()[:10]
        rows = "".join(
            f'<tr><td>{_h(item["filename"])}</td><td>{_h(item["size"])}</td>'
            f'<td>{_h(format_ts(item["modified_at"]))}</td><td>{ui.status_badge("healthy" if item["verification"].get("ok") else "failed")}</td>'
            f'<td><a class="button secondary" href="/api/operations/v1/backups/{quote(item["filename"])}">下载</a></td></tr>'
            for item in backups
        )
        diagnostic_rows = "".join(
            f'<tr><td>{_h(item["filename"])}</td><td>{_h(item["size"])}</td>'
            f'<td>{_h(format_ts(item["modified_at"]))}</td>'
            f'<td><a class="button secondary" href="/api/operations/v1/diagnostics/{quote(item["filename"])}">下载</a></td></tr>'
            for item in diagnostics
        )
        token = csrf_token(request)
        content = f"""
        <section class="metrics-grid">
          <div class="metric"><span>版本</span><strong class="metric-value">{_h(status['release_version'])}</strong></div>
          <div class="metric"><span>备份</span><strong class="metric-value">{_h(status['backup_count'])}</strong></div>
          <div class="metric"><span>恢复码</span><strong class="metric-value">{_h(recovery_status['active_recovery_codes'])}</strong></div>
          <div class="metric"><span>外部 API</span><strong class="metric-value">{'已禁用' if recovery_status['external_api_disabled'] else '正常'}</strong></div>
        </section>
        {ui.notice('Break-glass 只能执行备份、禁用外部 API 和撤销外部访问，不能创建管理员会话。', kind='warning', title='受限应急模式')}
        <section class="surface surface-padded"><div class="section-header"><div><h2>运维操作</h2><p>所有操作都会写入审计或运行状态。</p></div></div>
          <div class="table-actions">
            <form method="post" action="/dashboard/operations/backup"><input type="hidden" name="csrf_token" value="{_h(token)}"><button class="button primary">立即备份</button></form>
            <form method="post" action="/dashboard/operations/diagnostics"><input type="hidden" name="csrf_token" value="{_h(token)}"><button class="button secondary">生成诊断包</button></form>
            <form method="post" action="/dashboard/operations/external-api/enable" data-confirm-title="重新启用外部 API" data-confirm-message="确认应急处置已经完成。"><input type="hidden" name="csrf_token" value="{_h(token)}"><button class="button secondary">重新启用外部 API</button></form>
          </div>
        </section>
        <section class="surface"><div class="data-table-wrap"><table class="data-table"><thead><tr><th>备份</th><th>大小</th><th>时间</th><th>验证</th><th>操作</th></tr></thead><tbody>{rows}</tbody></table></div></section>
        <section><div class="section-header"><div><h2>诊断包</h2><p>只保留脱敏配置、状态与日志尾部。</p></div></div><div class="surface"><div class="data-table-wrap"><table class="data-table"><thead><tr><th>诊断包</th><th>大小</th><th>时间</th><th>操作</th></tr></thead><tbody>{diagnostic_rows}</tbody></table></div></div></section>
        """
        return render_page(
            request, title="运维与恢复", description="管理备份、诊断、版本和受限应急状态。",
            content=content, active_nav="settings", breadcrumbs=(("设置", "/dashboard/settings"), ("运维与恢复", "")),
            flash_message=str(request.query_params.get("message", "")),
        )

    @router.post("/dashboard/operations/backup")
    async def backup_form(request: Request):
        username = require_admin(request, auth_config.session_max_age_seconds)
        form = await request.form()
        verify_csrf(request, str(form.get("csrf_token", "")))
        result = get_operations().create_backup(reason="manual web backup", actor=username)
        return RedirectResponse(f"/dashboard/operations?message={quote('备份已创建：' + result['filename'])}", status_code=303)

    @router.post("/dashboard/operations/diagnostics")
    async def diagnostics_form(request: Request):
        username = require_admin(request, auth_config.session_max_age_seconds)
        form = await request.form()
        verify_csrf(request, str(form.get("csrf_token", "")))
        result = get_operations().create_diagnostic_bundle(actor=username)
        return RedirectResponse(f"/dashboard/operations?message={quote('诊断包已创建：' + result['filename'])}", status_code=303)

    @router.post("/dashboard/operations/external-api/enable")
    async def enable_external_form(request: Request):
        username = require_admin(request, auth_config.session_max_age_seconds)
        form = await request.form()
        verify_csrf(request, str(form.get("csrf_token", "")))
        get_recovery().set_external_api_disabled(False, actor=username)
        return RedirectResponse("/dashboard/operations?message=外部%20API%20已重新启用", status_code=303)

    @router.get("/api/operations/v1/status")
    async def operations_status(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, "operations": get_operations().status(), "recovery": get_recovery().status()}

    @router.post("/api/operations/v1/backups")
    async def create_backup_api(request: Request):
        username = require_admin(request, auth_config.session_max_age_seconds)
        payload = await read_json_object(request)
        verify_csrf(request, request.headers.get("x-csrf-token"))
        return {"ok": True, "backup": get_operations().create_backup(
            reason=str(payload.get("reason", "manual API backup")), actor=username
        )}

    @router.get("/api/operations/v1/backups")
    async def list_backups_api(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, "items": get_operations().list_backups()}

    @router.get("/api/operations/v1/backups/{filename}")
    async def download_backup(request: Request, filename: str):
        require_admin(request, auth_config.session_max_age_seconds)
        try:
            path = get_operations().backup_path(filename)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return FileResponse(path, media_type="application/zip", filename=path.name)

    @router.post("/api/operations/v1/diagnostics")
    async def create_diagnostics_api(request: Request):
        username = require_admin(request, auth_config.session_max_age_seconds)
        verify_csrf(request, request.headers.get("x-csrf-token"))
        return {"ok": True, "diagnostic": get_operations().create_diagnostic_bundle(actor=username)}

    @router.get("/api/operations/v1/diagnostics")
    async def list_diagnostics_api(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, "items": get_operations().list_diagnostics()}

    @router.get("/api/operations/v1/diagnostics/{filename}")
    async def download_diagnostics(request: Request, filename: str):
        require_admin(request, auth_config.session_max_age_seconds)
        try:
            path = get_operations().diagnostic_path(filename)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return FileResponse(path, media_type="application/zip", filename=path.name)

    @router.post("/api/emergency/v1/activate")
    async def activate_emergency(request: Request):
        recovery = get_recovery()
        decision = rate_limiter.check(
            f"breakglass-activate:{client_ip(request)}",
            limit=5,
            window_seconds=900,
            block_seconds=900,
        )
        if not decision.allowed:
            return security_error_response(
                request,
                SecurityError(429, "rate_limited", f"retry after {decision.retry_after_seconds} seconds"),
            )
        supplied = request.headers.get("x-breakglass-secret", "")
        if not recovery.verifier_secret or not hmac.compare_digest(supplied, recovery.verifier_secret):
            return security_error_response(request, SecurityError(401, "breakglass_verifier_denied", "local break-glass verifier is invalid"))
        try:
            payload = await read_json_object(request)
            reject_unknown_fields(payload, {"recovery_code", "reason"})
            return {"ok": True, **recovery.activate(
                recovery_code=str(payload.get("recovery_code", "")), reason=str(payload.get("reason", ""))
            )}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.get("/api/emergency/v1/status")
    async def emergency_status(request: Request):
        recovery = get_recovery()
        recovery.verify_token(_emergency_token(request))
        return {"ok": True, **recovery.status()}

    @router.post("/api/emergency/v1/disable-external-api")
    async def disable_external_api(request: Request):
        recovery = get_recovery()
        actor = recovery.verify_token(_emergency_token(request))["token_id"]
        recovery.set_external_api_disabled(True, actor=actor)
        return {"ok": True, "external_api_disabled": True, "actor": actor}

    @router.post("/api/emergency/v1/revoke-all-access")
    async def revoke_all_access(request: Request):
        recovery = get_recovery()
        actor = recovery.verify_token(_emergency_token(request))["token_id"]
        return {"ok": True, **recovery.revoke_all_external_access(actor=actor)}

    @router.post("/api/emergency/v1/create-backup")
    async def emergency_backup(request: Request):
        recovery = get_recovery()
        actor = recovery.verify_token(_emergency_token(request))["token_id"]
        return {"ok": True, "backup": get_operations().create_backup(reason="break-glass backup", actor=actor)}

    return router
