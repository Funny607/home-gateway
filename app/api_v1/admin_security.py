from __future__ import annotations

import html
import time
from collections.abc import Callable
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.security.auth import AuthConfig, csrf_token, require_admin, verify_csrf
from app.security.http import read_json_object, security_error_response
from app.security.service import SecurityError, SecurityService
from app.ui import design as ui
from app.ui.pages import format_ts, section_tabs


def _h(value) -> str:
    return html.escape("" if value is None else str(value))




def _admin_or_redirect(request: Request, config: AuthConfig) -> str | RedirectResponse:
    try:
        return require_admin(request, config.session_max_age_seconds)
    except HTTPException as exc:
        target = "/login" if exc.status_code == 401 else "/dashboard"
        return RedirectResponse(target, status_code=303)


def _form_csrf(request: Request) -> str:
    return f'<input type="hidden" name="csrf_token" value="{_h(csrf_token(request))}">'


def _security_tabs(current: str) -> str:
    return section_tabs(
        (
            ("overview", "安全概况", "/dashboard/security"),
            ("devices", "设备", "/dashboard/devices"),
            ("grants", "授权", "/dashboard/grants"),
            ("approvals", "审批", "/dashboard/approvals"),
            ("leases", "Lease", "/dashboard/leases"),
        ),
        current,
    )


def _pill_list(values) -> str:
    return '<span class="pill-list">' + "".join(
        f'<span class="pill">{_h(value)}</span>' for value in (values or [])
    ) + "</span>"


def _render_security_overview(service: SecurityService) -> str:
    summary = service.security_summary()
    pending = [row for row in service.list_approvals() if row.get("status") == "pending"]
    devices = service.list_devices()
    active_devices = sum(1 for row in devices if row.get("status") == "active")
    metrics = "".join(
        (
            '<div class="metric"><div class="metric-header"><span>受信设备</span>'
            f'{ui.icon("device", size=18)}</div><strong class="metric-value">{active_devices}</strong><span class="metric-detail">可申请细粒度授权</span></div>',
            '<div class="metric"><div class="metric-header"><span>待审批</span>'
            f'{ui.icon("approval", size=18)}</div><strong class="metric-value">{len(pending)}</strong><span class="metric-detail">需要管理员决定</span></div>',
            '<div class="metric"><div class="metric-header"><span>活动 Token</span>'
            f'{ui.icon("grant", size=18)}</div><strong class="metric-value">{summary.get("active_tokens", 0)}</strong><span class="metric-detail">短时访问凭据</span></div>',
            '<div class="metric"><div class="metric-header"><span>活动 Lease</span>'
            f'{ui.icon("clock", size=18)}</div><strong class="metric-value">{summary.get("active_leases", 0)}</strong><span class="metric-detail">受监控的临时状态</span></div>',
        )
    )
    queue = []
    for row in pending[:6]:
        target = row.get("target_app") or row.get("device_id") or "未知目标"
        queue.append(
            '<li class="attention-item"><span class="attention-icon">'
            f'{ui.icon("approval", size=17)}</span><span class="item-copy"><strong>{_h(row.get("approval_type"))}</strong>'
            f'<small>{_h(target)} · {_h(row.get("risk_level", "medium"))} 风险 · {_h(format_ts(row.get("expires_at")))} 到期</small></span>'
            '<a class="button secondary" href="/dashboard/approvals?status=pending">审查</a></li>'
        )
    queue_html = (
        f'<ul class="attention-list">{"".join(queue)}</ul>'
        if queue
        else ui.empty_state("审批队列为空", "目前没有设备注册或能力授权等待决定。", icon_name="check")
    )
    return f"""
    <section class="metrics-grid" aria-label="安全指标">{metrics}</section>
    <div class="split-grid">
      <section><div class="section-header"><div><h2>等待决定</h2><p>每项审批都要求核对发起设备、能力、风险与请求码。</p></div><a class="section-link" href="/dashboard/approvals">查看全部</a></div><div class="surface">{queue_html}</div></section>
      <section><div class="section-header"><div><h2>外部访问闭环</h2><p>外部程序不能绕过其中任一步骤。</p></div></div><div class="surface surface-padded">
        <ol class="security-flow"><li>设备注册</li><li>管理员审批设备</li><li>申请 capability grant</li><li>管理员审批授权</li><li>签发短时 token</li><li>受控代理与审计</li></ol>
      </div></section>
    </div>
    {ui.notice("长期保存的是设备凭据与 grant；access token 必须短时，并且每次调用都会写入审计。", kind="info", title="默认安全模型")}
    """


def _render_devices(request: Request, rows: list[dict]) -> str:
    body_rows = []
    for row in rows:
        revoked = row.get("status") == "revoked"
        action = '<span class="result-count">不可操作</span>' if revoked else (
            f'<details class="details-menu"><summary class="button secondary">管理</summary><div class="details-popover">'
            f'<form method="post" action="/dashboard/devices/{quote(row["device_id"])}/update">{_form_csrf(request)}'
            f'<label class="field"><span>设备名称</span><input name="device_name" value="{_h(row.get("device_name"))}" required></label>'
            f'<label class="field"><span>信任等级</span><select name="trust_level">'
            + "".join(
                f'<option value="{level}"{" selected" if row.get("trust_level") == level else ""}>{level}</option>'
                for level in ("paired", "trusted", "privileged")
            )
            + '</select></label>'
            '<label class="field"><span>续期天数</span><input type="number" name="trust_days" min="1" max="365" value="365"></label>'
            '<button class="button primary" type="submit">保存并续期</button></form>'
            f'<form method="post" action="/dashboard/devices/{quote(row["device_id"])}/rotate" data-confirm-title="轮换设备凭据" data-confirm-message="旧凭据、grant、token 将立即失效。" data-confirm-label="确认轮换" data-confirm-kind="danger">{_form_csrf(request)}<button class="button danger" type="submit">轮换凭据</button></form>'
            '</div></details>'
            f'<form class="inline-form" method="post" action="/dashboard/devices/{quote(row["device_id"])}/revoke" '
            'data-confirm-title="撤销设备信任" '
            f'data-confirm-message="将撤销 {_h(row["device_name"])}，并级联撤销其 grant 与 token；活动 lease 将进入恢复流程。" '
            'data-confirm-label="撤销设备" data-confirm-kind="danger">'
            f'{_form_csrf(request)}<button class="button danger" type="submit">撤销</button></form>'
        )
        body_rows.append(
            f'<tr data-search="{_h(row.get("device_name"))} {_h(row.get("device_id"))} {_h(row.get("status"))}"><td><div class="primary-cell"><span class="object-icon">{ui.icon("device", size=17)}</span>'
            f'<span class="primary-cell-copy"><strong>{_h(row.get("device_name"))}</strong><small>{_h(row.get("device_id"))}</small></span></div></td>'
            f'<td data-label="类型">{_h(row.get("device_type"))}</td><td data-label="状态">{ui.status_badge(str(row.get("status")))}</td>'
            f'<td data-label="信任">{ui.status_badge(str(row.get("trust_level")))}</td><td data-label="信任到期">{_h(format_ts(row.get("trust_expires_at")))}</td>'
            f'<td data-label="最近活动">{_h(format_ts(row.get("last_seen_at")))}</td><td data-label="操作"><div class="table-actions">{action}</div></td></tr>'
        )
    table = (
        '<div class="data-table-wrap"><table class="data-table"><thead><tr><th>设备</th><th>类型</th><th>状态</th><th>信任</th><th>信任到期</th><th>最近活动</th><th>操作</th></tr></thead>'
        f'<tbody id="device-table-body">{"".join(body_rows)}</tbody></table></div>'
        if body_rows else ui.empty_state("暂无设备", "设备完成注册后，会在这里等待审批或显示信任状态。", icon_name="device")
    )
    return f"""{ui.notice("撤销设备会同时撤销其 grant 与 token；活动 lease 会先进入安全恢复。", kind="warning")}
    <section class="surface"><div class="command-bar"><label class="search-field">{ui.icon("search", size=17)}<span class="sr-only">搜索设备</span><input type="search" placeholder="搜索设备名称、ID 或状态…" data-table-filter="#device-table-body"></label><span class="result-count">{len(rows)} 台设备</span></div>{table}</section>"""


def _render_grants(request: Request, rows: list[dict]) -> str:
    body_rows = []
    for row in rows:
        revoked = bool(row.get("revoked_at"))
        state = "revoked" if revoked else ("expired" if int(row.get("expires_at") or 0) <= int(time.time()) else "active")
        action = '<span class="result-count">不可操作</span>' if revoked else (
            f'<form class="inline-form" method="post" action="/dashboard/grants/{quote(row["grant_id"])}/revoke" '
            'data-confirm-title="撤销能力授权" '
            f'data-confirm-message="将立即终止 grant {_h(row["grant_id"])} 及其签发的 token。" '
            'data-confirm-label="撤销授权" data-confirm-kind="danger">'
            f'{_form_csrf(request)}<button class="button danger" type="submit">撤销</button></form>'
        )
        body_rows.append(
            f'<tr data-search="{_h(row.get("grant_id"))} {_h(row.get("device_id"))} {_h(row.get("target_app"))}"><td><div class="primary-cell"><span class="object-icon">{ui.icon("grant", size=17)}</span>'
            f'<span class="primary-cell-copy"><strong>{_h(row.get("target_app"))}</strong><small>{_h(row.get("grant_id"))}</small></span></div></td>'
            f'<td data-label="设备"><code>{_h(row.get("device_id"))}</code></td><td data-label="Capabilities">{_pill_list(row.get("capabilities"))}</td>'
            f'<td data-label="风险">{ui.status_badge(str(row.get("risk_level")), str(row.get("risk_level", "-")).replace("_", " "))}</td>'
            f'<td data-label="到期">{_h(format_ts(row.get("expires_at")))}</td><td data-label="状态">{ui.status_badge(state)}</td>'
            f'<td data-label="操作"><div class="table-actions">{action}</div></td></tr>'
        )
    table = (
        '<div class="data-table-wrap"><table class="data-table"><thead><tr><th>应用 / Grant</th><th>设备</th><th>Capabilities</th><th>风险</th><th>到期</th><th>状态</th><th>操作</th></tr></thead>'
        f'<tbody id="grant-table-body">{"".join(body_rows)}</tbody></table></div>'
        if body_rows else ui.empty_state("暂无授权", "受信设备申请 capability 后，grant 会在这里显示。", icon_name="grant")
    )
    return f"""{ui.notice("Grant 是设备与 capability 的细粒度长期关系；真正调用时仍需签发短时 token。", kind="info")}
    <section class="surface"><div class="command-bar"><label class="search-field">{ui.icon("search", size=17)}<span class="sr-only">搜索授权</span><input type="search" placeholder="搜索 Grant、设备或应用…" data-table-filter="#grant-table-body"></label><span class="result-count">{len(rows)} 项授权</span></div>{table}</section>"""


def _render_approvals(request: Request, rows: list[dict], status_filter: str = "") -> str:
    cards = []
    ordered = sorted(rows, key=lambda row: (row.get("status") != "pending", -(int(row.get("created_at") or 0))))
    for row in ordered:
        pending = row.get("status") == "pending"
        target = row.get("target_app") or row.get("device_id") or "未知目标"
        actions = ""
        action_binding = ""
        if row.get("approval_type") == "action":
            action_binding = (
                '<div class="notice notice-warning"><strong>本次批准严格绑定</strong><br>'
                f'<code>{_h(row.get("action_method"))} {_h(row.get("action_path"))}</code><br>'
                f'<span>{_h(row.get("payload_preview") or "（无 payload 预览）")}</span><br>'
                f'<small>Body SHA-256: {_h(row.get("body_sha256"))}</small></div>'
            )
        browser_methods = set(row.get("required_approval_methods", [])) & {"web-admin", "totp"}
        if pending and browser_methods:
            trust = ""
            if row.get("approval_type") == "device_registration":
                trust = '<label class="field"><span>信任级别</span><select name="trust_level"><option value="paired">paired</option><option value="trusted">trusted</option><option value="privileged">privileged</option></select></label>'
            actions = (
                f'<form class="approval-form" method="post" action="/dashboard/approvals/{quote(row["approval_id"])}/approve" data-loading-form>'
                f'{_form_csrf(request)}{trust}<label class="field"><span>批准方式</span><select name="approval_method">'
                + ('<option value="web-admin">网页管理员</option>' if "web-admin" in browser_methods else '')
                + ('<option value="totp">Microsoft Authenticator</option>' if "totp" in row.get("required_approval_methods", []) else '')
                + '</select></label><label class="field"><span>请求码</span><input name="request_code" placeholder="XXXXX-XXXXX" autocomplete="one-time-code" required></label>'
                '<label class="field"><span>TOTP（选择 Authenticator 时填写）</span><input name="totp_code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code"></label>'
                '<button class="button primary" type="submit">批准</button></form>'
                f'<form class="inline-form" method="post" action="/dashboard/approvals/{quote(row["approval_id"])}/deny" data-confirm-title="拒绝审批" '
                f'data-confirm-message="将拒绝对 {target} 的本次请求。设备或程序需要重新发起。" data-confirm-label="确认拒绝" data-confirm-kind="danger">'
                f'{_form_csrf(request)}<button class="button danger" type="submit">拒绝</button></form>'
            )
        elif pending:
            actions = f'<div class="notice notice-warning">等待 {_pill_list(row.get("required_approval_methods"))}</div>'
        cards.append(
            '<article class="approval-card"><div class="approval-header"><span class="object-icon">'
            f'{ui.icon("approval", size=17)}</span><span class="item-copy"><strong>{_h(row.get("approval_type"))} · {_h(target)}</strong>'
            f'<small>{_h(row.get("approval_id"))}</small></span>{ui.status_badge(str(row.get("status")))}</div>'
            '<div class="approval-meta">'
            f'<span class="meta-block"><small>风险</small><strong>{_h(row.get("risk_level"))}</strong></span>'
            f'<span class="meta-block"><small>设备</small><code>{_h(row.get("device_id") or "-")}</code></span>'
            f'<span class="meta-block"><small>到期</small><strong>{_h(format_ts(row.get("expires_at")))}</strong></span>'
            f'<span class="meta-block"><small>Capabilities</small>{_pill_list(row.get("requested_capabilities"))}</span></div>{action_binding}{actions}</article>'
        )
    filter_options = []
    for value, label in (("", "全部状态"), ("pending", "待审批"), ("approved", "已批准"), ("denied", "已拒绝"), ("expired", "已过期")):
        selected = " selected" if status_filter == value else ""
        filter_options.append(f'<option value="{value}"{selected}>{label}</option>')
    filter_bar = (
        '<form class="command-bar" method="get" action="/dashboard/approvals">'
        f'<label class="field"><span class="sr-only">审批状态</span><select class="select" name="status" data-auto-submit>{"".join(filter_options)}</select></label>'
        f'<span class="result-count">{len(rows)} 条记录</span></form>'
    )
    return (
        f'{ui.notice("批准前同时核对发起设备上的请求码、目标 capability、风险等级与到期时间。", kind="warning", title="审批核对")}'
        f'<section class="surface">{filter_bar}{"".join(cards)}</section>'
        if cards else f'<section class="surface">{filter_bar}{ui.empty_state("暂无审批", "当前筛选下没有设备注册或 capability grant 请求。", icon_name="approval")}</section>'
    )


def _render_leases(rows: list[dict]) -> str:
    body_rows = []
    for row in rows:
        body_rows.append(
            f'<tr data-search="{_h(row.get("lease_id"))} {_h(row.get("device_id"))} {_h(row.get("target_app"))} {_h(row.get("status"))}"><td><div class="primary-cell"><span class="object-icon">{ui.icon("clock", size=17)}</span>'
            f'<span class="primary-cell-copy"><strong>{_h(row.get("target_app"))}</strong><small>{_h(row.get("lease_id"))}</small></span></div></td>'
            f'<td data-label="设备"><code>{_h(row.get("device_id"))}</code></td><td data-label="Capability"><code>{_h(row.get("capability"))}</code></td>'
            f'<td data-label="状态">{ui.status_badge(str(row.get("status")))}</td><td data-label="到期">{_h(format_ts(row.get("expires_at")))}</td>'
            f'<td data-label="最近心跳">{_h(format_ts(row.get("last_heartbeat_at")))}</td><td data-label="释放原因">{_h(row.get("release_reason") or "-")}</td></tr>'
        )
    table = (
        '<div class="data-table-wrap"><table class="data-table"><thead><tr><th>应用 / Lease</th><th>设备</th><th>Capability</th><th>状态</th><th>到期</th><th>最近心跳</th><th>释放原因</th></tr></thead>'
        f'<tbody id="lease-table-body">{"".join(body_rows)}</tbody></table></div>'
        if body_rows else ui.empty_state("暂无 Lease", "外部 watcher 创建临时状态后，心跳和恢复进度会显示在这里。", icon_name="clock")
    )
    return f"""{ui.notice("Lease 丢失心跳、到期、设备或 grant 被撤销时，Gateway 会进入 releasing 并尝试恢复 App 状态。", kind="info")}
    <section class="surface"><div class="command-bar"><label class="search-field">{ui.icon("search", size=17)}<span class="sr-only">搜索 Lease</span><input type="search" placeholder="搜索 Lease、设备、应用或状态…" data-table-filter="#lease-table-body"></label><span class="result-count">{len(rows)} 条记录</span></div>{table}</section>"""


async def _json_admin_mutation(request: Request, config: AuthConfig) -> tuple[str, dict]:
    username = require_admin(request, config.session_max_age_seconds)
    payload = await read_json_object(request)
    verify_csrf(request, request.headers.get("x-csrf-token"))
    return username, payload


def build_admin_security_router(
    *,
    get_security_service: Callable[[], SecurityService],
    auth_config: AuthConfig,
    render_page: Callable[..., HTMLResponse],
) -> APIRouter:
    router = APIRouter(tags=["admin-security"])

    @router.get("/api/auth/v1/csrf")
    async def get_csrf(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, "csrf_token": csrf_token(request)}

    @router.get("/dashboard/security", response_class=HTMLResponse, response_model=None)
    async def security_page(request: Request):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        return render_page(
            request,
            title="安全",
            description="管理外部设备从注册、授权、短时 token 到受控代理的完整信任链。",
            content=_render_security_overview(get_security_service()),
            active_nav="security",
            section_tabs=_security_tabs("overview"),
            page_actions=f'<a class="button secondary" href="/dashboard/security">{ui.icon("refresh", size=16)}刷新</a>',
        )

    @router.get("/dashboard/devices", response_class=HTMLResponse, response_model=None)
    async def devices_page(request: Request):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        rows = get_security_service().list_devices()
        return render_page(
            request,
            title="设备",
            description="确认哪些外部设备受到信任，并在必要时级联撤销其访问。",
            content=_render_devices(request, rows),
            active_nav="security",
            section_tabs=_security_tabs("devices"),
            breadcrumbs=(("安全", "/dashboard/security"), ("设备", "")),
            page_actions=f'<a class="button secondary" href="/dashboard/devices">{ui.icon("refresh", size=16)}刷新</a>',
            flash_message=str(request.query_params.get("message", "")),
        )

    @router.get("/dashboard/grants", response_class=HTMLResponse, response_model=None)
    async def grants_page(request: Request):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        rows = get_security_service().list_grants()
        return render_page(
            request,
            title="授权",
            description="查看设备被授予的具体 capability、风险、期限和当前有效性。",
            content=_render_grants(request, rows),
            active_nav="security",
            section_tabs=_security_tabs("grants"),
            breadcrumbs=(("安全", "/dashboard/security"), ("授权", "")),
            page_actions=f'<a class="button secondary" href="/dashboard/grants">{ui.icon("refresh", size=16)}刷新</a>',
        )

    @router.get("/dashboard/approvals", response_class=HTMLResponse, response_model=None)
    async def approvals_page(
        request: Request,
        status: str = Query(default="", max_length=16),
    ):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        if status not in {"", "pending", "approved", "denied", "expired"}:
            status = ""
        rows = get_security_service().list_approvals()
        if status:
            rows = [row for row in rows if row.get("status") == status]
        return render_page(
            request,
            title="审批",
            description="结合设备请求码、能力范围、风险和期限作出明确决定。",
            content=_render_approvals(request, rows, status),
            active_nav="security",
            section_tabs=_security_tabs("approvals"),
            breadcrumbs=(("安全", "/dashboard/security"), ("审批", "")),
            page_actions=f'<a class="button secondary" href="/dashboard/approvals{("?status=" + quote(status)) if status else ""}">{ui.icon("refresh", size=16)}刷新</a>',
            flash_message=str(request.query_params.get("message", "")),
        )

    @router.get("/dashboard/leases", response_class=HTMLResponse, response_model=None)
    async def leases_page(request: Request):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        rows = get_security_service().list_leases(limit=500)
        return render_page(
            request,
            title="Lease",
            description="观察临时状态的心跳、到期、释放和异常恢复，不直接绕过设备控制流程。",
            content=_render_leases(rows),
            active_nav="security",
            section_tabs=_security_tabs("leases"),
            breadcrumbs=(("安全", "/dashboard/security"), ("Lease", "")),
            page_actions=f'<a class="button secondary" href="/dashboard/leases">{ui.icon("refresh", size=16)}刷新</a>',
        )

    @router.post("/dashboard/approvals/{approval_id}/approve")
    async def approve_form(request: Request, approval_id: str):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        form = await request.form()
        try:
            verify_csrf(request, str(form.get("csrf_token", "")))
            get_security_service().approve(
                approval_id=approval_id,
                approved_by=str(auth),
                approval_method=str(form.get("approval_method", "web-admin")),
                device_trust_level=str(form.get("trust_level", "paired")),
                request_code=str(form.get("request_code", "")),
                totp_code=str(form.get("totp_code", "")),
            )
            message = "审批已批准"
        except (HTTPException, SecurityError) as exc:
            message = f"操作失败：{exc}"
        return RedirectResponse(f"/dashboard/approvals?message={quote(message)}", status_code=303)

    @router.post("/dashboard/approvals/{approval_id}/deny")
    async def deny_form(request: Request, approval_id: str):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        form = await request.form()
        try:
            verify_csrf(request, str(form.get("csrf_token", "")))
            get_security_service().deny(approval_id=approval_id, denied_by=str(auth))
        except (HTTPException, SecurityError):
            pass
        return RedirectResponse("/dashboard/approvals", status_code=303)

    @router.post("/dashboard/devices/{device_id}/revoke")
    async def revoke_device_form(request: Request, device_id: str):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        form = await request.form()
        try:
            verify_csrf(request, str(form.get("csrf_token", "")))
            get_security_service().revoke_device(device_id=device_id, revoked_by=str(auth), reason="web admin")
            message = "设备已撤销"
        except (HTTPException, SecurityError) as exc:
            message = f"操作失败：{exc}"
        return RedirectResponse(f"/dashboard/devices?message={quote(message)}", status_code=303)

    @router.post("/dashboard/devices/{device_id}/update")
    async def update_device_form(request: Request, device_id: str):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        form = await request.form()
        try:
            verify_csrf(request, str(form.get("csrf_token", "")))
            get_security_service().update_device(
                device_id=device_id, updated_by=str(auth), device_name=str(form.get("device_name", "")),
                trust_level=str(form.get("trust_level", "paired")),
                trust_ttl_seconds=int(form.get("trust_days", 365)) * 86400,
            )
            message = "设备已更新并续期"
        except (HTTPException, SecurityError, TypeError, ValueError) as exc:
            message = f"操作失败：{exc}"
        return RedirectResponse(f"/dashboard/devices?message={quote(message)}", status_code=303)

    @router.post("/dashboard/devices/{device_id}/rotate")
    async def rotate_device_form(request: Request, device_id: str):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        form = await request.form()
        try:
            verify_csrf(request, str(form.get("csrf_token", "")))
            result = get_security_service().rotate_device_secret(device_id=device_id, rotated_by=str(auth))
        except (HTTPException, SecurityError) as exc:
            return RedirectResponse(
                f"/dashboard/devices?message={quote(f'操作失败：{exc}')}", status_code=303
            )
        secret = _h(result["device_secret"])
        content = (
            ui.notice("旧凭据、Grant 和 Token 已立即失效。离开本页后将不再显示新凭据。", kind="warning", title="仅显示一次")
            + '<section class="surface surface-padded"><h2>新设备凭据</h2>'
            + f'<pre id="rotated-device-secret"><code>{secret}</code></pre>'
            + '<div class="table-actions"><button class="button primary" type="button" data-copy="#rotated-device-secret">复制凭据</button>'
            + '<a class="button secondary" href="/dashboard/devices">返回设备</a></div></section>'
        )
        return render_page(
            request,
            title="设备凭据已轮换",
            description="将新凭据立即保存到设备的受保护凭据文件。",
            content=content,
            active_nav="security",
            breadcrumbs=(("安全", "/dashboard/security"), ("设备", "/dashboard/devices"), ("轮换凭据", "")),
        )

    @router.post("/dashboard/grants/{grant_id}/revoke")
    async def revoke_grant_form(request: Request, grant_id: str):
        auth = _admin_or_redirect(request, auth_config)
        if isinstance(auth, RedirectResponse):
            return auth
        form = await request.form()
        verify_csrf(request, str(form.get("csrf_token", "")))
        get_security_service().revoke_grant(grant_id=grant_id, revoked_by=str(auth), reason="web admin")
        return RedirectResponse("/dashboard/grants", status_code=303)

    @router.get("/api/devices/v1")
    async def list_devices_api(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, "items": get_security_service().list_devices()}

    @router.post("/api/devices/v1/manual")
    async def create_device_api(request: Request):
        try:
            username, payload = await _json_admin_mutation(request, auth_config)
            result = get_security_service().create_manual_device(
                device_name=str(payload.get("device_name", "")),
                device_type=str(payload.get("device_type", "manual")),
                trust_level=str(payload.get("trust_level", "paired")),
                trust_ttl_seconds=int(payload.get("trust_ttl_seconds", 31536000)),
                created_by=username,
                source_id=str(payload.get("source_id", "")),
            )
            return {"ok": True, **result}
        except (TypeError, ValueError) as exc:
            return security_error_response(request, SecurityError(422, "invalid_request", str(exc)))
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.post("/api/devices/v1/{device_id}/revoke")
    async def revoke_device_api(request: Request, device_id: str):
        try:
            username, payload = await _json_admin_mutation(request, auth_config)
            result = get_security_service().revoke_device(
                device_id=device_id, revoked_by=username, reason=str(payload.get("reason", ""))
            )
            return {"ok": True, **result}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.post("/api/devices/v1/{device_id}/update")
    async def update_device_api(request: Request, device_id: str):
        try:
            username, payload = await _json_admin_mutation(request, auth_config)
            return {"ok": True, **get_security_service().update_device(
                device_id=device_id, updated_by=username,
                device_name=payload.get("device_name"), trust_level=payload.get("trust_level"),
                trust_ttl_seconds=payload.get("trust_ttl_seconds"),
            )}
        except (TypeError, ValueError) as exc:
            return security_error_response(request, SecurityError(422, "invalid_request", str(exc)))
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.post("/api/devices/v1/{device_id}/rotate-secret")
    async def rotate_device_secret_api(request: Request, device_id: str):
        try:
            username, _ = await _json_admin_mutation(request, auth_config)
            return {"ok": True, **get_security_service().rotate_device_secret(
                device_id=device_id, rotated_by=username
            )}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.get("/api/grants/v1")
    async def list_grants_api(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, "items": get_security_service().list_grants()}

    @router.post("/api/grants/v1/manual")
    async def create_grant_api(request: Request):
        try:
            _, payload = await _json_admin_mutation(request, auth_config)
            capabilities = payload.get("capabilities")
            if not isinstance(capabilities, list):
                raise SecurityError(422, "capabilities_required", "capabilities must be an array")
            result = get_security_service().admin_request_grant(
                device_id=str(payload.get("device_id", "")),
                target_app=str(payload.get("target_app", "")),
                capabilities=[str(item) for item in capabilities],
                requested_ttl_seconds=int(payload.get("requested_ttl_seconds", 3600)),
                grant_type=str(payload.get("grant_type", "session")),
                reason=str(payload.get("reason", "web admin request")),
            )
            return {"ok": True, **result}
        except (TypeError, ValueError) as exc:
            return security_error_response(request, SecurityError(422, "invalid_request", str(exc)))
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.post("/api/grants/v1/{grant_id}/revoke")
    async def revoke_grant_api(request: Request, grant_id: str):
        try:
            username, payload = await _json_admin_mutation(request, auth_config)
            result = get_security_service().revoke_grant(
                grant_id=grant_id, revoked_by=username, reason=str(payload.get("reason", ""))
            )
            return {"ok": True, **result}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.get("/api/approvals/v1")
    async def list_approvals_api(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, "items": get_security_service().list_approvals()}

    @router.get("/api/leases/v1")
    async def list_leases_api(
        request: Request,
        active_only: bool = False,
        limit: int = 200,
    ):
        require_admin(request, auth_config.session_max_age_seconds)
        return {
            "ok": True,
            "items": get_security_service().list_leases(
                limit=max(1, min(int(limit), 500)),
                active_only=active_only,
            ),
        }

    @router.post("/api/approvals/v1/{approval_id}/approve")
    async def approve_api(request: Request, approval_id: str):
        try:
            username, payload = await _json_admin_mutation(request, auth_config)
            result = get_security_service().approve(
                approval_id=approval_id,
                approved_by=username,
                approval_method=str(payload.get("approval_method", "web-admin")),
                device_trust_level=str(payload.get("trust_level", "paired")),
                trust_ttl_seconds=int(payload.get("trust_ttl_seconds", 31536000)),
                request_code=str(payload.get("request_code", "")),
                totp_code=str(payload.get("totp_code", "")),
            )
            return {"ok": True, **result}
        except (TypeError, ValueError) as exc:
            return security_error_response(request, SecurityError(422, "invalid_request", str(exc)))
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.post("/api/approvals/v1/{approval_id}/deny")
    async def deny_api(request: Request, approval_id: str):
        try:
            username, payload = await _json_admin_mutation(request, auth_config)
            result = get_security_service().deny(
                approval_id=approval_id,
                denied_by=username,
                reason=str(payload.get("reason", "")),
            )
            return {"ok": True, **result}
        except SecurityError as exc:
            return security_error_response(request, exc)

    @router.get("/api/gateway/v1/security-summary")
    async def security_summary(request: Request):
        require_admin(request, auth_config.session_max_age_seconds)
        return {"ok": True, **get_security_service().security_summary()}

    return router
