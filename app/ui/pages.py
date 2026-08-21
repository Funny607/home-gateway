from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from app.ui import design as ui


def format_ts(value: Any) -> str:
    if not value:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
    except (TypeError, ValueError, OSError):
        return "-"


def relative_time(value: Any) -> str:
    if not value:
        return "从未"
    try:
        delta = max(0, int(time.time() - float(value)))
    except (TypeError, ValueError):
        return "未知"
    if delta < 60:
        return f"{delta} 秒前"
    if delta < 3600:
        return f"{delta // 60} 分钟前"
    if delta < 86400:
        return f"{delta // 3600} 小时前"
    return f"{delta // 86400} 天前"


def section_tabs(items: Iterable[tuple[str, str, str]], current: str) -> str:
    links = []
    for key, label, url in items:
        selected = ' aria-current="page"' if key == current else ""
        links.append(f'<a href="{ui.h(url)}"{selected}>{ui.h(label)}</a>')
    return f'<nav class="section-tabs" aria-label="页面分区">{"".join(links)}</nav>'


def _metric(label: str, value: Any, detail: str, icon_name: str) -> str:
    return (
        '<div class="metric">'
        f'<div class="metric-header"><span>{ui.h(label)}</span>{ui.icon(icon_name, size=18)}</div>'
        f'<strong class="metric-value">{ui.h(value)}</strong>'
        f'<span class="metric-detail">{ui.h(detail)}</span></div>'
    )


def _event_label(event_type: str) -> str:
    known = {
        "app_started": "应用已启动",
        "app_stopped": "应用已停止",
        "app_start_failed": "应用启动失败",
        "app_restarted": "应用已重启",
        "proxy_error": "代理请求失败",
        "proxy_upstream_server_error": "上游返回错误",
        "app_health_failed": "健康检查失败",
        "gateway_recovery_started": "恢复流程开始",
        "gateway_recovery_finished": "恢复流程完成",
        "gateway_recovery_completed": "恢复流程完成",
        "gateway_phase_changed": "Gateway 阶段已变化",
        "stage2_monitors_started": "系统监控已启动",
        "stage3_security_started": "Stage 3 安全服务已启动",
        "stage5_operations_started": "Stage 5 运维服务已启动",
        "qbt_lease_monitor_started": "Lease 监控已启动",
    }
    return known.get(event_type, event_type.replace("_", " "))


def app_actions(
    *,
    item: dict[str, Any],
    config: Any,
    role: str,
    csrf_value: str,
    back: str,
    include_detail: bool = True,
    return_state: str = "",
    return_query: str = "",
    return_tab: str = "",
) -> str:
    app_id = str(item["app_id"])
    state = str(item.get("state", "stopped"))
    actions = config.actions
    pieces: list[str] = []
    back_params = {"back": back}
    if return_state:
        back_params["state"] = return_state
    if return_query:
        back_params["q"] = return_query
    if return_tab:
        back_params["tab"] = return_tab
    back_query = ui.h(urlencode(back_params))

    if actions.show_open and role in config.dashboard.allow_open_roles and state == "running":
        pieces.append(
            f'<a class="button primary" href="{ui.h(item["mount_path"])}" target="_blank" '
            f'rel="noopener noreferrer">{ui.icon("external", size=16)}打开</a>'
        )
    elif role == "admin" and item.get("enabled", True) and state in {"stopped", "failed"}:
        endpoint = "retry" if state == "failed" else "start"
        label = "重试启动" if state == "failed" else "启动"
        pieces.append(
            f'<form class="inline-form" method="post" action="/dashboard/apps/{ui.h(app_id)}/{endpoint}?{back_query}" data-loading-form>'
            f'<input type="hidden" name="csrf_token" value="{ui.h(csrf_value)}">'
            f'<button class="button primary" type="submit">{ui.icon("play", size=16)}{label}</button></form>'
        )

    if include_detail and actions.show_detail and role in config.dashboard.allow_detail_roles:
        pieces.append(
            f'<a class="button secondary" href="/dashboard/apps/{ui.h(app_id)}">查看详情</a>'
        )

    secondary: list[str] = []
    if role == "admin" and state in {"running", "starting"}:
        if actions.show_restart:
            secondary.append(
                f'<form method="post" action="/dashboard/apps/{ui.h(app_id)}/restart?{back_query}" '
                'data-confirm-title="重启应用" '
                f'data-confirm-message="将中断 {ui.h(item["display_name"])} 当前连接并重新启动。" '
                'data-confirm-label="确认重启">'
                f'<input type="hidden" name="csrf_token" value="{ui.h(csrf_value)}">'
                f'<button type="submit">{ui.icon("restart", size=16)}重启</button></form>'
            )
        if actions.show_stop:
            secondary.append(
                f'<form method="post" action="/dashboard/apps/{ui.h(app_id)}/stop?{back_query}" '
                'data-confirm-title="停止应用" '
                f'data-confirm-message="将停止 {ui.h(item["display_name"])}。存在活动 lease 时操作会被拒绝。" '
                'data-confirm-label="确认停止" data-confirm-kind="danger">'
                f'<input type="hidden" name="csrf_token" value="{ui.h(csrf_value)}">'
                f'<button class="danger-command" type="submit">{ui.icon("stop", size=16)}停止</button></form>'
            )
    if secondary:
        pieces.append(
            '<details class="details-menu"><summary class="icon-button" aria-label="更多操作" title="更多操作">'
            f'{ui.icon("more")}</summary><div class="menu-popover">{"".join(secondary)}</div></details>'
        )
    return "".join(pieces) or '<span class="result-count">没有可用操作</span>'


def overview_content(
    *,
    snapshot: list[dict[str, Any]],
    summary: dict[str, int],
    pending_approvals: list[dict[str, Any]],
    recent_events: list[dict[str, Any]],
    role: str,
    config_for: Callable[[str], Any],
    csrf_value: str,
    phase: str,
) -> str:
    unhealthy = int(summary.get("failed", 0)) + int(summary.get("unhealthy", 0))
    metrics = (
        _metric("Gateway", "正常" if phase == "ready" else "恢复中", "控制平面运行状态", "system")
        + _metric("运行中的应用", summary.get("running", 0), f'共 {summary.get("total", 0)} 个可见应用', "apps")
        + _metric("需要关注", unhealthy, "失败或健康检查异常", "warning")
        + _metric("待审批", len(pending_approvals), "需要管理员作出决定", "approval")
    )

    attention: list[str] = []
    for item in snapshot:
        if item.get("state") == "failed" or (
            item.get("state") == "running" and item.get("last_health_check_ok") is False
        ):
            config = config_for(str(item["app_id"]))
            reason = item.get("last_failure_reason") or item.get("last_error") or "健康状态异常"
            action = (
                f'<a class="button secondary" href="/dashboard/apps/{ui.h(item["app_id"])}">处理</a>'
                if role in config.dashboard.allow_detail_roles
                else '<span class="result-count">只读状态</span>'
            )
            attention.append(
                '<li class="attention-item"><span class="attention-icon danger">'
                f'{ui.icon("error", size=18)}</span><span class="item-copy"><strong>{ui.h(item["display_name"])}</strong>'
                f'<small>{ui.h(reason)}</small></span>{action}</li>'
            )
    if role == "admin":
        for approval in pending_approvals[:5]:
            target = approval.get("target_app") or approval.get("device_id") or "未知目标"
            attention.append(
                '<li class="attention-item"><span class="attention-icon">'
                f'{ui.icon("approval", size=18)}</span><span class="item-copy"><strong>待审批：{ui.h(approval.get("approval_type"))}</strong>'
                f'<small>{ui.h(target)} · {ui.h(approval.get("risk_level", "medium"))} 风险 · {relative_time(approval.get("created_at"))}</small></span>'
                '<a class="button secondary" href="/dashboard/approvals?status=pending">审查</a></li>'
            )
    attention_html = (
        f'<ul class="attention-list">{"".join(attention)}</ul>'
        if attention
        else ui.empty_state("当前没有待处理项目", "应用状态正常，审批队列为空。", icon_name="check")
    )

    app_rows = []
    for item in snapshot:
        config = config_for(str(item["app_id"]))
        health = "健康" if item.get("state") == "running" and item.get("last_health_check_ok") is not False else item.get("state")
        name = (
            f'<a href="/dashboard/apps/{ui.h(item["app_id"])}">{ui.h(item["display_name"])}</a>'
            if role in config.dashboard.allow_detail_roles
            else f'<strong>{ui.h(item["display_name"])}</strong>'
        )
        app_rows.append(
            f'<tr><td><div class="primary-cell"><span class="object-icon">{ui.icon("apps", size=17)}</span>'
            f'<span class="primary-cell-copy">{name}'
            f'<small>{ui.h(item["app_id"])}</small></span></div></td>'
            f'<td data-label="状态">{ui.status_badge(str(health))}</td>'
            f'<td data-label="最近活动">{ui.h(relative_time(item.get("last_user_activity_time")))}</td>'
            f'<td data-label="请求" class="numeric">{ui.h(item.get("request_count", 0))}</td>'
            f'<td data-label="操作"><div class="table-actions">{app_actions(item=item, config=config, role=role, csrf_value=csrf_value, back="dashboard")}</div></td></tr>'
        )
    apps_html = (
        '<div class="data-table-wrap"><table class="data-table"><thead><tr><th>应用</th><th>状态</th><th>最近活动</th><th class="numeric">请求</th><th>操作</th></tr></thead>'
        f'<tbody>{"".join(app_rows)}</tbody></table></div>'
        if app_rows
        else ui.empty_state("尚未接入应用", "在 configs/apps 中声明第一个本地 WebUI App。", icon_name="apps")
    )

    event_items = []
    for event in recent_events[:8]:
        kind = "danger" if "fail" in str(event.get("event_type", "")) or "error" in str(event.get("event_type", "")) else ""
        event_items.append(
            '<li class="compact-item"><span class="attention-icon '
            f'{kind}">{ui.icon("activity", size=17)}</span><span class="item-copy">'
            f'<strong>{ui.h(_event_label(str(event.get("event_type", "event"))))}</strong>'
            f'<small>{ui.h(event.get("app_id") or "Gateway")} · {relative_time(event.get("ts"))}</small></span></li>'
        )
    events_html = (
        f'<ul class="compact-list">{"".join(event_items)}</ul>'
        if event_items
        else ui.empty_state("还没有活动记录", "Gateway 开始处理应用后，最近活动会显示在这里。", icon_name="activity")
    )

    return f"""
    <section class="metrics-grid" aria-label="关键指标">{metrics}</section>
    <div class="split-grid">
      <section class="section"><div class="section-header"><div><h2>需要关注</h2><p>只显示需要判断或处理的异常与审批。</p></div></div><div class="surface">{attention_html}</div></section>
      <section class="section"><div class="section-header"><div><h2>最近活动</h2><p>生命周期与恢复事件。</p></div><a class="section-link" href="/dashboard/activity">查看全部</a></div><div class="surface">{events_html}</div></section>
    </div>
    <section class="section"><div class="section-header"><div><h2>应用健康</h2><p>比较状态、活动与请求量；控制操作会根据当前状态出现。</p></div><a class="section-link" href="/dashboard/apps">管理全部应用</a></div><div class="surface">{apps_html}</div></section>
    """


def apps_content(
    *,
    snapshot: list[dict[str, Any]],
    role: str,
    config_for: Callable[[str], Any],
    csrf_value: str,
    query: str,
    state_filter: str,
) -> str:
    rows = []
    for item in snapshot:
        if state_filter and state_filter != "all" and item.get("state") != state_filter:
            continue
        config = config_for(str(item["app_id"]))
        search = " ".join(
            str(value or "") for value in (item.get("display_name"), item.get("app_id"), item.get("state"), item.get("mount_path"))
        )
        health = "健康" if item.get("state") == "running" and item.get("last_health_check_ok") is not False else item.get("state")
        name = (
            f'<a href="/dashboard/apps/{ui.h(item["app_id"])}">{ui.h(item["display_name"])}</a>'
            if role in config.dashboard.allow_detail_roles
            else f'<strong>{ui.h(item["display_name"])}</strong>'
        )
        rows.append(
            f'<tr data-search="{ui.h(search)}"><td><div class="primary-cell"><span class="object-icon">{ui.icon("apps", size=17)}</span>'
            f'<span class="primary-cell-copy">{name}<small>{ui.h(item["app_id"])}</small></span></div></td>'
            f'<td data-label="状态">{ui.status_badge(str(health))}</td>'
            f'<td data-label="入口"><code>{ui.h(item.get("mount_path"))}</code></td>'
            f'<td data-label="最近活动">{ui.h(relative_time(item.get("last_user_activity_time")))}</td>'
            f'<td data-label="失败" class="numeric">{ui.h(item.get("consecutive_failures", 0))}</td>'
            f'<td data-label="操作"><div class="table-actions">{app_actions(item=item, config=config, role=role, csrf_value=csrf_value, back="apps", return_state=state_filter, return_query=query)}</div></td></tr>'
        )
    empty = ui.empty_state("没有匹配的应用", "调整搜索词或状态筛选后再试。", icon_name="search")
    options = []
    for value, label in (("all", "全部状态"), ("running", "运行中"), ("stopped", "已停止"), ("failed", "失败")):
        selected = " selected" if (state_filter or "all") == value else ""
        options.append(f'<option value="{value}"{selected}>{label}</option>')
    return f"""
    <section class="surface">
      <div class="command-bar">
        <label class="search-field">{ui.icon("search", size=17)}<span class="sr-only">搜索应用</span>
          <input type="search" value="{ui.h(query)}" placeholder="搜索名称、ID、状态或入口…" data-table-filter="#apps-table-body" data-empty-target="#apps-empty" data-count-target="#apps-count">
        </label>
        <form method="get" action="/dashboard/apps">
          <label class="sr-only" for="state-filter">状态筛选</label>
          <select class="select" id="state-filter" name="state" data-auto-submit>{"".join(options)}</select>
        </form>
        <span class="result-count" id="apps-count">{len(rows)} 项</span>
      </div>
      <div class="data-table-wrap"><table class="data-table"><thead><tr><th>应用</th><th>状态</th><th>Gateway 入口</th><th>最近活动</th><th class="numeric">连续失败</th><th>操作</th></tr></thead>
        <tbody id="apps-table-body">{"".join(rows)}</tbody></table></div>
      <div id="apps-empty" hidden>{empty}</div>
    </section>
    """


def app_detail_content(
    *,
    item: dict[str, Any],
    config: Any,
    runtime_data: dict[str, Any],
    recent_events: list[dict[str, Any]],
    stdout_tail: str,
    stderr_tail: str,
    tab: str,
    role: str,
    csrf_value: str,
) -> tuple[str, str, str]:
    app_id = str(item["app_id"])
    tabs = section_tabs(
        (
            ("overview", "概况", f"/dashboard/apps/{app_id}?tab=overview"),
            ("activity", "活动", f"/dashboard/apps/{app_id}?tab=activity"),
            ("logs", "日志", f"/dashboard/apps/{app_id}?tab=logs"),
            ("access", "访问与能力", f"/dashboard/apps/{app_id}?tab=access"),
        ),
        tab,
    )
    actions = app_actions(
        item=item,
        config=config,
        role=role,
        csrf_value=csrf_value,
        back="detail",
        include_detail=False,
        return_tab=tab,
    )
    if tab == "activity":
        rows = []
        for event in recent_events:
            rows.append(
                f'<tr><td>{ui.h(format_ts(event.get("ts")))}</td><td data-label="事件">{ui.h(_event_label(str(event.get("event_type", "event"))))}</td>'
                f'<td data-label="原因">{ui.h(event.get("reason") or event.get("phase") or "-")}</td>'
                f'<td data-label="数据"><details><summary>查看</summary><pre class="log-view">{ui.h(json.dumps(event, ensure_ascii=False, indent=2))}</pre></details></td></tr>'
            )
        content = (
            '<section class="surface"><div class="data-table-wrap"><table class="data-table"><thead><tr><th>时间</th><th>事件</th><th>原因</th><th>数据</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div></section>'
            if rows
            else f'<section class="surface">{ui.empty_state("暂无活动", "该应用尚未产生生命周期事件。", icon_name="activity")}</section>'
        )
    elif tab == "logs":
        content = f"""
        {ui.notice("日志只显示末尾 50 行，不会自动刷新，避免打断当前阅读位置。", kind="info")}
        <div class="detail-grid">
          <section class="surface surface-padded"><div class="section-header"><div><h2>标准输出</h2><p>stdout · 最近 50 行</p></div></div><pre class="log-view">{ui.h(stdout_tail)}</pre></section>
          <section class="surface surface-padded"><div class="section-header"><div><h2>错误输出</h2><p>stderr · 最近 50 行</p></div></div><pre class="log-view">{ui.h(stderr_tail)}</pre></section>
        </div>"""
    elif tab == "access":
        capabilities = []
        for capability in config.capabilities:
            route_count = len(capability.routes)
            managed = "Gateway 托管" if capability.gateway_managed else f"{route_count} 条路由"
            capabilities.append(
                '<li class="compact-item"><span class="attention-icon">'
                f'{ui.icon("grant", size=17)}</span><span class="item-copy"><strong>{ui.h(capability.title)}</strong>'
                f'<small><code>{ui.h(capability.id)}</code> · {ui.h(managed)}</small></span>'
                f'{ui.status_badge(capability.risk, capability.risk.replace("_", " "))}</li>'
            )
        cap_html = (
            f'<ul class="compact-list">{"".join(capabilities)}</ul>'
            if capabilities
            else ui.empty_state("未对外声明 capability", "此外部 API 默认不暴露任何应用路径。", icon_name="security")
        )
        content = f"""
        <div class="detail-grid">
          <section><div class="section-header"><div><h2>外部能力</h2><p>只有显式声明的 capability 才能通过外部 API 调用。</p></div></div><div class="surface">{cap_html}</div></section>
          <section><div class="section-header"><div><h2>WebUI 访问策略</h2><p>页面展示、打开与代理是相互独立的权限。</p></div></div><div class="surface surface-padded"><dl class="detail-list">
            <dt>可见角色</dt><dd>{ui.h(", ".join(config.dashboard.visible_roles))}</dd>
            <dt>可打开角色</dt><dd>{ui.h(", ".join(config.dashboard.allow_open_roles))}</dd>
            <dt>可代理角色</dt><dd>{ui.h(", ".join(config.dashboard.allow_proxy_roles))}</dd>
            <dt>API 暴露</dt><dd>{ui.status_badge("active" if config.api.enabled else "stopped", "已启用" if config.api.enabled else "未启用")}</dd>
            <dt>自动启动 API</dt><dd>{"是" if config.api.auto_start else "否"}</dd>
          </dl></div></section>
        </div>"""
    else:
        health = "健康" if item.get("state") == "running" and item.get("last_health_check_ok") is not False else item.get("state")
        error_notice = ""
        if item.get("last_error") or item.get("last_failure_reason"):
            error_notice = ui.notice(
                str(item.get("last_failure_reason") or item.get("last_error")),
                kind="danger",
                title="最近一次故障",
            )
        content = f"""
        {error_notice}
        <div class="detail-grid">
          <section><div class="section-header"><div><h2>运行状态</h2><p>用于判断应用是否可被访问和控制。</p></div></div><div class="surface surface-padded"><dl class="detail-list">
            <dt>状态</dt><dd>{ui.status_badge(str(health))}</dd>
            <dt>进程 PID</dt><dd><code>{ui.h(item.get("pid") or "-")}</code></dd>
            <dt>内部地址</dt><dd><code>{ui.h(item.get("internal_url") or "-")}</code></dd>
            <dt>启动时间</dt><dd>{ui.h(format_ts(item.get("started_at")))}</dd>
            <dt>最近健康检查</dt><dd>{ui.h(format_ts(item.get("last_health_check_time")))}</dd>
            <dt>活动流</dt><dd>{ui.h(item.get("active_stream_count", 0))}</dd>
          </dl></div></section>
          <section><div class="section-header"><div><h2>Gateway 行为</h2><p>生命周期与流量保护设置。</p></div></div><div class="surface surface-padded"><dl class="detail-list">
            <dt>统一入口</dt><dd><code>{ui.h(item.get("mount_path"))}</code></dd>
            <dt>注册状态</dt><dd>{ui.status_badge("active" if item.get("enabled", True) else "stopped", "已启用" if item.get("enabled", True) else "已停用")}</dd>
            <dt>启动策略</dt><dd>{ui.h(item.get("start_policy", "on_demand"))}</dd>
            <dt>依赖</dt><dd>{ui.h(", ".join(item.get("dependencies", [])) or "无")}</dd>
            <dt>自动停止</dt><dd>{"允许" if config.allow_auto_stop else "禁止"}</dd>
            <dt>空闲超时</dt><dd>{ui.h(config.idle_timeout_seconds or "Gateway 默认")}</dd>
            <dt>启动超时</dt><dd>{ui.h(config.startup_timeout_seconds or "Gateway 默认")}</dd>
            <dt>API 请求数</dt><dd>{ui.h(item.get("request_count", 0))}</dd>
            <dt>连续失败</dt><dd>{ui.h(item.get("consecutive_failures", 0))}</dd>
            <dt>剩余重启预算</dt><dd>{ui.h(item.get("restart_budget_remaining", 0))}</dd>
            <dt>代理请求上限</dt><dd>{ui.h(config.proxy.max_request_body_bytes)} 字节</dd>
          </dl></div></section>
        </div>
        <section class="section"><div class="section-header"><div><h2>诊断摘要</h2><p>保留原始运行数据用于排障，不作为主要操作界面。</p></div></div>
          <details class="surface surface-padded"><summary>查看运行时数据</summary><pre class="log-view">{ui.h(json.dumps(runtime_data, ensure_ascii=False, indent=2))}</pre></details>
        </section>"""
    return content, tabs, actions


def activity_content(
    *,
    events: list[dict[str, Any]],
    audits: list[dict[str, Any]],
    role: str,
    tab: str,
    app_id: str,
    event_type: str,
    limit: int,
    app_options: list[str],
    event_types: list[str],
    audit_success: str = "",
) -> tuple[str, str]:
    tabs = section_tabs(
        (
            ("events", "生命周期事件", "/dashboard/activity?tab=events"),
            ("audit", "API 审计", "/dashboard/activity?tab=audit"),
        ) if role == "admin" else (("events", "生命周期事件", "/dashboard/activity?tab=events"),),
        tab,
    )
    if tab == "audit" and role == "admin":
        app_opts = ['<option value="">全部目标应用</option>']
        for value in app_options:
            selected = " selected" if value == app_id else ""
            app_opts.append(f'<option value="{ui.h(value)}"{selected}>{ui.h(value)}</option>')
        result_opts = []
        for value, label in (("", "全部结果"), ("true", "成功"), ("false", "失败")):
            selected = " selected" if value == audit_success else ""
            result_opts.append(f'<option value="{value}"{selected}>{label}</option>')
        export_query = {"format": "csv"}
        if app_id:
            export_query["target_app"] = app_id
        if audit_success:
            export_query["success"] = audit_success
        rows = []
        for row in audits:
            success = bool(row.get("success"))
            actor = row.get("actor_name") or row.get("device_id") or row.get("actor_type") or "未知"
            target = row.get("target_app") or "Gateway"
            operation = row.get("capability") or f'{row.get("method", "-")} {row.get("path", "-")}'
            rows.append(
                f'<tr><td>{ui.h(format_ts(row.get("created_at")))}</td><td data-label="调用方"><strong>{ui.h(actor)}</strong><br><small>{ui.h(row.get("actor_type"))}</small></td>'
                f'<td data-label="目标">{ui.h(target)}</td><td data-label="操作"><code>{ui.h(operation)}</code></td>'
                f'<td data-label="结果">{ui.status_badge("active" if success else "failed", "成功" if success else "失败")}</td>'
                f'<td data-label="耗时" class="numeric">{ui.h(row.get("duration_ms") if row.get("duration_ms") is not None else "-")} ms</td>'
                f'<td data-label="请求 ID"><code>{ui.h(row.get("request_id"))}</code></td></tr>'
            )
        table = (
            '<div class="data-table-wrap"><table class="data-table"><thead><tr><th>时间</th><th>调用方</th><th>目标</th><th>Capability / 路径</th><th>结果</th><th class="numeric">耗时</th><th>请求 ID</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>'
            if rows
            else ui.empty_state("暂无 API 审计", "外部程序调用受控 API 后，记录会显示在这里。", icon_name="activity")
        )
        filters = f"""
        <form class="command-bar" method="get" action="/dashboard/activity">
          <input type="hidden" name="tab" value="audit">
          <label class="field"><span class="sr-only">目标应用</span><select class="select" name="app_id">{"".join(app_opts)}</select></label>
          <label class="field"><span class="sr-only">调用结果</span><select class="select" name="success">{"".join(result_opts)}</select></label>
          <label class="field"><span class="sr-only">数量</span><input class="select" type="number" name="limit" value="{ui.h(limit)}" min="1" max="500"></label>
          <button class="button secondary" type="submit">{ui.icon("filter", size=16)}应用筛选</button>
          <a class="button secondary" href="/api/audit/v1/export?{ui.h(urlencode(export_query))}">导出 CSV</a>
          <a class="button subtle" href="/dashboard/activity?tab=audit">重置</a>
        </form>"""
        content = f'{ui.notice("审计记录包含调用方、授权能力、结果和请求 ID，不会显示 token 或设备 secret。", kind="info")}<section class="surface">{filters}{table}</section>'
    else:
        app_opts = ['<option value="">全部应用</option>']
        for value in app_options:
            selected = " selected" if value == app_id else ""
            app_opts.append(f'<option value="{ui.h(value)}"{selected}>{ui.h(value)}</option>')
        type_opts = ['<option value="">全部事件类型</option>']
        for value in event_types:
            selected = " selected" if value == event_type else ""
            type_opts.append(f'<option value="{ui.h(value)}"{selected}>{ui.h(_event_label(value))}</option>')
        rows = []
        for event in events:
            event_json = json.dumps(event, ensure_ascii=False, indent=2)
            rows.append(
                f'<tr><td>{ui.h(format_ts(event.get("ts")))}</td><td data-label="事件"><strong>{ui.h(_event_label(str(event.get("event_type", "event"))))}</strong><br><small>{ui.h(event.get("event_type"))}</small></td>'
                f'<td data-label="应用">{ui.h(event.get("app_id") or "Gateway")}</td>'
                f'<td data-label="原因">{ui.h(event.get("reason") or event.get("phase") or "-")}</td>'
                f'<td data-label="数据"><details><summary>查看</summary><pre class="log-view">{ui.h(event_json)}</pre></details></td></tr>'
            )
        table = (
            '<div class="data-table-wrap"><table class="data-table"><thead><tr><th>时间</th><th>事件</th><th>应用</th><th>原因 / 阶段</th><th>数据</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>'
            if rows
            else ui.empty_state("没有匹配事件", "调整筛选条件或等待 Gateway 产生新事件。", icon_name="activity")
        )
        content = f"""
        <section class="surface">
          <form class="command-bar" method="get" action="/dashboard/activity">
            <input type="hidden" name="tab" value="events">
            <label class="field"><span class="sr-only">应用</span><select class="select" name="app_id">{"".join(app_opts)}</select></label>
            <label class="field"><span class="sr-only">事件类型</span><select class="select" name="event_type">{"".join(type_opts)}</select></label>
            <label class="field"><span class="sr-only">数量</span><input class="select" type="number" name="limit" value="{ui.h(limit)}" min="1" max="500"></label>
            <button class="button secondary" type="submit">{ui.icon("filter", size=16)}应用筛选</button>
            <a class="button subtle" href="/dashboard/activity">重置</a>
          </form>{table}
        </section>"""
    return content, tabs


def system_content(
    *,
    phase: str,
    config_dir: Path,
    gateway_config: Any,
    security_summary: dict[str, Any],
    version: str,
) -> str:
    database = security_summary.get("database", {})
    db_ok = bool(database.get("ok"))
    checks = [
        ("Gateway 运行阶段", phase == "ready", phase, "system"),
        ("监听地址", str(gateway_config.listen_host) in {"127.0.0.1", "localhost"}, f"{gateway_config.listen_host}:{gateway_config.listen_port}", "security"),
        ("安全数据库", db_ok, f'完整性 {database.get("integrity", "未知")} · schema v{database.get("schema_version", "-")}', "database"),
        ("配置目录", config_dir.exists(), str(config_dir), "terminal"),
    ]
    rows = []
    for label, ok, detail, glyph in checks:
        rows.append(
            '<li class="compact-item"><span class="attention-icon '
            f'{"" if ok else "danger"}">{ui.icon(glyph, size=17)}</span><span class="item-copy"><strong>{ui.h(label)}</strong><small>{ui.h(detail)}</small></span>'
            f'{ui.status_badge("healthy" if ok else "failed", "通过" if ok else "异常")}</li>'
        )
    return f"""
    <div class="detail-grid">
      <section><div class="section-header"><div><h2>运行就绪检查</h2><p>影响 Gateway 是否可以安全接收请求的关键条件。</p></div></div><div class="surface"><ul class="compact-list">{"".join(rows)}</ul></div></section>
      <section><div class="section-header"><div><h2>安装信息</h2><p>用于部署核对与问题定位。</p></div></div><div class="surface surface-padded"><dl class="detail-list">
        <dt>版本</dt><dd><code>{ui.h(version)}</code></dd>
        <dt>生命周期恢复</dt><dd>{"已启用" if gateway_config.recovery_block_requests else "未阻止恢复期请求"}</dd>
        <dt>失败自动重启</dt><dd>{"已启用" if gateway_config.auto_restart_failed_apps else "已关闭"}</dd>
        <dt>健康轮询</dt><dd>{ui.h(gateway_config.health_poll_interval_seconds)} 秒</dd>
        <dt>日志目录</dt><dd><code>{ui.h(gateway_config.log_path)}</code></dd>
        <dt>运行目录</dt><dd><code>{ui.h(gateway_config.runtime_path)}</code></dd>
      </dl></div></section>
    </div>
    <section class="section"><div class="section-header"><div><h2>安全边界</h2><p>外部流量必须先经过 Tunnel，再由 Gateway 执行认证、授权与审计。</p></div></div>
      {ui.notice("Gateway 只监听 loopback。不要将本地 App 端口或 8081 直接暴露到公网。", kind="warning", title="部署约束")}
      <div class="surface surface-padded"><dl class="detail-list">
        <dt>受信设备</dt><dd>{ui.h(security_summary.get("devices", 0))}</dd>
        <dt>活动 token</dt><dd>{ui.h(security_summary.get("active_tokens", 0))}</dd>
        <dt>待审批</dt><dd>{ui.h(security_summary.get("pending_approvals", 0))}</dd>
        <dt>审计记录</dt><dd>{ui.h(security_summary.get("audit_events", 0))}</dd>
      </dl></div>
    </section>"""


def registry_content(
    *,
    rows: list[dict[str, Any]],
    csrf_value: str,
    editor_manifest: str,
    expected_revision: str = "",
    editor_app_id: str = "",
) -> str:
    table_rows: list[str] = []
    for row in rows:
        app_id = str(row["app_id"])
        enabled = bool(row.get("enabled"))
        endpoint = "disable" if enabled else "enable"
        label = "停用" if enabled else "启用"
        confirm = (
            ' data-confirm-title="停用应用" '
            f'data-confirm-message="将停止并停用 {ui.h(row["display_name"])}。存在活动 Lease 时操作会被拒绝。" '
            'data-confirm-label="确认停用" data-confirm-kind="danger"'
            if enabled else ""
        )
        action = (
            f'<a class="button secondary" href="/dashboard/apps?tab=registry&edit={ui.h(app_id)}">编辑清单</a>'
            f'<form class="inline-form" method="post" action="/dashboard/apps/registry/{ui.h(app_id)}/{endpoint}"{confirm}>'
            f'<input type="hidden" name="csrf_token" value="{ui.h(csrf_value)}">'
            f'<button class="button {"danger" if enabled else "primary"}" type="submit">{label}</button></form>'
        )
        table_rows.append(
            f'<tr><td><div class="primary-cell"><span class="object-icon">{ui.icon("apps", size=17)}</span>'
            f'<span class="primary-cell-copy"><strong>{ui.h(row["display_name"])}</strong><small>{ui.h(app_id)}</small></span></div></td>'
            f'<td data-label="注册状态">{ui.status_badge("active" if enabled else "stopped", "已启用" if enabled else "已停用")}</td>'
            f'<td data-label="运行状态">{ui.status_badge(str(row.get("state", "stopped")))}</td>'
            f'<td data-label="入口"><code>{ui.h(row.get("mount_path"))}</code></td>'
            f'<td data-label="能力" class="numeric">{len(row.get("capabilities", []))}</td>'
            f'<td data-label="更新人">{ui.h(row.get("updated_by") or "system")}</td>'
            f'<td data-label="操作"><div class="table-actions">{action}</div></td></tr>'
        )
    table = (
        '<div class="data-table-wrap"><table class="data-table"><thead><tr><th>应用</th><th>注册状态</th><th>运行状态</th><th>入口</th><th class="numeric">能力</th><th>更新人</th><th>操作</th></tr></thead>'
        f'<tbody>{"".join(table_rows)}</tbody></table></div>'
        if table_rows else ui.empty_state("尚未注册应用", "使用下方清单编辑器添加第一个应用。", icon_name="apps")
    )
    editor_title = f"编辑 {editor_app_id}" if editor_app_id else "添加应用"
    return f"""
    {ui.notice("保存前会执行结构、路径冲突、能力路由、依赖环和 Lease 适配器检查。更新现有应用前必须先停止应用并释放 Lease。", kind="info", title="清单校验")}
    <section class="surface">{table}</section>
    <section class="section"><div class="section-header"><div><h2>{ui.h(editor_title)}</h2><p>清单使用 YAML；秘密值只能通过 env: 或 macOS Keychain 引用。</p></div></div>
      <form class="surface surface-padded" method="post" action="/dashboard/apps/registry/save" data-loading-form>
        <input type="hidden" name="csrf_token" value="{ui.h(csrf_value)}">
        <input type="hidden" name="expected_revision" value="{ui.h(expected_revision)}">
        <label class="field" for="manifest-editor"><span>应用清单</span>
          <textarea class="manifest-editor" id="manifest-editor" name="manifest" spellcheck="false" required>{ui.h(editor_manifest)}</textarea>
          <small>保存操作具有版本冲突保护；不会通过页面展示 secret 的解析值。</small>
        </label>
        <div class="dialog-actions"><a class="button secondary" href="/dashboard/apps?tab=registry">重置</a><button class="button primary" type="submit">校验并保存</button></div>
      </form>
    </section>"""


def notifications_content(
    *, page_data: dict[str, Any], csrf_value: str, page: int
) -> str:
    items = page_data.get("items", [])
    rows: list[str] = []
    for item in items:
        unread = item.get("read_at") is None
        delivery = str(item.get("status", "in_app"))
        delivery_label = {
            "queued": "等待发送", "sending": "发送中", "sent": "邮件已发送",
            "failed": "发送失败", "in_app": "仅站内",
        }.get(delivery, delivery)
        action = ""
        if unread:
            action = (
                f'<form class="inline-form" method="post" action="/dashboard/notifications/{ui.h(item["notification_id"])}/read">'
                f'<input type="hidden" name="csrf_token" value="{ui.h(csrf_value)}">'
                '<button class="button secondary" type="submit">标为已读</button></form>'
            )
        rows.append(
            f'<li class="attention-item"><span class="attention-icon {"danger" if item.get("severity") == "danger" else ""}">{ui.icon("bell", size=17)}</span>'
            f'<span class="item-copy"><strong>{"未读 · " if unread else ""}{ui.h(item.get("title"))}</strong>'
            f'<small class="notification-message">{ui.h(item.get("message"))}</small>'
            f'<small>{ui.h(item.get("category"))} · {ui.h(format_ts(item.get("last_occurrence_at")))} · {ui.h(delivery_label)}'
            f'{" · 重复 " + ui.h(item.get("repeat_count")) + " 次" if int(item.get("repeat_count", 1)) > 1 else ""}</small></span>{action}</li>'
        )
    body = (
        f'<ul class="attention-list">{"".join(rows)}</ul>'
        if rows else ui.empty_state("没有通知", "Gateway 的异常、恢复、审批和测试通知会显示在这里。", icon_name="bell")
    )
    current = int(page_data.get("page", page))
    total_pages = int(page_data.get("total_pages", 1))
    previous = (
        f'<a class="button secondary" href="/dashboard/notifications?page={current - 1}">上一页</a>'
        if current > 1 else '<span class="button secondary" aria-disabled="true">上一页</span>'
    )
    following = (
        f'<a class="button secondary" href="/dashboard/notifications?page={current + 1}">下一页</a>'
        if current < total_pages else '<span class="button secondary" aria-disabled="true">下一页</span>'
    )
    return f"""
    <section class="surface">{body}<nav class="pagination" aria-label="通知分页"><span class="result-count">第 {current} / {total_pages} 页 · 共 {ui.h(page_data.get("total", 0))} 条</span>{previous}{following}</nav></section>
    <div class="section"><div class="section-header"><div><h2>通知行为</h2><p>关键状态会保留在此；邮件发送失败不会丢失站内证据。</p></div></div>
      {ui.notice("相同问题会在冷却时间内合并；邮件正文不会包含 token、Cookie、密码或本地邮件器凭据。", kind="info")}
    </div>"""


def settings_content(
    *,
    tab: str,
    phase: str,
    config_dir: Path,
    gateway_config: Any,
    security_summary: dict[str, Any],
    notification_health: dict[str, Any],
    tunnel_state: dict[str, Any],
    version: str,
    csrf_value: str,
) -> tuple[str, str, str]:
    tabs = section_tabs(
        (
            ("general", "常规", "/dashboard/settings?tab=general"),
            ("notifications", "通知", "/dashboard/settings?tab=notifications"),
            ("integrations", "集成", "/dashboard/settings?tab=integrations"),
            ("security", "安全", "/dashboard/settings?tab=security"),
            ("operations", "运维与恢复", "/dashboard/operations"),
            ("about", "关于", "/dashboard/settings?tab=about"),
        ),
        tab,
    )
    actions = ""
    if tab == "notifications":
        actions = (
            '<form class="inline-form" method="post" action="/dashboard/notifications/test" data-loading-form>'
            f'<input type="hidden" name="csrf_token" value="{ui.h(csrf_value)}">'
            '<button class="button primary" type="submit">发送测试通知</button></form>'
        )
        available = bool(notification_health.get("python_available") and notification_health.get("mailer_available"))
        content = f"""
        {ui.notice("测试会进入同一持久化队列，并发送到已配置收件人。", kind="info")}
        <div class="detail-grid"><section class="surface surface-padded"><h2>Local Mailer</h2><dl class="detail-list">
          <dt>通道</dt><dd>{ui.status_badge("healthy" if available else "failed", "可用" if available else "路径待确认")}</dd>
          <dt>收件人</dt><dd><code>{ui.h(notification_health.get("recipient"))}</code></dd>
          <dt>Python</dt><dd>{"已找到" if notification_health.get("python_available") else "未找到"}</dd>
          <dt>发送脚本</dt><dd>{"已找到" if notification_health.get("mailer_available") else "未找到"}</dd>
          <dt>未读通知</dt><dd>{ui.h(notification_health.get("unread", 0))}</dd>
        </dl></section><section class="surface surface-padded"><h2>发送策略</h2><dl class="detail-list">
          <dt>主题前缀</dt><dd><code>{ui.h(gateway_config.notifications.subject_prefix)}</code></dd>
          <dt>公网故障邮件</dt><dd>连续未恢复 {ui.h(gateway_config.tunnel.alert_after_seconds // 60)} 分钟后，每次故障仅一次</dd>
          <dt>去重冷却</dt><dd>{ui.h(gateway_config.notifications.cooldown_seconds)} 秒</dd>
          <dt>最多尝试</dt><dd>{ui.h(gateway_config.notifications.max_attempts)} 次</dd>
          <dt>保留时间</dt><dd>{ui.h(gateway_config.notifications.retention_days)} 天</dd>
        </dl></section></div>"""
    elif tab == "integrations":
        status = str(tunnel_state.get("status", "unknown"))
        content = f"""
        {ui.notice("此处只读取公网健康状态，不修改 Cloudflare Tunnel 配置。", kind="info", title="只读集成")}
        <section class="surface surface-padded"><h2>Cloudflare Tunnel</h2><dl class="detail-list">
          <dt>状态</dt><dd>{ui.status_badge(status)}</dd>
          <dt>健康地址</dt><dd><code>{ui.h(tunnel_state.get("public_url") or gateway_config.tunnel.public_url)}</code></dd>
          <dt>最近检查</dt><dd>{ui.h(format_ts(tunnel_state.get("last_checked_at")))}</dd>
          <dt>最近正常</dt><dd>{ui.h(format_ts(tunnel_state.get("last_ok_at")))}</dd>
          <dt>本次故障开始</dt><dd>{ui.h(format_ts(tunnel_state.get("failure_started_at")))}</dd>
          <dt>本次邮件告警</dt><dd>{ui.h(format_ts(tunnel_state.get("alert_sent_at")))}</dd>
          <dt>连续失败</dt><dd>{ui.h(tunnel_state.get("consecutive_failures", 0))}</dd>
          <dt>最近错误</dt><dd>{ui.h(tunnel_state.get("last_error") or "-")}</dd>
        </dl></section>"""
    elif tab == "security":
        database = security_summary.get("database", {})
        content = f"""
        {ui.notice("Gateway 只监听 loopback；不要直接暴露 Gateway 或子应用端口。", kind="warning", title="部署边界")}
        <section class="surface surface-padded"><dl class="detail-list">
          <dt>监听地址</dt><dd><code>{ui.h(gateway_config.listen_host)}:{ui.h(gateway_config.listen_port)}</code></dd>
          <dt>数据库完整性</dt><dd>{ui.status_badge("healthy" if database.get("ok") else "failed", str(database.get("integrity", "未知")))}</dd>
          <dt>Schema</dt><dd>v{ui.h(database.get("schema_version", "-"))}</dd>
          <dt>受信设备</dt><dd>{ui.h(security_summary.get("devices", 0))}</dd>
          <dt>活动 Token</dt><dd>{ui.h(security_summary.get("active_tokens", 0))}</dd>
          <dt>审计保留</dt><dd>{ui.h(gateway_config.audit.retention_days)} 天</dd>
        </dl></section>"""
    elif tab == "about":
        content = f"""<section class="surface surface-padded"><dl class="detail-list">
          <dt>产品</dt><dd>WebUI Home Gateway</dd><dt>版本</dt><dd><code>{ui.h(version)}</code></dd>
          <dt>阶段</dt><dd>Stage 5 · Operations v1</dd><dt>配置目录</dt><dd><code>{ui.h(config_dir)}</code></dd>
          <dt>运行目录</dt><dd><code>{ui.h(gateway_config.runtime_path)}</code></dd>
          <dt>日志目录</dt><dd><code>{ui.h(gateway_config.log_path)}</code></dd>
        </dl></section>"""
    else:
        content = f"""<div class="detail-grid"><section class="surface surface-padded"><h2>运行</h2><dl class="detail-list">
          <dt>Gateway</dt><dd>{ui.status_badge(phase)}</dd><dt>健康轮询</dt><dd>{ui.h(gateway_config.health_poll_interval_seconds)} 秒</dd>
          <dt>失败自动重启</dt><dd>{"已启用" if gateway_config.auto_restart_failed_apps else "已关闭"}</dd>
          <dt>滚动窗口</dt><dd>{ui.h(gateway_config.restart_window_seconds)} 秒</dd><dt>稳定重置</dt><dd>{ui.h(gateway_config.restart_stable_seconds)} 秒</dd>
        </dl></section><section class="surface surface-padded"><h2>数据保留</h2><dl class="detail-list">
          <dt>审计</dt><dd>{ui.h(gateway_config.audit.retention_days)} 天</dd><dt>通知</dt><dd>{ui.h(gateway_config.notifications.retention_days)} 天</dd>
          <dt>审计导出上限</dt><dd>{ui.h(gateway_config.audit.export_limit)} 条</dd><dt>日志轮换</dt><dd>{ui.h(gateway_config.log_backup_count)} 份</dd>
        </dl></section></div>"""
    return content, tabs, actions
