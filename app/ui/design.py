from __future__ import annotations

import html
from collections.abc import Iterable
from dataclasses import dataclass

from fastapi.responses import HTMLResponse


def h(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


_ICON_PATHS = {
    "overview": '<path d="M4 13h6V4H4v9Zm0 7h6v-4H4v4Zm10 0h6v-9h-6v9Zm0-16v4h6V4h-6Z"/>',
    "apps": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    "security": '<path d="M12 3 4.5 6v5.2c0 4.6 3.2 8.1 7.5 9.8 4.3-1.7 7.5-5.2 7.5-9.8V6L12 3Z"/><path d="m8.8 12 2.1 2.1 4.4-4.5"/>',
    "activity": '<path d="M3 12h4l2.1-5 4 10 2.2-5H21"/>',
    "system": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/>',
    "theme": '<path d="M20 15.2A8.5 8.5 0 0 1 8.8 4 8.5 8.5 0 1 0 20 15.2Z"/>',
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "collapse": '<path d="m14 6-6 6 6 6"/>',
    "expand": '<path d="m10 6 6 6-6 6"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    "bell": '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 7h18s-3 0-3-7M10 19h4"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4.5 21a7.5 7.5 0 0 1 15 0"/>',
    "logout": '<path d="M10 5H5v14h5M14 8l4 4-4 4M18 12H9"/>',
    "refresh": '<path d="M20 6v5h-5M4 18v-5h5"/><path d="M18.4 9A7 7 0 0 0 6.3 6.3L4 9M5.6 15A7 7 0 0 0 17.7 17.7L20 15"/>',
    "external": '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/>',
    "chevron": '<path d="m9 18 6-6-6-6"/>',
    "play": '<path d="m8 5 11 7-11 7V5Z"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="1"/>',
    "restart": '<path d="M20 7v5h-5"/><path d="M19 12a7 7 0 1 0-2 5"/>',
    "more": '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
    "check": '<path d="m5 12 4 4L19 6"/>',
    "warning": '<path d="M12 3 2.8 20h18.4L12 3Z"/><path d="M12 9v4M12 17h.01"/>',
    "error": '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6m0-6-6 6"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',
    "device": '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 17h6"/>',
    "grant": '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8m-3 3 2 2m-5 1 2 2"/>',
    "approval": '<path d="M7 3h10v4H7zM5 5H4a1 1 0 0 0-1 1v14h18V6a1 1 0 0 0-1-1h-1"/><path d="m8 14 2.5 2.5L16 11"/>',
    "database": '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
    "terminal": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "filter": '<path d="M4 5h16l-6 7v6l-4 2v-8L4 5Z"/>',
    "copy": '<rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
    "arrow-left": '<path d="m15 18-6-6 6-6"/>',
}


def icon(name: str, *, size: int = 20, label: str = "") -> str:
    path = _ICON_PATHS.get(name, _ICON_PATHS["apps"])
    aria = f' role="img" aria-label="{h(label)}"' if label else ' aria-hidden="true"'
    return (
        f'<svg class="icon" width="{size}" height="{size}" viewBox="0 0 24 24" '
        f'fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        f'stroke-linejoin="round"{aria}>{path}</svg>'
    )


@dataclass(frozen=True)
class CommandItem:
    label: str
    url: str
    group: str
    description: str = ""
    icon_name: str = "chevron"


def status_badge(status: str, label: str | None = None) -> str:
    normalized = str(status or "unknown").strip().lower().replace("_", "-")
    semantic = {
        "running": "success",
        "ready": "success",
        "active": "success",
        "approved": "success",
        "healthy": "success",
        "granted": "success",
        "pending": "warning",
        "queued": "warning",
        "degraded": "warning",
        "pending-approval": "warning",
        "starting": "info",
        "stopping": "info",
        "recovering": "info",
        "paired": "info",
        "trusted": "success",
        "privileged": "success",
        "stopped": "neutral",
        "released": "neutral",
        "disabled": "neutral",
        "in-app": "neutral",
        "sent": "success",
        "unhealthy": "danger",
        "expired": "neutral",
        "revoked": "danger",
        "failed": "danger",
        "denied": "danger",
        "re-registration-required": "danger",
    }.get(normalized, "neutral")
    glyph = {"success": "check", "warning": "warning", "danger": "error", "info": "info"}.get(
        semantic, "info"
    )
    labels = {
        "running": "运行中", "ready": "就绪", "active": "活跃", "approved": "已批准",
        "healthy": "健康", "granted": "已授权", "pending": "待处理", "queued": "排队中",
        "degraded": "性能下降", "pending-approval": "待批准", "starting": "启动中",
        "stopping": "停止中", "recovering": "恢复中", "paired": "已配对",
        "trusted": "受信任", "privileged": "特权", "stopped": "已停止",
        "released": "已释放", "disabled": "已禁用", "sent": "已发送",
        "unhealthy": "异常", "expired": "已过期", "revoked": "已撤销",
        "failed": "失败", "denied": "已拒绝", "re-registration-required": "需重新注册",
    }
    text = label or labels.get(normalized, str(status or "unknown").replace("_", " "))
    return f'<span class="status-badge status-{semantic}">{icon(glyph, size=14)}<span>{h(text)}</span></span>'


def notice(message: str, *, kind: str = "info", title: str = "") -> str:
    if not message:
        return ""
    glyph = {"success": "check", "warning": "warning", "danger": "error"}.get(kind, "info")
    heading = f'<strong>{h(title)}</strong>' if title else ""
    return (
        f'<div class="notice notice-{h(kind)}" role="status">{icon(glyph, size=20)}'
        f'<div>{heading}<div>{h(message)}</div></div></div>'
    )


def empty_state(title: str, message: str, *, action_html: str = "", icon_name: str = "info") -> str:
    return (
        f'<div class="empty-state">{icon(icon_name, size=28)}<h3>{h(title)}</h3>'
        f'<p>{h(message)}</p>{action_html}</div>'
    )


def _navigation(role: str, pending_approvals: int) -> list[tuple[str, str, str, int]]:
    items = [
        ("overview", "概览", "/dashboard", 0),
        ("apps", "应用", "/dashboard/apps", 0),
    ]
    if role == "admin":
        items.append(("security", "访问控制", "/dashboard/security", pending_approvals))
    items.append(("activity", "活动", "/dashboard/activity", 0))
    if role == "admin":
        items.append(("settings", "设置", "/dashboard/settings", 0))
    return items


def render_shell(
    *,
    title: str,
    description: str,
    content: str,
    identity: dict[str, str],
    csrf_value: str,
    active_nav: str,
    gateway_phase: str,
    version: str,
    pending_approvals: int = 0,
    failed_apps: int = 0,
    unread_notifications: int = 0,
    tunnel_state: dict[str, object] | None = None,
    page_actions: str = "",
    breadcrumbs: Iterable[tuple[str, str]] = (),
    section_tabs: str = "",
    command_items: Iterable[CommandItem] = (),
    flash_message: str = "",
) -> HTMLResponse:
    role = identity.get("role", "guest")
    username = identity.get("username", "")
    nav_html: list[str] = []
    command_links: list[str] = []
    for key, label, url, count in _navigation(role, pending_approvals):
        current = ' aria-current="page"' if key == active_nav else ""
        badge = f'<span class="nav-badge" aria-label="{count} 个待处理">{count}</span>' if count else ""
        nav_html.append(
            f'<a class="nav-item" href="{h(url)}" data-tooltip="{h(label)}"{current}>'
            f'{icon(key)}<span class="nav-label">{h(label)}</span>{badge}</a>'
        )
        command_links.append(
            f'<a class="command-result" href="{h(url)}" data-command-text="{h(label)}">'
            f'{icon(key)}<span><strong>{h(label)}</strong><small>导航</small></span></a>'
        )
    for item in command_items:
        command_links.append(
            f'<a class="command-result" href="{h(item.url)}" '
            f'data-command-text="{h(item.label)} {h(item.description)} {h(item.group)}">'
            f'{icon(item.icon_name)}<span><strong>{h(item.label)}</strong>'
            f'<small>{h(item.group)}{(" · " + h(item.description)) if item.description else ""}</small></span></a>'
        )

    crumb_list = list(breadcrumbs)
    crumb_html = ""
    if crumb_list:
        pieces = []
        for index, (label, url) in enumerate(crumb_list):
            if index:
                pieces.append(icon("chevron", size=14))
            if url:
                pieces.append(f'<a href="{h(url)}">{h(label)}</a>')
            else:
                pieces.append(f'<span aria-current="page">{h(label)}</span>')
        crumb_html = f'<nav class="breadcrumbs" aria-label="面包屑">{"".join(pieces)}</nav>'

    alert_count = unread_notifications
    alert_badge = f'<span class="toolbar-badge">{alert_count}</span>' if alert_count else ""
    alert_url = "/dashboard/notifications"
    phase_kind = "success" if gateway_phase == "ready" else "warning"
    flash = notice(flash_message, kind="success") if flash_message else ""
    tunnel_state = tunnel_state or {}
    tunnel_status = str(tunnel_state.get("status", "unknown"))
    service_banner = ""
    if tunnel_status == "unhealthy":
        service_banner = notice(
            "公网入口连续健康检查失败；本地 Gateway 仍可使用，请在设置中查看集成状态。",
            kind="danger",
            title="公网隧道不可用",
        )
    elif tunnel_status == "degraded":
        service_banner = notice(
            "公网入口最近一次健康检查失败，正在继续确认。",
            kind="warning",
            title="公网隧道可能异常",
        )
    page = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>{h(title)} · Home Gateway</title>
  <link rel="stylesheet" href="/assets/gateway.css">
  <script src="/assets/gateway.js" defer></script>
</head>
<body>
  <a class="skip-link" href="#main-content">跳到主要内容</a>
  <div class="app-shell" data-nav="expanded">
    <div class="drawer-overlay" data-drawer-close></div>
    <aside class="global-navigation" id="global-navigation" aria-label="全局导航">
      <div class="brand-row">
        <a class="brand" href="/dashboard" aria-label="Home Gateway 概览">
          <span class="brand-mark">HG</span>
          <span class="brand-copy"><strong>Home Gateway</strong><small>Local control plane</small></span>
        </a>
        <button class="icon-button nav-collapse" type="button" data-nav-toggle aria-label="收起导航" title="收起导航">
          {icon("collapse")}
        </button>
      </div>
      <nav class="primary-navigation" aria-label="主导航">{"".join(nav_html)}</nav>
      <div class="navigation-footer">
        <div class="identity-block">
          <span class="identity-avatar">{h((username or "?")[:1].upper())}</span>
          <span class="identity-copy"><strong>{h(username)}</strong><small>{'管理员模式' if role == 'admin' else '只读访客'}</small></span>
        </div>
        <form method="post" action="/logout" class="logout-form">
          <input type="hidden" name="csrf_token" value="{h(csrf_value)}">
          <button class="nav-item logout-button" type="submit" data-tooltip="退出登录">
            {icon("logout")}<span class="nav-label">退出登录</span>
          </button>
        </form>
      </div>
    </aside>

    <section class="workspace">
      <header class="workspace-toolbar">
        <button class="icon-button mobile-menu" type="button" data-drawer-open aria-controls="global-navigation" aria-expanded="false" aria-label="打开导航">
          {icon("menu")}
        </button>
        <button class="command-trigger" type="button" data-command-open aria-haspopup="dialog">
          {icon("search")}<span>快速跳转</span><kbd>⌘ K</kbd>
        </button>
        <div class="toolbar-spacer"></div>
        <a class="icon-button notification-button" href="{h(alert_url)}" aria-label="{alert_count} 个需要关注的项目" title="需要关注">
          {icon("bell")}{alert_badge}
        </a>
        <button class="icon-button" type="button" data-theme-toggle aria-label="切换明暗主题" title="切换明暗主题">{icon("theme")}</button>
        <span class="role-chip">{h(role)}</span>
      </header>

      <main id="main-content" tabindex="-1">
        <div class="page-container">
          {crumb_html}
          <header class="page-header">
            <div class="page-heading"><h1 tabindex="-1">{h(title)}</h1><p>{h(description)}</p></div>
            <div class="page-actions">{page_actions}</div>
          </header>
          {section_tabs}
          {service_banner}
          {flash}
          {content}
        </div>
      </main>

      <footer class="status-bar" aria-label="系统状态">
        <span>{status_badge(gateway_phase, gateway_phase)}</span>
        <span>仅监听 loopback</span>
        <span class="status-spacer"></span>
        <span>Stage 5 Operations v1</span>
        <span>{h(version)}</span>
      </footer>
    </section>
  </div>

  <dialog class="command-dialog" data-command-dialog aria-labelledby="command-title">
    <div class="command-header">
      {icon("search")}<label class="sr-only" for="command-search" id="command-title">快速跳转</label>
      <input id="command-search" data-command-search autocomplete="off" placeholder="搜索页面或应用…">
      <kbd>Esc</kbd>
    </div>
    <div class="command-results" data-command-results>{"".join(command_links)}</div>
    <div class="command-empty" data-command-empty hidden>没有匹配结果</div>
  </dialog>

  <dialog class="confirm-dialog" data-confirm-dialog aria-labelledby="confirm-title">
    <form method="dialog">
      <div class="dialog-icon" data-confirm-icon>{icon("warning", size=24)}</div>
      <h2 id="confirm-title" data-confirm-title>确认操作</h2>
      <p data-confirm-message></p>
      <div class="dialog-actions">
        <button class="button secondary" value="cancel" data-confirm-cancel>取消</button>
        <button class="button danger" value="confirm" data-confirm-submit>确认</button>
      </div>
    </form>
  </dialog>
  <div class="toast-region" aria-live="polite" aria-atomic="true" data-toast-region></div>
</body>
</html>"""
    return HTMLResponse(page)


def render_login(
    *,
    csrf_value: str,
    flash_message: str,
    gateway_phase: str,
    version: str,
) -> HTMLResponse:
    flash = notice(flash_message, kind="warning") if flash_message else ""
    page = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>登录 · Home Gateway</title>
  <link rel="stylesheet" href="/assets/gateway.css">
  <script src="/assets/gateway.js" defer></script>
</head>
<body class="auth-page">
  <main class="auth-shell">
    <section class="auth-introduction" aria-labelledby="product-title">
      <div class="brand-mark brand-mark-large">HG</div>
      <p class="eyebrow">MAC MINI · LOCAL CONTROL PLANE</p>
      <h1 id="product-title">一个入口，管理所有本地服务。</h1>
      <p>Home Gateway 统一处理应用生命周期、设备授权、审批、审计和异常恢复。业务 App 不需要直接暴露到外部。</p>
      <ul class="auth-benefits">
        <li>{icon("security")}<span><strong>能力级授权</strong><small>设备只能调用被明确批准的 capability。</small></span></li>
        <li>{icon("activity")}<span><strong>完整活动记录</strong><small>控制操作、API 调用和恢复结果都有记录。</small></span></li>
        <li>{icon("restart")}<span><strong>自动恢复</strong><small>服务故障和临时 lease 都有确定的恢复路径。</small></span></li>
      </ul>
    </section>
    <section class="auth-card" aria-labelledby="login-title">
      <div class="auth-card-header">
        <div><p class="eyebrow">受保护的管理入口</p><h2 id="login-title">登录 Home Gateway</h2></div>
        {status_badge(gateway_phase, "Gateway " + gateway_phase)}
      </div>
      {flash}
      <form class="auth-form" method="post" action="/login" data-loading-form>
        <input type="hidden" name="csrf_token" value="{h(csrf_value)}">
        <div class="field">
          <label for="username">用户名</label>
          <input id="username" name="username" autocomplete="username" required autofocus>
        </div>
        <div class="field">
          <label for="password">密码</label>
          <input id="password" type="password" name="password" autocomplete="current-password" required>
        </div>
        <button class="button primary button-full" type="submit"><span>登录</span></button>
      </form>
      <p class="auth-help">凭据由 macOS Keychain 管理。连续失败会触发临时限速。</p>
      <div class="auth-meta"><span>仅允许受信 Host</span><span>{h(version)}</span></div>
    </section>
  </main>
</body>
</html>"""
    return HTMLResponse(page)
