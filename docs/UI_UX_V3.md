# Home Gateway UI/UX v3 实现规范

基线：`General-Management-UI-Design-Guide-v2.0`。此文件记录 Stage 2 如何把指南落到真实页面和状态，不重复通用设计原文。

## 信息架构

| 层级 | v3 实现 |
|---|---|
| 全局 | 概览、应用、访问控制、活动、设置；全局铃铛进入通知中心 |
| 上下文 | 应用：运行与健康 / 注册表；访问控制：设备 / 授权 / 审批 / Lease；设置：五个标签 |
| 内容 | Page Header、一个主要操作、筛选/表格、详情/日志、空/错/加载状态 |

设置放在导航底部稳定位置，不随当前应用改变。页面 URL 保存 tab、筛选、搜索和分页；浏览器返回不会丢失上下文。

## 响应式转换

- ≥1200px：232px 导航，可手动收为 56px。
- 720–1199px：56px 紧凑导航与可见 tooltip。
- <720px：导航抽屉；Page Header 操作换行；表格转换为带 `data-label` 的卡片行。
- 最小 320px；400% 缩放时按窄屏规则回流。

## 反馈与通知族

| 类型 | 用途 | 本实现 |
|---|---|---|
| Inline | 字段规则/风险提示 | 清单、审批、Local Mailer 与安全边界 |
| Page Banner | 页面级、持续问题 | Tunnel degraded/unhealthy、代理错误 |
| Toast | 非关键即时完成 | 仅作辅助；关键结果还会持久化 |
| Modal | 不可逆或破坏性操作 | 停止、重启、停用、撤销、拒绝 |
| Notification Center | 异步/跨会话证据 | 应用、Lease、Tunnel、审批、邮件投递 |

邮件发送失败时通知记录仍保留，并显示 `failed` 与重试信息；不以邮件或 Toast 作为唯一证据。

## 视觉与可访问性

- 语义 token 基线：`#F5F6F8` 背景、白色 surface、`#0F6CBD` 主色、4px 倍数间距。
- 系统字体，14px 正文；表格标题与状态 badge 使用语义文本和图标，状态不只靠颜色。
- `:focus-visible`、skip link、语义 `nav/main/header/table/dialog`、焦点回送和抽屉 focus trap。
- 支持 `prefers-reduced-motion`、`forced-colors` 和系统/显式明暗主题。
- 所有按钮有至少 34–40px 可操作高度；错误信息使用可读文字，不暴露内部 secret。

## 关键页面

- **概览**：异常和待审批优先，随后是应用健康与最近活动。
- **应用**：运行状态表 + Registry 清单工作流。注册表只在停止且无活动 Lease 时更新。
- **访问控制**：完整 device → grant → token → capability/lease 信任链。
- **活动**：生命周期与 API 审计分离；审计可导出。
- **设置**：常规、通知、集成、安全、关于。Tunnel 只读，Local Mailer 可显式测试。
- **通知中心**：未读、重复次数、类别、站内/队列/发送/失败状态和持久化分页。

## 验收门槛

自动化检查导航/角色差异、主题与响应式资源、管理表面、WebSocket、请求体 413、通知 outbox、Registry、审计导出和无 secret 发布。Mac 人工验收补充 320px/400%、键盘、真实 Local Mailer 和真实 Tunnel 状态。
