# WebUI Home Gateway UI/UX v2 设计与复现规范

版本：`1.1.0-stage1-uiux`  
适用范围：Mac Mini 本地 Gateway 的浏览器管理界面  
设计依据：`General Management UI Design Guide v1.1` 与 Gateway 的最终产品目标

## 1. 设计目标

这个界面不是本地 App 的链接集合，而是本地服务的控制平面。用户进入后应按以下顺序完成工作：

1. 发现需要处理的异常、审批或恢复任务；
2. 判断具体 App 是否健康、是否应该启动或停止；
3. 管理外部设备的信任与 capability 授权；
4. 追查某次生命周期变化或 API 调用；
5. 核对 Gateway 自身是否满足安全运行条件。

界面不会把数据库表直接作为一级导航，也不会为每个本地 App 复制一套管理结构。所有 App 共享同一套状态、命令、权限和审计语言。

## 2. 用户与权限

| 角色 | 核心任务 | 可见区域 | 禁止行为 |
|---|---|---|---|
| admin | 管理 App、批准设备与 grant、排障、审计 | 概览、应用、安全、活动、系统 | 不能绕过 capability 策略或活动 lease 保护 |
| guest | 查看被允许的 App 状态与生命周期活动 | 概览、应用、活动 | 不渲染启动、停止、重启、安全或系统命令 |
| 外部程序 | 使用设备凭据换取短时 token 并调用 capability | 不使用 Web Dashboard | 不能访问未声明路径、不能自报信任或风险 |

权限规则采用“服务端不渲染”而不是“前端隐藏”。直接访问无权限 URL 时仍由服务端拒绝。

## 3. 信息架构

全局导航只有一份数据结构，并按角色过滤：

```text
概览
应用
安全（admin）
  ├─ 安全概况
  ├─ 设备
  ├─ 授权
  ├─ 审批
  └─ Lease
活动
  ├─ 生命周期事件
  └─ API 审计（admin）
系统（admin）
```

“设备、授权、审批”属于同一外部访问闭环，因此使用安全中心内的二级标签，而不是三个互不关联的一级页面。“生命周期事件、API 审计”都回答“发生了什么”，因此归入活动。

## 4. 关键任务流

### 4.1 处理故障 App

```text
概览的“需要关注”
  → 打开 App 详情
  → 查看概况 / 活动 / 日志
  → 根据状态执行重试、重启或停止
  → 危险命令确认
  → 返回原列表或详情上下文
```

命令随状态出现：停止状态显示“启动”；失败状态显示“重试启动”；运行状态显示“打开”，并把“重启、停止”放入更多菜单。活动 lease 存在时，服务端仍会拒绝停止。

### 4.2 批准外部设备

```text
设备发起 registration
  → 管理员在概览或安全中心看到待审批
  → 核对设备、请求码、风险和到期时间
  → 选择信任级别并批准 / 明确拒绝
  → 设备变为 active 或 revoked
```

网页不能绕过策略声明的审批方式。请求码在设备端一次性展示，管理员必须输入同一请求码。

### 4.3 批准 capability grant

```text
受信设备申请 capability
  → Policy Engine 推导风险、信任要求和最大 TTL
  → 管理员核对目标 App、capability、风险、期限和请求码
  → 创建 grant
  → 设备使用长期 device_secret + grant 换取最长 15 分钟的 token
```

### 4.4 追查 API 调用

```text
活动 → API 审计
  → 查调用方、目标 App、capability / 路径
  → 查成功或失败、耗时、错误和 request_id
  → 需要时回到设备、grant 或 App 详情
```

UI 与 `GET /api/audit/v1` 都不返回客户端 IP、User-Agent、token 或 device secret。

## 5. 页面规格

### 5.1 登录

- 独立页面，不显示无意义的空导航；
- 说明产品是本地控制平面，而不是普通 App 首页；
- 展示 Gateway 运行状态；
- 使用用户名、密码、CSRF、限速和 macOS Keychain；
- 登录提交时锁定按钮并显示处理中状态。

### 5.2 概览

信息顺序固定为：关键指标 → 需要关注 → 最近活动 → 应用健康。

- 关键指标只保留 Gateway 状态、运行应用、异常数、待审批数；
- “需要关注”只显示失败、健康异常和 pending approval；
- 正常状态使用空状态明确告知“无需处理”；
- 应用表用于比较，不展示完整配置 JSON。

### 5.3 应用

- 支持按名称、ID、状态和入口搜索；
- 支持运行中、已停止、失败筛选；
- 每行显示状态、Gateway 入口、最近活动、连续失败和可执行命令；
- App 详情使用“概况、活动、日志、访问与能力”标签；
- 日志不自动刷新，保留阅读位置；
- 配置与原始运行数据采用渐进披露。

### 5.4 安全

- 安全概况显示受信设备、待审批、活动 token、活动 lease；
- 设备撤销明确提示会级联撤销 grant/token，并让 lease 进入恢复；
- grant 同时显示设备、App、capability、风险、到期与状态；
- pending approval 排在已处理记录之前；
- 批准表单同时呈现请求码和设备信任级别；拒绝需要确认。
- Lease 页面显示设备、capability、心跳、到期、释放原因与恢复状态。

### 5.5 活动

- guest 只看到其可见 App 的生命周期事件；
- admin 可切换生命周期事件与 API 审计；
- 结构化原始数据默认收起；
- 不使用整页定时刷新；用户主动刷新时保留当前标签。

### 5.6 系统

- 核对 Gateway phase、loopback 监听、SQLite 完整性和配置目录；
- 展示版本、恢复策略、自动重启、轮询频率和运行路径；
- 明确部署约束：8081 和子 App 端口不能直接暴露公网。

## 6. 响应式与导航

| 视口 | 导航模式 | 行为 |
|---|---|---|
| `>= 1200px` | 232px expanded / 56px compact | 用户选择保存在 `localStorage` |
| `720–1199px` | 56px compact | 标签变为可聚焦 tooltip |
| `< 720px` | drawer | 遮罩、焦点进入、Tab 循环、Esc/点击遮罩关闭并恢复触发点焦点 |

移动端数据表转换为带字段标签的卡片行，不要求用户横向滚动。320px 是最小支持宽度。

## 7. 状态与反馈

- `success`：ready、running、active、trusted、approved；
- `warning`：pending、待审批；
- `info`：starting、stopping、recovering、paired；
- `danger`：failed、denied、revoked；
- `neutral`：stopped、expired、released。

颜色不是唯一编码；所有状态都带文字和 SVG 图标。提交表单后按钮进入 `aria-busy` 并禁用。停止、重启、撤销设备、撤销 grant、拒绝审批必须经过确认对话框；对话框关闭后恢复原命令焦点。

## 8. 可访问性

- 使用 `aside/nav/main/header/footer/table/dialog/form` 等语义元素；
- 当前全局区域和当前标签使用 `aria-current="page"`；
- 提供跳到主要内容链接；
- 所有交互支持键盘，焦点轮廓不被移除；
- 页面导航后把焦点移到 `h1`；
- 动态提示使用 `aria-live`；
- 支持 `prefers-reduced-motion` 与 forced-colors；
- 图标使用内联 SVG，装饰图标从可访问树隐藏。

## 9. 实现映射

| 层 | 文件 | 责任 |
|---|---|---|
| Shell | `app/ui/design.py` | 全局导航、命令面板、对话框、登录与统一页面框架 |
| Page views | `app/ui/pages.py` | 概览、应用、详情、活动、系统的信息编排 |
| Design tokens | `app/ui/static/gateway.css` | 布局、视觉状态、响应式、可访问性样式 |
| Interaction | `app/ui/static/gateway.js` | 导航、抽屉、搜索、确认、焦点与加载反馈 |
| Security views | `app/api_v1/admin_security.py` | 安全概况、设备、grant、审批和管理 API |
| Audit query | `app/security/service.py` | 有界、脱敏、按时间倒序的审计检索 |

所有新页面都调用同一个 `render_gateway_page`，避免安全中心形成第二套视觉或导航结构。

## 10. 本地复现

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock.txt
./scripts/test_stage1.sh
./deploy/install_launchd.sh
```

本地访问：`http://127.0.0.1:8081/login`  
Tunnel 访问：`https://dev.lu607.com/login`

测试至少覆盖：角色导航、响应式资源、无自动刷新、guest 不渲染控制命令、安全中心统一 Shell、请求码审批 API、手工设备 API、审计检索与既有安全/生命周期回归。

## 11. Stage 1 边界

- App Registry 仍由 YAML 管理；
- qbt-mode lease 仍是专用实现；
- TOTP、macOS 桌面审批、payload-bound 单次操作审批属于 Stage 3；
- 审计导出、保留周期、跨字段高级筛选属于 Stage 2；
- WebSocket 代理尚未实现。

这些边界在 UI 中不会伪装成已完成能力；尚未实现的命令不会被渲染。
