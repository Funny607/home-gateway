# WebUI Home Gateway — Stage 5 Operations v1

这是面向 Mac Mini 的完整可安装包，包含 Stage 1–5 的全部能力，不需要与旧包手工合并。Gateway 与子应用只监听 loopback；公网入口仍由现有 Cloudflare Tunnel 转发到 Gateway。

## Stage 3–5 已完成内容

### Stage 3：高风险操作与设备安全

- 长期 Device/Grant 与短时 Token 分离；critical capability 必须逐次批准。
- 批准记录绑定 App、Capability、HTTP method、规范化 path、请求体 SHA-256 与可读预览。
- 一次性 Token 在真实代理请求匹配全部字段后原子消费，不能“批准 A、执行 B”。
- Web 管理员、Microsoft Authenticator TOTP、macOS 原生桌面弹窗三种批准方式并存，由策略与用户选择。
- TOTP 同一时间步不可重放；桌面批准器使用独立 Keychain 密钥。
- 管理员可更新设备名称/信任/期限、轮换设备凭据或级联撤销设备。
- `qbt-cleaner.deletion.execute` 已作为 critical capability 接入逐次批准。

### Stage 4：恢复、密钥与 break-glass

- SQLite schema v4；session signing secret 与数据库 pepper 已拆分，可独立轮换。
- 管理员/guest 密码、session、desktop、TOTP、break-glass 与 database pepper 均有显式轮换脚本。
- 一次性离线恢复码；恢复码加 pepper 哈希保存，明文只显示一次。
- break-glass 需要本机 Keychain verifier + 恢复码，只签发最长 30 分钟、默认 15 分钟的受限 Token。
- 应急 Token 只能查看状态、创建备份、禁用外部 API、撤销所有外部访问；不能创建管理员浏览器会话。
- 外部 API 总开关、撤权与恢复动作均写入统一审计。

### Stage 5：运维、升级与发布

- SQLite 一致性备份、SHA-256 清单验证、保留策略与定时备份。
- 脱敏诊断包：运行报告、数据库完整性、LaunchAgent 信息、配置和日志尾部；敏感字段会被替换。
- 离线恢复脚本先验证 ZIP、成员校验和、schema、SQLite integrity 与 foreign keys，再切换数据库。
- Stage 2/3 → Stage 5 一键升级；旧目录和旧数据库保持不变，可一键回滚。
- UI 新增“设置 → 运维与恢复”；管理员 API 提供状态、备份、诊断和受限应急端点。
- SDK/CLI 支持 high-risk action request、TOTP 批准、action status 和 action-bound Token。
- 受保护 OpenAPI 可导出；发布构建器会排除 `.venv`、运行数据、日志、备份和缓存，并生成文件校验清单。

## 从当前 Stage 2 安装升级（推荐）

把 ZIP 解压到新目录后执行：

```bash
mkdir -p ~/dev/gateway-releases/5.0.1
ditto -x -k ~/Downloads/Home-Gateway-Stage5-Ops-v1-5.0.1-stage5-ops-v1.zip \
  ~/dev/gateway-releases/5.0.1

cd ~/dev/gateway-releases/5.0.1/webui_home_gateway_stage5_ops_v1
chmod +x deploy/*.sh scripts/*.sh scripts/*.py

./deploy/upgrade_to_stage5.sh \
  ~/dev/gateway-releases/2.0.0/webui_home_gateway_stage2_uiux_v3
```

安装时会沿用现有管理员、guest、qBittorrent 与 Local Mailer Keychain 项；首次升级会显示一组恢复码，请立即保存到离线密码管理器或打印件。旧 Stage 2 目录不被修改。

若从 Stage 3 升级，把最后一个参数替换为 Stage 3 目录；不传参数时升级器会自动寻找标准 Stage 3/Stage 2 路径。

## 全新安装

```bash
cd ~/dev/gateway-releases/5.0.1/webui_home_gateway_stage5_ops_v1
./deploy/install_launchd.sh
curl --fail http://127.0.0.1:8081/readyz
```

管理入口：<https://dev.lu607.com/dashboard>

## 升级后验收

```bash
./scripts/macos_uat_stage5.sh
```

自动回归覆盖 Stage 1–5；UAT 会提示输入管理员密码完成 HTTPS 只读验收，不自动发送邮件，也不自动执行恢复演练。

## 启用 Microsoft Authenticator

```bash
.venv/bin/python scripts/configure_totp.py
./deploy/renew.sh
```

脚本会把密钥写入 macOS Keychain、自动启用 `totp_secret_ref`，并一次性显示 Microsoft Authenticator 注册信息。

## 运维命令

```bash
# 轮换管理员密码或 session signing secret
.venv/bin/python scripts/rotate_keys.py admin-password
.venv/bin/python scripts/rotate_keys.py session

# 重新生成恢复码（旧的未使用码会被撤销）
.venv/bin/python scripts/configure_recovery_codes.py

# 本机受限应急操作
.venv/bin/python scripts/breakglass.py create-backup
.venv/bin/python scripts/breakglass.py disable-external-api
.venv/bin/python scripts/breakglass.py revoke-all-access

# 恢复一个已验证备份
.venv/bin/python scripts/restore_backup.py runtime/backups/operations/<backup>.zip --confirm RESTORE

# 回滚到升级前完整目录
./deploy/rollback_to_previous.sh
```

`database-pepper` 轮换会使全部外部设备凭据、Grant、Token 和恢复码失效，因此需要双重显式确认；旧 pepper 会保存在带时间戳的 macOS Keychain 项中。

## 主要 API

- Device/Grant/Token：`/api/auth/v1/*`
- 高风险操作批准：`/api/auth/v1/actions/*`、`/api/auth/v1/approvals/*`
- Capability proxy：`/api/apps/v1/{app_id}/{path}`
- 通用 Lease：`/api/leases/v1/*`
- 运维：`/api/operations/v1/*`
- 受限应急：`/api/emergency/v1/*`
- 受保护 OpenAPI：`GET /api/admin/v1/openapi.json`

公共 `/docs`、`/redoc` 和 `/openapi.json` 均关闭。导出当前 OpenAPI：

```bash
.venv/bin/python scripts/export_openapi.py
```

## Local Mailer 边界

邮件固定发送到 `lu.yuanqi.2005@gmail.com`。Gateway 只以固定参数数组调用：

```text
/usr/bin/python3 /Users/yuanqilu/dev/Local_Mailer/send_mail.py send ...
```

Gateway 不读取 Local Mailer 的 Microsoft Graph Token、配置或缓存；邮件失败保留在持久化 outbox 中重试。

公网隧道使用延迟告警策略：瞬时失败和恢复只写入控制台；同一次故障连续至少 3600 秒仍未恢复时，才发送一次“公网隧道恢复失败”邮件。故障开始时间和本次告警状态持久化在 Gateway 数据库中，进程重启不会重置计时或导致重复发信。该阈值由 `configs/gateway.yaml` 的 `tunnel.alert_after_seconds` 控制。

## 发布边界

发布包不包含 `.venv/`、`runtime/`、`logs/`、SQLite/WAL/SHM、备份、诊断包、`__pycache__/`、密码、Cookie、设备密钥或访问 Token。YAML 只保存 `keychain:` / `env:` 引用。
