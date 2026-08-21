# 产品路线

## Stage 1 — 安全、数据与可靠性底座（完成）

Loopback/Keychain/Argon2id、浏览器会话与 CSRF、Device/Grant/Token/Capability 闭环、SQLite v1、生命周期恢复与统一 UI。

## Stage 2 — 多 App 产品化（完成）

App Registry、通用 Lease、WebSocket/SSE/大请求代理、生命周期策略、审计、通知、Local Mailer、Cloudflare Tunnel 只读监控和可复用 SDK。

## Stage 3 — 高风险批准（完成）

- payload-bound per-action approval 与一次性 Token；
- Microsoft Authenticator TOTP 防重放；
- macOS 原生桌面批准；
- 设备更新、续期、信任调整、凭据轮换与级联撤销；
- qbt-cleaner critical 删除能力接入。

完成证据：长期 Grant 可保留，但每个 critical action 都必须重新批准；method/path/body 任一变化都会在代理前拒绝。

## Stage 4 — 恢复与密钥生命周期（完成）

- schema v4、独立 database pepper 和全类密钥轮换；
- 一次性恢复码与受限 break-glass Token；
- 外部 API 总开关、全量撤权与统一审计；
- SQLite 一致性备份及严格恢复前验证。

完成证据：恢复码原子单次消费；应急 Token 不能创建管理员会话；database pepper 轮换要求显式销毁外部信任并保留可恢复旧 pepper。

## Stage 5 — 可运维发布（完成）

- 定时备份、保留、校验和与篡改检测；
- 脱敏诊断包与运维 UI/API；
- Stage 2/3 → Stage 5 新目录升级与旧目录回滚；
- 部署历史、受保护 OpenAPI 导出、Stage 5 SDK/CLI；
- 可重复的洁净发布构建与 Mac UAT。

完成证据：升级不修改旧数据库；恢复前检查 manifest/schema/integrity/foreign keys；发布 ZIP 带 SHA-256 文件清单且不包含运行态或秘密。
