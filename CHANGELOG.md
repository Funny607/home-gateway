# Changelog

## 5.0.2-stage5-ops-v1

- 公网隧道的瞬时失败和恢复只写入控制台通知，不再发送邮件。
- 同一次公网故障持续至少 1 小时且仍未恢复时，才发送一次恢复失败邮件。
- 公网故障起始时间和告警状态持久化，Gateway 重启不会重置 1 小时计时或重复告警。
- 升级启动时停止重试旧版本遗留的瞬时公网失败/恢复邮件。
- 增加跨重启延迟、恢复重置、单次邮件和配置边界回归测试。

## 5.0.1-stage5-ops-v1

- 修复发布构建器误将源码包 `app/runtime/` 当成顶层运行数据目录排除的问题。
- 增加发布构建回归，保证 `RuntimeStore` 源码始终进入正式 ZIP。

## 5.0.0-stage5-ops-v1

- 增加一致性备份、清单验证、定时保留、严格恢复和脱敏诊断包。
- 增加运维 UI/API、部署历史、Stage 2/3 新目录升级与旧目录回滚。
- 增加受保护 OpenAPI 导出、Stage 5 SDK/CLI 和洁净发布构建器。
- 增加 Stage 3–5 Mac UAT 与完整回归。

## 4.0.0-stage4-recovery-v1

- 数据库升级至 schema v4，新增一次性恢复码和应急 Token。
- session signing secret 与 database pepper 解耦。
- 增加管理员/guest、session、desktop、TOTP、break-glass、database pepper 轮换。
- 增加外部 API 总开关、紧急全量撤权和受限 break-glass。

## 3.0.0-stage3-security-v1

- 增加数据库 schema v3 与升级前备份。
- 增加 payload-bound per-action approval 和最长 120 秒的一次性 token。
- 增加 Microsoft Authenticator TOTP 验证与时间步重放保护。
- 增加 Keychain 认证的 macOS 桌面批准 LaunchAgent。
- 代理依据真实请求体 SHA-256 做最终校验后才转发。
- 长期 grant 可重复发起新操作，但每个批准与 token 只能消费一次。
- 修复已安装目录 UAT 的发布洁净度误报。
- 修复页面标题程序化焦点蓝框，并补齐常见状态及生命周期事件中文标签。
- 补齐设备续期、信任调整、凭据轮换与全类型桌面批准。
- qbt-cleaner 删除能力接入 critical per-action approval。
