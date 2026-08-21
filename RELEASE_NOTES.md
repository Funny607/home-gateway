# Stage 5 发布说明

版本：`5.0.2-stage5-ops-v1`

`5.0.2` 调整公网隧道邮件策略：瞬时失败和恢复只保留在控制台活动记录中；同一次故障连续至少 1 小时仍未恢复时，才发送一次恢复失败邮件。故障计时保存在数据库中，Gateway 重启不会重置计时，也不会对同一次故障重复发信。

已安装 `5.0.1` 的用户可以直接把新 ZIP 覆盖解压到当前 Stage 5 项目目录所在的发布父目录；顶层 `runtime/` 和 `logs/` 不在 ZIP 内，因此现有数据库、恢复码与日志不会被覆盖。启动新版本时，旧版本遗留且尚未发送的瞬时公网失败/恢复邮件会被改为仅站内通知。

这是一个从 Stage 2 或 Stage 3 新目录升级的完整包。旧目录、旧数据库和旧虚拟环境不会被覆盖。

## 新增

- 完成 Stage 3：TOTP 防重放、全类型 macOS 桌面审批、payload-bound action Token、设备续期/信任/凭据管理，以及 qbt-cleaner critical 删除策略。
- 完成 Stage 4：schema v4、独立 database pepper、全类密钥轮换、一次性恢复码、受限 break-glass、外部 API 总开关和紧急全量撤权。
- 完成 Stage 5：一致性备份、清单验证、恢复脚本、定时保留、脱敏诊断包、运维 UI/API、升级回滚、部署历史、OpenAPI 导出与洁净发布构建。
- SDK/CLI 新增 action request/status、TOTP 批准和 action-bound Token。

## 重要升级行为

- 首次安装 Stage 5 会生成恢复码并仅显示一次。
- schema 从 v2/v3 迁移至 v4 前会在新目录的 `runtime/backups` 中创建迁移备份。
- 旧数据库仍保留在旧目录，因此回滚不需要把 schema v4 降级。
- `database-pepper` 首次从旧 session secret 安全初始化，以保持已有设备/Grant/Token 哈希可验证；以后两者可以独立轮换。
- Local Mailer 仍固定发送到 `lu.yuanqi.2005@gmail.com`，Gateway 不接触其 Microsoft Graph 凭据。

## 验收

```bash
./deploy/upgrade_to_stage5.sh /path/to/previous-release
./scripts/macos_uat_stage5.sh
```

自动回归当前包含 51 项测试；在已安装目录执行时，发布洁净度测试按设计跳过，洁净 ZIP 构建前会单独执行该检查。
