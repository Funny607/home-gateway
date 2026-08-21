# Stage 4–5 恢复与运维

## 恢复码

安装器会在没有活动恢复码时生成 8 个一次性恢复码。数据库只保存带独立 pepper 的哈希；明文不会再次显示。

重新生成会撤销所有尚未使用的旧码：

```bash
.venv/bin/python scripts/configure_recovery_codes.py
```

## 受限 break-glass

激活同时要求：

1. 当前登录用户 macOS Keychain 中的 `breakglass-secret`；
2. 一个未使用恢复码；
3. loopback Gateway 可达。

应急 Token 默认 15 分钟有效，只允许状态、备份、禁用外部 API 和全量撤销外部访问。它不能登录网页、修改应用清单、启动应用或调用应用 API。

```bash
.venv/bin/python scripts/breakglass.py create-backup
.venv/bin/python scripts/breakglass.py disable-external-api
.venv/bin/python scripts/breakglass.py revoke-all-access
```

网页管理员可在“设置 → 运维与恢复”重新启用外部 API。

## 备份与恢复

备份默认位于 `runtime/backups/operations`，包含 SQLite 一致性副本、YAML 配置副本和 SHA-256 manifest。校验和用于检测损坏或意外修改，不是第三方数字签名。

恢复脚本要求备份位于受管备份目录，并检查 ZIP 成员、校验和、schema v4、SQLite integrity 和 foreign keys。恢复前会自动创建当前状态备份；即使恢复失败，也会尝试重新启动 LaunchAgent。

```bash
.venv/bin/python scripts/restore_backup.py \
  runtime/backups/operations/gateway-backup-YYYYMMDD-HHMMSS-NNNNNNNNN.zip \
  --confirm RESTORE
```

只有明确需要恢复 YAML 时才加 `--restore-configs`。配置会先在临时目录解析验证，再切换。

## 诊断包

诊断包默认位于 `runtime/diagnostics`，包含平台/版本/数据库状态、LaunchAgent 输出、YAML 和日志尾部。password、secret、token、authorization、cookie、credential 等敏感键值会被替换为 `[redacted]`。

## 密钥轮换

```bash
.venv/bin/python scripts/rotate_keys.py admin-password
.venv/bin/python scripts/rotate_keys.py guest-password
.venv/bin/python scripts/rotate_keys.py session
.venv/bin/python scripts/rotate_keys.py desktop
.venv/bin/python scripts/rotate_keys.py breakglass
.venv/bin/python scripts/rotate_keys.py totp
```

数据库 pepper 轮换会使全部外部身份和恢复码失效，必须显式执行：

```bash
.venv/bin/python scripts/rotate_keys.py database-pepper \
  --invalidate-external-access \
  --confirm ROTATE-DATABASE-PEPPER
```

脚本先创建备份，把旧 pepper 保存到带时间戳的 macOS Keychain 账户，再清除受旧 pepper 保护的外部身份记录。完成后必须重新注册设备并生成恢复码。
