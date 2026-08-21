# Stage 2 自动化测试范围

运行：

```bash
./scripts/test_stage2.sh
```

当前测试集共 38 项；安装脚本和测试脚本均使用 `requirements.lock.txt` 的精确依赖版本。

覆盖：

- 严格配置、loopback、保留路径、capability 匹配、依赖环与 Stage 3 字段拒绝；
- v0 → v1 → v2 数据库备份、迁移、外键、索引与完整性；
- Device/Grant/Token、审批请求码、trust/TTL、一次性消费与撤销级联；
- 通用 Lease 的共享资源 acquire-once / release-last、释放失败恢复；
- Notification outbox 的去重、邮件成功、失败保留与重试状态；
- Registry preview/save、原子文件与 revision 冲突；
- PID 代际身份、滚动生命周期元数据；
- Gateway/Authorization/Cookie header 隔离与 canonical path；
- API 请求体上限、WebSocket echo、角色代理边界；
- UI v3 导航、注册表、设置、通知中心与明暗/响应式资源；
- 审计查询/导出与敏感传输字段隐藏；
- 发布包无 `.venv`、runtime、logs、SQLite、备份、pyc 或明文秘密。

HTTP 测试使用临时配置、临时数据库和 demo App，不读取真实 Keychain、数据库或 Local Mailer，也不发送真实邮件。
