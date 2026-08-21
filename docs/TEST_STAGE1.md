# Stage 1 自动化测试范围

运行：

```bash
./scripts/test_stage1.sh
```

当前测试覆盖：

- 配置拒绝未知字段、非回环地址、保留 mount、无效正则；
- capability prefix 边界和 regex full-match；
- 风险、信任、TTL、审批和一次性动作由 Policy Engine 推导；
- v0 SQLite 自动备份、v1 迁移、外键、索引和完整性检查；
- device secret 不以明文落盘，grant 申请必须验证 secret；
- device 审批、grant 审批、token 签发、introspection、自撤销；
- 过期审批不可批准，过期信任不可使用；
- 一次性 token 只能原子消费一次；
- `/docs` 和公共 OpenAPI 关闭，管理 OpenAPI 受保护；
- 登录 CSRF、管理 API CSRF、Host allowlist；
- guest 即使在 App 已运行时也无法穿透 WebUI；
- 外部代理会删除伪造的 `X-Gateway-*`，再注入可信身份。
- WebUI 代理不会把 Gateway session/Authorization 交给子 App，子 App 不能覆盖 Gateway Cookie；
- 点路径、编码斜杠、反斜杠、重复斜杠和双重编码路径被拒绝；
- 多设备 lease 中，只有最后一个 lease 释放时才回到 normal，失败会进入自动恢复。

自动化测试使用临时配置、临时 SQLite 和 demo App，不会读取或修改真实运行数据库。
