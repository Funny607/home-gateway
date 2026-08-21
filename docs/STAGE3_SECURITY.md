# Stage 3 高风险操作批准

Stage 3 把长期设备授权与单次高风险操作分开：长期 grant 可以保留，但每个声明了
`per_action_approval` 的操作都必须重新批准，并领取最长 120 秒的一次性 token。

## 绑定内容

批准记录与 token 同时绑定：HTTP method、规范化上游 path（含 query）、请求体
SHA-256、target app、capability、device 和 parent grant。代理先缓存并计算真实请求体
哈希，匹配全部字段后才原子消费 token 与 action approval；任何字段不符都不转发。

## 批准方式

- `web-admin`：管理员在访问控制页面输入请求码。
- `totp`：Gateway 自己验证 Microsoft Authenticator 的 6 位 TOTP；同一时间步不可重放。
- `desktop`：独立 LaunchAgent 每 3 秒读取本机待批准项，以 macOS 对话框显示操作和
  payload preview。帮助程序通过 Keychain 内独立随机密钥认证，缺失或异常时安全失败。

策略可同时声明多个方式，客户端选择其中一个。关键 capability 必须配置
`per_action_approval: true`、`require_payload_preview: true` 和 `one_time_token: true`。

## Microsoft Authenticator 注册

```bash
cd ~/dev/gateway-releases/5.0.1/webui_home_gateway_stage5_ops_v1
.venv/bin/python scripts/configure_totp.py
./deploy/renew.sh
```

在 Microsoft Authenticator 中选择“其他账户”，按脚本的一次性输出添加密钥；脚本会自动
启用 `configs/auth.yaml` 中的 `totp_secret_ref`。密钥只保存在
登录用户的 macOS Keychain，不写入数据库、YAML 或日志。

## 客户端顺序

1. 使用现有 grant 调用 `POST /api/auth/v1/actions/request`，提交 capability、method、
   path、body_sha256 和可读 payload_preview。
2. 通过 web admin、TOTP 或桌面弹窗批准。
3. 轮询 `POST /api/auth/v1/actions/{approval_id}/status`。
4. 调用 `POST /api/auth/v1/token`，同时提交 `action_approval_id`。
5. 使用返回的 Bearer token 发送完全相同的请求；token 只能成功使用一次。

Stage 5 数据库 schema 为 v4；从 v2/v3 迁移前会在新目录自动创建 `pre-stage5-v4` 备份。
