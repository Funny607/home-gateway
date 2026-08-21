# 升级与回滚

## 升级原则

Stage 5 必须解压到新目录。升级器停止当前 LaunchAgent 后，通过 SQLite backup API 从旧数据库创建一致性副本；旧目录、旧数据库、旧 `.venv` 和日志均不修改。

```bash
cd ~/dev/gateway-releases/5.0.1/webui_home_gateway_stage5_ops_v1
./deploy/upgrade_to_stage5.sh \
  ~/dev/gateway-releases/2.0.0/webui_home_gateway_stage2_uiux_v3
```

若此前已安装 Stage 3：

```bash
./deploy/upgrade_to_stage5.sh \
  ~/dev/gateway-releases/3.0.0/webui_home_gateway_stage3_security_v1
```

升级器会在 Stage 5 `runtime/previous_release_path.txt` 记录旧目录，用于一键回滚。Stage 5 首次打开数据库副本时迁移到 schema v4，并先在新目录创建迁移备份。

## 验收

```bash
curl --fail http://127.0.0.1:8081/readyz
./scripts/macos_uat_stage5.sh
```

## 回滚

```bash
./deploy/rollback_to_previous.sh
```

回滚会重新安装旧目录的 LaunchAgent，并使用从未被 Stage 5 修改的旧数据库。因此回滚点是“升级发生时”，Stage 5 运行后新增的设备、Grant、审计或配置不会自动写回旧版。

需要回到不同目录时可显式传入：

```bash
./deploy/rollback_to_previous.sh /absolute/path/to/previous-release
```
