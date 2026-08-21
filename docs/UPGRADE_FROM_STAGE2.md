# 从已运行的 Stage 2 升级

当前完整流程见 `UPGRADE_TO_STAGE5.md`。针对现有标准目录可直接运行：

```bash
cd ~/dev/gateway-releases/5.0.1/webui_home_gateway_stage5_ops_v1
./deploy/upgrade_to_stage5.sh \
  ~/dev/gateway-releases/2.0.0/webui_home_gateway_stage2_uiux_v3
./scripts/macos_uat_stage5.sh
```

旧 Stage 2 目录和数据库保持不变；回滚执行 `./deploy/rollback_to_previous.sh`。
