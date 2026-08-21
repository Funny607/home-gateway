# Mac Mini Stage 5 验收指南

## 1. 并行解压与安装

保留仍在运行的旧目录，把新包解压到新目录：

```bash
./deploy/install_launchd.sh
```

秘密进入当前 macOS 用户的 Keychain。安装器不会修改 Cloudflare Tunnel。

确认以下本地路径存在；若路径不同，请先记录差异：

```bash
test -f /Users/yuanqilu/dev/Local_Mailer/send_mail.py
test -d /Users/yuanqilu/dev/qbt_mode
test -d /Users/yuanqilu/dev/qbt_cleaner
test -d /Users/yuanqilu/dev/Live_Downloader
```

## 2. 一键验收

```bash
./scripts/macos_uat_stage5.sh
```

它验证完整回归、配置/Keychain/数据库、8081 loopback、本地 readiness、Local Mailer 路径和 HTTPS 管理页面。报告写入 `uat-results/stage2-uat-*.json`，不含密码、Cookie、CSRF、device secret 或 token。

## 3. UI 人工检查

打开 <https://dev.lu607.com>：

1. admin 全局导航应为“概览、应用、访问控制、活动、设置”；guest 不显示访问控制与设置。
2. “应用”包含“运行与健康 / 应用注册表”。打开清单编辑器但不要保存真实应用，检查 YAML、revision 提示与危险停用确认。
3. 全局铃铛打开“通知中心”。“设置 → 通知”显示 `lu.yuanqi.2005@gmail.com`，并能看到 Python 与脚本路径状态。
4. 在“设置 → 通知”点击“发送测试通知”。页面应显示已入队，通知中心最终显示“邮件已发送”；收件箱应收到 `[Home Gateway]` 前缀邮件。
5. “设置 → 集成”显示 Tunnel 的只读健康状态；这里不应存在修改 Cloudflare 配置的按钮。
6. “活动 → API 审计”可筛选并导出 CSV；文件不应包含 token、Cookie、密码、客户端 IP 或 User-Agent。
7. 窗口小于 720px 时导航变抽屉、表格变标签卡片；在 320px 或浏览器 400% 缩放下不出现双向滚动。
8. `⌘K` 打开命令面板；键盘能操作对话框并看见焦点；主题按钮可切换明暗模式。
9. Tunnel 失败、应用失败等关键状态应有页面横幅和通知记录，不能只出现短暂 Toast。

## 4. Device/Grant/Token/Lease

可使用内置 CLI：

```bash
./scripts/gatewayctl.py --url https://dev.lu607.com register --name test-watcher
./scripts/gatewayctl.py --url https://dev.lu607.com registration-status
```

管理员批准设备后，申请 grant、签发 token，再调用 capability 或通用 Lease。凭据文件必须保持 `0600`；CLI 不把 device secret 或 access token打印到终端。

## 5. 反馈材料

如失败，请提供：

- `uat-results/stage2-uat-*.json`
- `logs/launchd.stderr.log` 最后 100 行
- 失败页面文字或截图
- 所执行命令与发生时间

不要提供 Keychain 内容、密码、device secret、access token 或 Local Mailer token。
