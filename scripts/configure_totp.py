from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.security.totp import generate_secret, provisioning_uri

SERVICE = "com.yuanqilu.webui-home-gateway"


def main() -> None:
    if sys.platform != "darwin":
        raise SystemExit("This enrollment helper must run on macOS")
    secret = generate_secret()
    subprocess.run([
        "/usr/bin/security", "add-generic-password", "-U", "-s", SERVICE,
        "-a", "totp-secret", "-w", secret,
    ], check=True, stdout=subprocess.DEVNULL)
    auth_path = ROOT / "configs" / "auth.yaml"
    text = auth_path.read_text(encoding="utf-8")
    reference = 'totp_secret_ref: "keychain:com.yuanqilu.webui-home-gateway:totp-secret"'
    if reference not in [line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")]:
        commented = f"# {reference}"
        if commented not in text:
            raise SystemExit("configs/auth.yaml 中缺少 TOTP Keychain 引用占位符")
        auth_path.write_text(text.replace(commented, reference, 1), encoding="utf-8")
    print("在 Microsoft Authenticator 中选择“其他账户”，输入以下密钥：")
    print(secret)
    print("账户: 607")
    print("类型: 基于时间")
    print("URI（如使用支持 URI 的导入器）:")
    print(provisioning_uri(secret, issuer="Home Gateway", account="607"))
    print("configs/auth.yaml 已启用 totp_secret_ref；请运行 ./deploy/renew.sh 重启 Gateway。")


if __name__ == "__main__":
    main()
