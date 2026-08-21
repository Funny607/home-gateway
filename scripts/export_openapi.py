from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Export the protected Gateway OpenAPI document")
    parser.add_argument("--url", default="https://dev.lu607.com")
    parser.add_argument("--username", default="607")
    parser.add_argument("--output", type=Path, default=Path("sdk/openapi.stage5.json"))
    args = parser.parse_args()
    base = args.url.rstrip("/")
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    with opener.open(base + "/login", timeout=30) as response:
        login = response.read().decode("utf-8")
    match = re.search(r'name="csrf_token" value="([^"]+)"', login)
    if not match:
        raise SystemExit("login CSRF token was not found")
    body = urllib.parse.urlencode({
        "username": args.username,
        "password": getpass.getpass(f"{args.username} 管理员密码: "),
        "csrf_token": match.group(1),
    }).encode("utf-8")
    request = urllib.request.Request(
        base + "/login", data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with opener.open(request, timeout=30) as response:
        if "/login" in response.geturl():
            raise SystemExit("administrator login failed")
    with opener.open(base + "/api/admin/v1/openapi.json", timeout=30) as response:
        document = json.load(response)
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"OpenAPI exported: {output}")


if __name__ == "__main__":
    main()
