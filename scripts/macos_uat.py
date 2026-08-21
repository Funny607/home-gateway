from __future__ import annotations

import argparse
import getpass
import json
import re
import time
from pathlib import Path

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only Stage 5 HTTPS acceptance test")
    parser.add_argument("--base-url", default="https://dev.lu607.com")
    parser.add_argument("--username", default="607")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    if not base_url.startswith("https://"):
        raise SystemExit("Authenticated UAT requires the HTTPS Cloudflare URL")
    password = getpass.getpass(f"{args.username} 管理员密码: ")
    checks: list[dict] = []

    def check(name: str, actual: int, expected: int) -> None:
        checks.append({"name": name, "actual": actual, "expected": expected, "ok": actual == expected})

    def check_true(name: str, actual: bool) -> None:
        checks.append({"name": name, "actual": actual, "expected": True, "ok": actual is True})

    with httpx.Client(base_url=base_url, follow_redirects=False, timeout=15.0) as client:
        check("public healthz", client.get("/healthz").status_code, 200)
        check("public docs disabled", client.get("/docs").status_code, 404)
        check("public openapi disabled", client.get("/openapi.json").status_code, 404)
        check("anonymous app inventory denied", client.get("/api/apps").status_code, 401)

        login_page = client.get("/login")
        match = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
        if login_page.status_code != 200 or not match:
            raise SystemExit("Login page or CSRF token is unavailable")
        response = client.post(
            "/login",
            data={
                "username": args.username,
                "password": password,
                "csrf_token": match.group(1),
            },
        )
        check("admin login redirect", response.status_code, 303)
        dashboard = client.get("/dashboard")
        check("authenticated dashboard", dashboard.status_code, 200)
        check_true("goal-driven global navigation", all(
            href in dashboard.text
            for href in (
                'href="/dashboard/apps"',
                'href="/dashboard/security"',
                'href="/dashboard/activity"',
                'href="/dashboard/settings"',
            )
        ))
        check_true("dashboard does not auto refresh", 'http-equiv="refresh"' not in dashboard.text)
        check("UI stylesheet", client.get("/assets/gateway.css").status_code, 200)
        check("security workspace", client.get("/dashboard/security").status_code, 200)
        check("lease workspace", client.get("/dashboard/leases").status_code, 200)
        check("audit workspace", client.get("/dashboard/activity?tab=audit").status_code, 200)
        check("settings workspace", client.get("/dashboard/settings").status_code, 200)
        operations_page = client.get("/dashboard/operations")
        check("operations workspace", operations_page.status_code, 200)
        check_true("settings links operations", 'href="/dashboard/operations"' in client.get("/dashboard/settings").text)
        check("app registry workspace", client.get("/dashboard/apps?tab=registry").status_code, 200)
        check("notification center", client.get("/dashboard/notifications").status_code, 200)
        notification_health = client.get("/api/notifications/v1/health")
        check("Local Mailer health surface", notification_health.status_code, 200)
        registry_response = client.get("/api/registry/v1/apps")
        check("app registry API", registry_response.status_code, 200)
        audit_export = client.get("/api/audit/v1/export?format=csv")
        check("audit CSV export", audit_export.status_code, 200)
        csrf_response = client.get("/api/auth/v1/csrf")
        check("admin CSRF endpoint", csrf_response.status_code, 200)
        summary_response = client.get("/api/gateway/v1/security-summary")
        check("security summary", summary_response.status_code, 200)
        operations_status = client.get("/api/operations/v1/status")
        check("operations status", operations_status.status_code, 200)
        check("backup inventory", client.get("/api/operations/v1/backups").status_code, 200)
        check("diagnostic inventory", client.get("/api/operations/v1/diagnostics").status_code, 200)
        openapi_response = client.get("/api/admin/v1/openapi.json")
        check("protected OpenAPI", openapi_response.status_code, 200)
        summary = summary_response.json() if summary_response.status_code == 200 else {}
        operations = operations_status.json() if operations_status.status_code == 200 else {}
        mailer = notification_health.json() if notification_health.status_code == 200 else {}
        registry = registry_response.json() if registry_response.status_code == 200 else {}

    report = {
        "generated_at": int(time.time()),
        "base_url": base_url,
        "checks": checks,
        "security_summary": summary,
        "operations_status": operations,
        "notification_health": mailer,
        "registered_apps": [item.get("app_id") for item in registry.get("items", [])],
        "ok": (
            all(item["ok"] for item in checks)
            and bool(summary.get("database", {}).get("ok"))
            and int(summary.get("database", {}).get("schema_version", 0)) == 4
            and str(operations.get("operations", {}).get("release_version", "")).startswith("5.0.1-")
        ),
    }
    output_dir = Path("uat-results")
    output_dir.mkdir(exist_ok=True)
    output = output_dir / f"stage5-uat-{time.strftime('%Y%m%d-%H%M%S')}.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    for item in checks:
        mark = "PASS" if item["ok"] else "FAIL"
        print(f"[{mark}] {item['name']}: {item['actual']} (expected {item['expected']})")
    print(f"Report: {output}")
    if not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
