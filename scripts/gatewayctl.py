#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sdk.gateway_client import (
    GatewayClient,
    GatewayClientError,
    load_credentials,
    save_credentials,
)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="WebUI Home Gateway Stage 5 client")
    root.add_argument("--url", default="https://dev.lu607.com")
    root.add_argument("--credentials", type=Path, default=Path("~/.config/home-gateway/device.json"))
    commands = root.add_subparsers(dest="command", required=True)
    register = commands.add_parser("register")
    register.add_argument("--name", required=True)
    register.add_argument("--type", default="cli")
    register.add_argument("--source-id", default="")
    commands.add_parser("registration-status")
    grant = commands.add_parser("grant")
    grant.add_argument("--app", required=True)
    grant.add_argument("--capability", action="append", required=True)
    grant.add_argument("--ttl", type=int, default=3600)
    grant.add_argument("--reason", default="gatewayctl request")
    token = commands.add_parser("token")
    token.add_argument("--grant-id", required=True)
    token.add_argument("--ttl", type=int, default=900)
    token.add_argument("--name", default="gatewayctl")
    token.add_argument("--action-approval-id", default="")
    action = commands.add_parser("action-request")
    action.add_argument("--grant-id", required=True)
    action.add_argument("--capability", required=True)
    action.add_argument("--method", required=True)
    action.add_argument("--path", required=True)
    action.add_argument("--body-file", type=Path)
    action.add_argument("--preview", required=True)
    action.add_argument("--reason", default="gatewayctl high-risk action")
    status = commands.add_parser("action-status")
    status.add_argument("approval_id")
    approve = commands.add_parser("totp-approve")
    approve.add_argument("approval_id")
    approve.add_argument("--request-code", required=True)
    approve.add_argument("--totp", required=True)
    call = commands.add_parser("call")
    call.add_argument("--app", required=True)
    call.add_argument("--path", required=True)
    call.add_argument("--method", default="GET")
    call.add_argument("--json", default="")
    lease = commands.add_parser("lease-create")
    lease.add_argument("--capability", required=True)
    lease.add_argument("--seconds", type=int, default=300)
    heartbeat = commands.add_parser("lease-heartbeat")
    heartbeat.add_argument("lease_id")
    release = commands.add_parser("lease-release")
    release.add_argument("lease_id")
    return root


def public(data: dict) -> dict:
    result = dict(data)
    for key in ("device_secret", "access_token", "token"):
        if key in result:
            result[key] = "[saved to credential file]"
    return result


def main() -> int:
    args = parser().parse_args()
    client = GatewayClient(args.url)
    credential_path = args.credentials.expanduser()
    credentials = {} if args.command == "register" else load_credentials(credential_path)
    if args.command == "register":
        result = client.register_device(name=args.name, device_type=args.type, source_id=args.source_id)
        credentials.update(
            {
                "base_url": args.url,
                "device_id": result["device_id"],
                "device_secret": result["device_secret"],
                "registration_approval_id": result["approval_id"],
            }
        )
        save_credentials(credential_path, credentials)
    elif args.command == "registration-status":
        result = client.registration_status(
            approval_id=credentials["registration_approval_id"],
            device_id=credentials["device_id"],
            secret=credentials["device_secret"],
        )
    elif args.command == "grant":
        result = client.request_grant(
            device_id=credentials["device_id"], secret=credentials["device_secret"],
            app_id=args.app, capabilities=args.capability, ttl_seconds=args.ttl, reason=args.reason,
        )
    elif args.command == "token":
        result = client.issue_token(
            device_id=credentials["device_id"], secret=credentials["device_secret"],
            grant_id=args.grant_id, ttl_seconds=args.ttl, client_name=args.name,
            action_approval_id=args.action_approval_id,
        )
        credentials["access_token"] = result["access_token"]
        credentials["token_id"] = result.get("token", {}).get("token_id", "")
        save_credentials(credential_path, credentials)
    elif args.command == "action-request":
        body = args.body_file.read_bytes() if args.body_file else b""
        result = client.request_action(
            device_id=credentials["device_id"], secret=credentials["device_secret"],
            grant_id=args.grant_id, capability=args.capability, method=args.method,
            path=args.path, body=body, payload_preview=args.preview, reason=args.reason,
        )
        credentials["action_approval_id"] = result.get("approval", {}).get("approval_id", "")
        save_credentials(credential_path, credentials)
    elif args.command == "action-status":
        result = client.action_status(
            approval_id=args.approval_id, device_id=credentials["device_id"],
            secret=credentials["device_secret"],
        )
    elif args.command == "totp-approve":
        result = client.approve_with_totp(
            approval_id=args.approval_id, device_id=credentials["device_id"],
            secret=credentials["device_secret"], request_code=args.request_code,
            totp_code=args.totp,
        )
    elif args.command == "call":
        payload = json.loads(args.json) if args.json else None
        result = client.call_app(
            app_id=args.app, path=args.path, method=args.method,
            payload=payload, token=credentials["access_token"],
        )
    elif args.command == "lease-create":
        result = client.create_lease(
            capability=args.capability, seconds=args.seconds, token=credentials["access_token"]
        )
    elif args.command == "lease-heartbeat":
        result = client.heartbeat_lease(lease_id=args.lease_id, token=credentials["access_token"])
    else:
        result = client.release_lease(lease_id=args.lease_id, token=credentials["access_token"])
    print(json.dumps(public(result), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GatewayClientError, KeyError, ValueError, PermissionError) as exc:
        print(f"gatewayctl: {exc}", file=sys.stderr)
        raise SystemExit(2)
