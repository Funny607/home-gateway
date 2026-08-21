from __future__ import annotations

import unittest

from pydantic import ValidationError

from app.api_v1.capabilities import find_capability_for_request
from app.config.schema import AppConfig, GatewayConfig
from app.config.loader import validate_app_collection
from app.security.policy import PolicyDenied, PolicyEngine


def app_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "app_id": "demo-app",
            "display_name": "Demo",
            "mount_path": "/apps/demo",
            "workdir": "/tmp",
            "command": ["python3", "--host", "{host}", "--port", "{port}"],
            "api": {"enabled": True},
            "capabilities": [
                {
                    "id": "demo-app.items.read",
                    "title": "Read items",
                    "risk": "low",
                    "routes": [{"method": "GET", "path_prefix": "/api/items"}],
                },
                {
                    "id": "demo-app.items.delete",
                    "title": "Delete one item",
                    "risk": "high",
                    "routes": [{"method": "DELETE", "path_regex": r"/api/items/[0-9]+"}],
                    "action_policy": {
                        "per_action_approval": True,
                        "require_payload_preview": False,
                        "one_time_token": True,
                    },
                },
            ],
            "dashboard": {"visible_roles": ["admin"], "allow_proxy_roles": ["admin"]},
            "actions": {"show_stop": False},
        }
    )


class ConfigPolicyTests(unittest.TestCase):
    def test_gateway_and_app_must_bind_loopback(self) -> None:
        with self.assertRaises(ValidationError):
            GatewayConfig(listen_host="0.0.0.0")
        data = app_config().model_dump()
        data["listen_host"] = "192.168.1.10"
        with self.assertRaises(ValidationError):
            AppConfig.model_validate(data)

    def test_tunnel_alert_delay_must_be_positive_and_defaults_to_one_hour(self) -> None:
        self.assertEqual(GatewayConfig().tunnel.alert_after_seconds, 3600)
        with self.assertRaises(ValidationError):
            GatewayConfig.model_validate({"tunnel": {"alert_after_seconds": 0}})

    def test_unknown_config_key_is_rejected(self) -> None:
        data = app_config().model_dump()
        data["dashbord"] = {}
        with self.assertRaises(ValidationError):
            AppConfig.model_validate(data)

    def test_reserved_mount_and_invalid_regex_are_rejected(self) -> None:
        data = app_config().model_dump()
        data["mount_path"] = "/api/escape"
        with self.assertRaises(ValidationError):
            AppConfig.model_validate(data)
        data = app_config().model_dump()
        data["capabilities"][0]["routes"] = [{"method": "GET", "path_regex": "["}]
        with self.assertRaises(ValidationError):
            AppConfig.model_validate(data)

    def test_stage3_payload_binding_requires_per_action_and_one_time(self) -> None:
        data = app_config().model_dump()
        data["capabilities"][1]["action_policy"]["require_payload_preview"] = True
        data["capabilities"][1]["action_policy"]["per_action_approval"] = False
        with self.assertRaises(ValidationError):
            AppConfig.model_validate(data)
        data["capabilities"][1]["action_policy"].update({
            "per_action_approval": True, "one_time_token": True,
        })
        AppConfig.model_validate(data)

    def test_adapter_bodies_and_mail_headers_cannot_embed_secrets_or_newlines(self) -> None:
        data = app_config().model_dump()
        data["capabilities"].append(
            {
                "id": "demo-app.mode.lease",
                "title": "Lease mode",
                "risk": "medium_high",
                "gateway_managed": True,
                "lease_policy": {
                    "resource_key": "demo-app.mode",
                    "acquire": {"path": "/active", "json_body": {"access_token": "bad"}},
                    "release": {"path": "/normal"},
                    "probe": {
                        "path": "/status", "json_path": "mode",
                        "active_values": ["active"], "released_values": ["normal"],
                    },
                },
            }
        )
        with self.assertRaises(ValidationError):
            AppConfig.model_validate(data)
        with self.assertRaises(ValidationError):
            GatewayConfig.model_validate(
                {"notifications": {"subject_prefix": "[Gateway]\nBcc: attacker@example.com"}}
            )

    def test_prefix_and_regex_matching_have_boundaries(self) -> None:
        app = app_config()
        self.assertIsNotNone(find_capability_for_request(app, "GET", "/api/items/7"))
        self.assertIsNone(find_capability_for_request(app, "GET", "/api/itemshop"))
        self.assertIsNotNone(find_capability_for_request(app, "DELETE", "/api/items/7"))
        self.assertIsNone(find_capability_for_request(app, "DELETE", "/api/items/7/extra"))

    def test_policy_derives_risk_and_trust_instead_of_accepting_client_values(self) -> None:
        app = app_config()
        engine = PolicyEngine({app.app_id: app})
        with self.assertRaises(PolicyDenied) as caught:
            engine.evaluate_grant(
                app_id=app.app_id,
                capability_ids=["demo-app.items.delete"],
                device_trust_level="paired",
                requested_ttl_seconds=999999,
                grant_type="session",
            )
        self.assertEqual(caught.exception.code, "insufficient_trust")
        decision = engine.evaluate_grant(
            app_id=app.app_id,
            capability_ids=["demo-app.items.delete"],
            device_trust_level="trusted",
            requested_ttl_seconds=999999,
            grant_type="session",
        )
        self.assertEqual(decision.risk_level, "high")
        self.assertEqual(decision.required_trust_level, "trusted")
        self.assertTrue(decision.one_time)
        self.assertTrue(decision.approval_required)
        self.assertLessEqual(decision.ttl_seconds, 2592000)

    def test_dependency_cycles_are_rejected_across_manifests(self) -> None:
        one_data = app_config().model_dump()
        one_data["lifecycle"]["dependencies"] = ["other-app"]
        two_data = app_config().model_dump()
        two_data.update(
            {
                "app_id": "other-app",
                "display_name": "Other",
                "mount_path": "/apps/other",
            }
        )
        two_data["lifecycle"]["dependencies"] = ["demo-app"]
        for capability in two_data["capabilities"]:
            capability["id"] = capability["id"].replace("demo-app.", "other-app.")
        with self.assertRaisesRegex(ValueError, "dependency cycle"):
            validate_app_collection(
                {
                    "demo-app": AppConfig.model_validate(one_data),
                    "other-app": AppConfig.model_validate(two_data),
                }
            )


if __name__ == "__main__":
    unittest.main()
