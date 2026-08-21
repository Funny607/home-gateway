from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from app.config.schema import AppConfig, CapabilityConfig


TRUST_RANK = {"untrusted": 0, "paired": 1, "trusted": 2, "privileged": 3}
RISK_RANK = {"low": 0, "medium": 1, "medium_high": 2, "high": 3, "critical": 4}
RISK_MIN_TRUST = {
    "low": "paired",
    "medium": "paired",
    "medium_high": "trusted",
    "high": "trusted",
    "critical": "privileged",
}


class PolicyDenied(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PolicyDecision:
    target_app: str
    capabilities: tuple[str, ...]
    grant_type: str
    risk_level: str
    required_trust_level: str
    ttl_seconds: int
    approval_required: bool
    approval_methods: tuple[str, ...]
    one_time: bool
    per_action_approval: bool
    payload_preview_required: bool

    def to_dict(self) -> dict:
        data = asdict(self)
        data["capabilities"] = list(self.capabilities)
        data["approval_methods"] = list(self.approval_methods)
        return data


class PolicyEngine:
    def __init__(self, apps: dict[str, AppConfig]) -> None:
        self.apps = apps

    def capability(self, app_id: str, capability_id: str) -> CapabilityConfig:
        app = self.apps.get(app_id)
        if app is None:
            raise PolicyDenied("unknown_app", "target app is not registered")
        if not app.api.enabled:
            raise PolicyDenied("api_disabled", "target app does not expose external API capabilities")
        for capability in app.capabilities:
            if capability.id == capability_id:
                return capability
        raise PolicyDenied("unknown_capability", f"capability is not declared by {app_id}")

    def evaluate_grant(
        self,
        *,
        app_id: str,
        capability_ids: Iterable[str],
        device_trust_level: str,
        requested_ttl_seconds: int,
        grant_type: str,
    ) -> PolicyDecision:
        if device_trust_level not in TRUST_RANK:
            raise PolicyDenied("invalid_device_trust", "device trust level is invalid")
        if grant_type not in {"session", "long_lived", "one_time"}:
            raise PolicyDenied("invalid_grant_type", "grant_type is invalid")
        normalized = tuple(dict.fromkeys(str(item).strip().lower() for item in capability_ids if str(item).strip()))
        if not normalized:
            raise PolicyDenied("capabilities_required", "at least one capability is required")
        if len(normalized) > 32:
            raise PolicyDenied("too_many_capabilities", "at most 32 capabilities may be requested")

        capabilities = [self.capability(app_id, item) for item in normalized]
        max_risk = max((cap.risk for cap in capabilities), key=lambda risk: RISK_RANK[risk])
        capability_requirements: list[str] = []
        for cap in capabilities:
            risk_floor = RISK_MIN_TRUST[cap.risk]
            allowed = [
                level
                for level in TRUST_RANK
                if TRUST_RANK[level] >= TRUST_RANK[risk_floor]
                and getattr(cap.grant_policy, level).enabled
            ]
            if not allowed:
                raise PolicyDenied("grant_disabled", f"{cap.id} has no enabled trust rule")
            capability_requirements.append(min(allowed, key=lambda level: TRUST_RANK[level]))
        required_trust = max(capability_requirements, key=lambda trust: TRUST_RANK[trust])
        if TRUST_RANK[device_trust_level] < TRUST_RANK[required_trust]:
            raise PolicyDenied(
                "insufficient_trust",
                f"{max_risk} risk requires at least {required_trust} device trust",
            )

        rules = [getattr(cap.grant_policy, device_trust_level) for cap in capabilities]
        if any(not rule.enabled for rule in rules):
            raise PolicyDenied("grant_disabled", "one or more capabilities are disabled for this trust level")
        policy_max_ttl = min(rule.max_ttl_seconds for rule in rules)
        if grant_type == "one_time":
            policy_max_ttl = min(policy_max_ttl, 600)
        if requested_ttl_seconds < 0:
            raise PolicyDenied("invalid_ttl", "requested_ttl_seconds cannot be negative")
        if requested_ttl_seconds == 0:
            requested_ttl_seconds = min(3600, policy_max_ttl)
        ttl = min(requested_ttl_seconds, policy_max_ttl)
        if ttl <= 0:
            raise PolicyDenied("ttl_denied", "grant TTL is not allowed by policy")
        if grant_type == "long_lived":
            if TRUST_RANK[device_trust_level] < TRUST_RANK["trusted"]:
                raise PolicyDenied("insufficient_trust", "long-lived grants require a trusted device")
            if ttl <= 86400:
                raise PolicyDenied("invalid_long_lived_ttl", "long-lived grants must exceed 24 hours")

        approval_required = any(rule.approval_required for rule in rules)
        method_sets = [set(rule.approval_methods) for rule in rules if rule.approval_required]
        approval_methods = sorted(set.intersection(*method_sets)) if method_sets else []
        actions = [cap.action_policy for cap in capabilities if cap.action_policy is not None]
        per_action = any(action.per_action_approval for action in actions)
        one_time = grant_type == "one_time" or any(action.one_time_token for action in actions)
        preview = any(action.require_payload_preview for action in actions)
        if per_action or max_risk == "critical":
            approval_required = True
        if approval_required and not approval_methods:
            raise PolicyDenied("approval_unavailable", "policy requires approval but declares no method")

        return PolicyDecision(
            target_app=app_id,
            capabilities=normalized,
            # A reusable grant may issue a fresh one-time token for each approved
            # action. Do not accidentally consume the parent grant with the token.
            grant_type=grant_type,
            risk_level=max_risk,
            required_trust_level=required_trust,
            ttl_seconds=ttl,
            approval_required=approval_required,
            approval_methods=tuple(approval_methods),
            one_time=one_time,
            per_action_approval=per_action,
            payload_preview_required=preview,
        )

    def revalidate_snapshot(self, snapshot: dict, *, device_trust_level: str) -> PolicyDecision:
        return self.evaluate_grant(
            app_id=str(snapshot.get("target_app", "")),
            capability_ids=list(snapshot.get("capabilities", [])),
            device_trust_level=device_trust_level,
            requested_ttl_seconds=int(snapshot.get("ttl_seconds", 0) or 0),
            grant_type=str(snapshot.get("grant_type", "session")),
        )
