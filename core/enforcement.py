"""Canonical profile resolution and authoritative real-execution admission."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any

from core.policy import ActionRequest, Policy, PolicyDecision
from core.profiles import AssetRegistry, Profile, ProfileCatalog, ProfileError

_PERMIT_SEAL = object()
SERVICE_DISCOVERY_PORTS = "22,80,139,443,445,3389"
_SHELL_META = re.compile(r"[;&|`$<>\n\r]")
_ADDITIONAL_ARGS = {
    "gobuster": re.compile(r"^--exclude-length [0-9]+$"),
    "nc": re.compile(r"^-z -v -w 3$"),
    "arp-scan": re.compile(r"^--localnet$"),
}
_IMMUTABLE_TOOL_DEFAULTS: dict[str, dict[str, Any]] = {
    "httpx": {"ports": "80"},
    "ssh-posture": {"ports": "22"},
    "smb-posture": {"ports": "139,445"},
    "smb-anonymous-access": {"ports": "445"},
    "smb-ms17-010-check": {"ports": "445"},
    "smbmap": {"ports": "445"},
    "rpcclient": {"ports": "445"},
    "netexec": {"ports": "445"},
    "nbtscan": {"ports": "137"},
    "rdp-posture": {"ports": "3389"},
}
_IMMUTABLE_PROFILE_ARGUMENTS: dict[str, dict[str, Any]] = {
    "agent-service-discovery-low": {
        "scan_type": "-sV",
        "ports": SERVICE_DISCOVERY_PORTS,
    }
}


@dataclass(frozen=True)
class EffectiveAction:
    asset_id: str
    profile_id: str
    tool: str
    target: str
    params: Mapping[str, Any]
    profile: Profile
    asset_type: str
    max_ports: int
    max_tool_calls: int
    max_duration_seconds: int
    max_requests_per_second: int
    evidence_required: tuple[str, ...]
    approval_required: bool

    @property
    def params_dict(self) -> dict[str, Any]:
        return dict(self.params)

    @property
    def fingerprint(self) -> str:
        document = {
            "asset_id": self.asset_id,
            "profile_id": self.profile_id,
            "tool": self.tool,
            "target": self.target,
            "params": self.params_dict,
            "asset_type": self.asset_type,
            "limits": {
                "max_ports": self.max_ports,
                "max_tool_calls": self.max_tool_calls,
                "max_duration_seconds": self.max_duration_seconds,
                "max_requests_per_second": self.max_requests_per_second,
            },
            "evidence_required": self.evidence_required,
            "approval_required": self.approval_required,
        }
        return hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True)
class ExecutionPermit:
    run_id: str
    action_id: str
    asset_id: str
    profile_id: str
    tool: str
    target: str
    params_digest: str
    policy_rule: str
    action_fingerprint: str
    max_duration_seconds: int
    max_requests_per_second: int
    _seal: object

    def valid_for(self, task, run_id: str) -> bool:
        params = dict(task.agent_params)
        tool = params.pop("tool", "nmap")
        digest = hashlib.sha256(
            json.dumps(params, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return (
            self._seal is _PERMIT_SEAL
            and self.run_id == run_id
            and self.tool == tool
            and self.target == task.target
            and self.params_digest == digest
        )


def canonical_profile_arguments(profile: Profile, asset: dict[str, Any]) -> Mapping[str, Any]:
    """Merge immutable profile defaults then tool-scoped asset configuration."""
    params = dict(_IMMUTABLE_TOOL_DEFAULTS.get(profile.tool_id, {}))
    params.update(profile.parameters)
    if "ports" not in params:
        params["ports"] = asset.get("ports", "")
    tool_args = asset.get("tool_args", {}) or {}
    if not isinstance(tool_args, dict):
        raise ProfileError("asset tool_args must be a mapping")
    scoped = tool_args.get(profile.tool_id, {})
    if scoped:
        if not isinstance(scoped, dict):
            raise ProfileError("tool-specific arguments must be structured")
        params.update(scoped)
    elif (
        profile.tool_id == "gobuster"
        and tool_args
        and all(not isinstance(value, dict) for value in tool_args.values())
    ):
        params.update(tool_args)
    elif any(not isinstance(value, dict) for value in tool_args.values()):
        raise ProfileError("unscoped asset tool arguments are not supported")

    # Profile-bound execution arguments override every asset value. This first
    # live slice has one reviewed port set; neither assets nor callers can widen it.
    params.update(_IMMUTABLE_PROFILE_ARGUMENTS.get(profile.profile_id, {}))

    for forbidden in profile.forbidden_fields:
        if forbidden in params:
            raise ProfileError(f"forbidden profile argument: {forbidden}")
    for key, value in params.items():
        if isinstance(value, str) and _SHELL_META.search(value):
            raise ProfileError(f"shell-like profile argument rejected: {key}")
    if "additional_args" in params:
        value = str(params["additional_args"]).strip()
        matcher = _ADDITIONAL_ARGS.get(profile.tool_id)
        if value and (matcher is None or matcher.fullmatch(value) is None):
            raise ProfileError("unsupported structured additional arguments")
        params["additional_args"] = value
    return MappingProxyType(params)


def _port_count(value: Any) -> int:
    if value in ("", None):
        return 0
    ports = [part.strip() for part in str(value).split(",") if part.strip()]
    for port in ports:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ProfileError("invalid structured port list")
    return len(ports)


def resolve_effective_action(
    catalog: ProfileCatalog,
    assets: AssetRegistry,
    asset_id: str,
    profile_id: str,
) -> EffectiveAction:
    profile = catalog.get(profile_id)
    asset = dict(assets.resolve(asset_id))
    asset_type = asset.get("asset_type")
    if not isinstance(asset_type, str):
        raise ProfileError("asset type required")
    if profile.allowed_asset_types and not (
        asset_type in profile.allowed_asset_types or "any" in profile.allowed_asset_types
    ):
        raise ProfileError("asset type not allowed by profile")
    if profile.internet_egress:
        raise ProfileError("internet-egress profiles are unsupported")
    if not profile.tool_id or profile.tool_id == "t3-controlled-access":
        raise ProfileError("profile requires a dedicated execution route")
    target = asset.get("target")
    if not isinstance(target, str) or not target:
        raise ProfileError("registered target required")
    params = canonical_profile_arguments(profile, asset)
    if _port_count(params.get("ports")) > profile.limits.max_ports:
        raise ProfileError("profile max_ports exceeded")
    if (
        profile.limits.max_tool_calls != 1
        or profile.limits.max_duration_seconds <= 0
        or profile.limits.max_requests_per_second <= 0
        or profile.limits.max_retries != 0
    ):
        raise ProfileError("unsupported or unsafe profile limits")
    supported_evidence = {
        "tool_invocation_log",
        "target_access_log",
        "network_flow_log",
    }
    if not set(profile.evidence_required) <= supported_evidence:
        raise ProfileError("unsupported profile evidence requirement")
    return EffectiveAction(
        asset_id,
        profile_id,
        profile.tool_id,
        target,
        params,
        profile,
        asset_type,
        profile.limits.max_ports,
        profile.limits.max_tool_calls,
        profile.limits.max_duration_seconds,
        profile.limits.max_requests_per_second,
        tuple(profile.evidence_required),
        profile.approval_required,
    )


def evaluate_effective_action(
    action: EffectiveAction,
    policy: Policy,
    *,
    credential_ref: str = "",
    justification: str = "",
) -> PolicyDecision:
    return policy.check(
        ActionRequest(
            tool=action.tool,
            target=action.target,
            params=action.params_dict,
            target_source="case",
            t3_credential_ref=credential_ref,
            t3_written_justification=justification,
        )
    )


def authorize_execution(
    action: EffectiveAction,
    *,
    run_id: str,
    policy_rule: str,
) -> ExecutionPermit:
    params_digest = hashlib.sha256(
        json.dumps(action.params_dict, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    action_id = hashlib.sha256(f"{run_id}:{action.fingerprint}".encode()).hexdigest()[:24]
    return ExecutionPermit(
        run_id,
        action_id,
        action.asset_id,
        action.profile_id,
        action.tool,
        action.target,
        params_digest,
        policy_rule,
        action.fingerprint,
        action.max_duration_seconds,
        action.max_requests_per_second,
        _PERMIT_SEAL,
    )


def effective_approval_fingerprint(action: EffectiveAction) -> str:
    document = {
        "effective_action": action.fingerprint,
        "profile": asdict(action.profile),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
