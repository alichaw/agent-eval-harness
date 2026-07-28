"""core/profiles.py — capability-based execution profiles.

The core idea (this is the security property): the model may only propose
    {asset_id, profile_id}
It may NOT propose a tool, target, flags, or command. The Harness resolves the
profile into the real (tool, target, params) itself. A profile is a fixed template
the model cannot modify — so raw_command / custom_flags / arbitrary-target attacks
are impossible by construction, not by after-the-fact checking.

Each profile also declares the EVIDENCE its execution must produce. That field is
the specification the W4 Action Verifier checks against: "the agent claims it ran
profile X — are profile X's required evidence artifacts actually present?"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml


class InteractionMode(str, Enum):
    OFFLINE = "offline"  # never touches the target or any external service
    PASSIVE = "passive"  # no packets to target; uses external/collected data
    ACTIVE = "active"  # sends packets/requests directly to the target


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PROHIBITED = "prohibited"


@dataclass
class ProfileLimits:
    max_targets: int = 1
    max_ports: int = 20
    max_tool_calls: int = 1
    max_duration_seconds: int = 60
    max_requests_per_second: int = 5
    max_retries: int = 0


@dataclass
class Profile:
    profile_id: str
    description: str
    interaction_mode: InteractionMode
    risk_tier: RiskTier
    allowed_asset_types: list[str] = field(default_factory=list)
    # executor: the FIXED tool + parameter template the model cannot change
    tool_id: str = ""
    parameters: dict = field(default_factory=dict)
    limits: ProfileLimits = field(default_factory=ProfileLimits)
    internet_egress: bool = False
    approval_required: bool = False
    # evidence the execution MUST produce — the W4 verifier's checklist
    evidence_required: list[str] = field(default_factory=list)
    forbidden_fields: list[str] = field(
        default_factory=lambda: [
            "raw_command",
            "custom_flags",
            "payload",
            "callback_url",
            "arbitrary_target",
        ]
    )


class ProfileError(Exception):
    """Unknown/invalid profile — callers must treat as deny (fail-closed)."""


class ProfileCatalog:
    def __init__(self, profiles: dict[str, Profile]):
        self._profiles = profiles

    @classmethod
    def from_yaml(cls, path: str | Path) -> ProfileCatalog:
        data = yaml.safe_load(Path(path).read_text()) or {}
        out: dict[str, Profile] = {}
        for pid, p in (data.get("profiles") or {}).items():
            lim = p.get("limits", {})
            out[pid] = Profile(
                profile_id=pid,
                description=p.get("description", ""),
                interaction_mode=InteractionMode(p.get("interaction_mode", "offline")),
                risk_tier=RiskTier(p.get("risk_tier", "low")),
                allowed_asset_types=p.get("allowed_asset_types", []),
                tool_id=p.get("tool_id", ""),
                parameters=p.get("parameters", {}),
                limits=ProfileLimits(**lim) if lim else ProfileLimits(),
                internet_egress=p.get("internet_egress", False),
                approval_required=p.get("approval_required", False),
                evidence_required=p.get("evidence_required", []),
                forbidden_fields=p.get(
                    "forbidden_fields",
                    ["raw_command", "custom_flags", "payload", "callback_url", "arbitrary_target"],
                ),
            )
        return cls(out)

    def get(self, profile_id: str) -> Profile:
        if profile_id not in self._profiles:
            raise ProfileError(f"unknown profile_id '{profile_id}'")  # fail-closed
        return self._profiles[profile_id]

    def __contains__(self, profile_id: str) -> bool:
        return profile_id in self._profiles


@dataclass
class AssetRegistry:
    """asset_id -> real target. The model never sees or sets the real target;
    it only names an asset. (Signed scope registry is a stage-2 upgrade.)"""

    _assets: dict[str, dict]

    @classmethod
    def from_yaml(cls, path: str | Path) -> AssetRegistry:
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(data.get("assets", {}))

    def resolve(self, asset_id: str) -> dict:
        if asset_id not in self._assets:
            raise ProfileError(f"unknown asset_id '{asset_id}'")  # fail-closed
        return self._assets[asset_id]

    def items(self):
        """Iterate over registered assets without exposing registry internals."""
        return self._assets.items()
