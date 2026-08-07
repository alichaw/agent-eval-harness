from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from core.adapters.hexstrike import HexStrikeAdapter
from core.profiles import ProfileCatalog, ProfileError
from core.t3.impact import ACTION_ID as T3C_ACTION

T3_ACTIONS = {"t3-authorized-access-bounded", "windows-host-enumeration-readonly", T3C_ACTION}
EVIDENCE_TYPES = {
    "successful_sealed_t3a_evidence",
    "successful_sealed_t3b_evidence",
    "valid_t3_authorization",
}


class Capability(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability_id: str
    route: Literal["hexstrike", "t3_controller"]
    tool: str | None = None
    profile_id: str | None = None
    canonical_action: str | None = None
    phase: Literal["t1", "t2", "t3a", "t3b", "t3c"]
    risk_tier: Literal["low", "medium", "high"]
    approval_required: bool
    prerequisites: tuple[str, ...] = ()
    agent_parameters: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_route(self):
        if (
            self.route == "hexstrike"
            and not (self.tool and self.profile_id)
            or (self.route == "t3_controller" and not self.canonical_action)
        ):
            raise ValueError("route has no real executor binding")
        if self.phase == "t3c" and not self.approval_required:
            raise ValueError("T3-C capabilities require approval")
        if self.phase != "t3c" and self.approval_required:
            raise ValueError("only T3-C capabilities may require approval")
        if self.agent_parameters:
            raise ValueError("agent-controlled parameters are forbidden")
        return self


class CatalogError(ValueError):
    pass


class CapabilityCatalog:
    def __init__(self, entries: dict[str, Capability]):
        self.entries = entries

    @classmethod
    def from_yaml(cls, path: str | Path, profiles: ProfileCatalog):
        try:
            pairs = yaml.safe_load(Path(path).read_text()) or {}
            raw = pairs.get("capabilities", {})
            if not isinstance(raw, dict):
                raise CatalogError("capabilities must be a mapping")
            entries = {}
            for capability_id, value in raw.items():
                if capability_id in entries:
                    raise CatalogError("duplicate capability ID")
                item = Capability.model_validate({"capability_id": capability_id, **value})
                if item.route == "hexstrike":
                    profile = profiles.get(item.profile_id or "")
                    if item.tool not in HexStrikeAdapter.TOOL_SPECS or profile.tool_id != item.tool:
                        raise CatalogError(f"missing real executor for {capability_id}")
                elif item.canonical_action not in T3_ACTIONS:
                    raise CatalogError(f"unregistered T3 action for {capability_id}")
                unknown = set(item.prerequisites) - EVIDENCE_TYPES
                if unknown:
                    raise CatalogError(f"unknown prerequisite: {sorted(unknown)}")
                entries[capability_id] = item
            return cls(entries)
        except (OSError, yaml.YAMLError, ValidationError, ValueError, ProfileError) as exc:
            if isinstance(exc, CatalogError):
                raise
            raise CatalogError(str(exc)) from exc

    def get(self, capability_id: str) -> Capability:
        try:
            return self.entries[capability_id]
        except KeyError as exc:
            raise CatalogError(f"unknown capability '{capability_id}'") from exc
