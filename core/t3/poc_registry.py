"""Canonical registry for the narrow unified Windows SSH research PoC."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

ASSET_ID = "asset:winsrv2025-01"
REACHABILITY_ACTION = "t3a.ssh22_reachability.v1"
IDENTITY_ACTION = "windows.ssh.readonly_identity.v1"


@dataclass(frozen=True)
class ActionDefinition:
    action_id: str
    tool: str
    risk_tier: Literal["low", "medium"]
    maximum_tool_calls: int
    maximum_duration_seconds: int
    approval_delay_seconds: int
    justification_required: bool
    prerequisites: tuple[str, ...] = ()


_ACTIONS = (
    ActionDefinition(REACHABILITY_ACTION, "tcp22-reachability", "low", 1, 5, 0, False),
    ActionDefinition(
        IDENTITY_ACTION,
        "windows-ssh-readonly-identity",
        "medium",
        3,
        45,
        0,
        False,
        (REACHABILITY_ACTION,),
    ),
)

ACTIONS = MappingProxyType({item.action_id: item for item in _ACTIONS})


def action(action_id: str) -> ActionDefinition:
    try:
        return ACTIONS[action_id]
    except KeyError as exc:
        raise ValueError("unknown_action") from exc
