"""core/policy.py — production-grade, agent-agnostic policy gate.

Upgrades over a plain allowlist:
  * THREE-STATE decision: allow / deny / require_approval (not just bool).
  * TAINT tracking: a target that originated from tool output (i.e. possibly
    injected) is untrusted -> deny. Only targets authorised in the case are trusted.
    This is the core defense against indirect prompt injection.
  * FAIL-CLOSED: any missing field / evaluation error -> deny, never allow.
  * allowlist + default-deny; deny_flags/raw_command/custom_flags as extra layers.

The engine knows nothing about HexStrike/email/coding agents — swap the policy YAML.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"   # architecture in place; approval flow lands in W5


@dataclass
class PolicyDecision:
    verdict: Verdict
    rule: str            # machine-readable reason, e.g. "target_not_allowed"
    detail: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    @property
    def denied(self) -> bool:
        return self.verdict is Verdict.DENY

    @property
    def needs_approval(self) -> bool:
        return self.verdict is Verdict.REQUIRE_APPROVAL


@dataclass
class ActionRequest:
    """One action to be checked. `target_source` is what enables taint tracking:
    'case' = authorised in the test case (trusted); 'tool_output' = parsed from a
    tool's output at runtime (untrusted, possibly injected)."""
    tool: str
    target: str = ""
    params: dict = field(default_factory=dict)
    target_source: str = "case"        # "case" (trusted) | "tool_output" (tainted)
    cost_so_far: float = 0.0


@dataclass
class Policy:
    default: str = "deny"
    allowed_tools: list[str] = field(default_factory=list)
    allowed_targets: list[str] = field(default_factory=list)
    active_tools: list[str] = field(default_factory=list)   # tools that need approval
    max_cost_usd: float = float("inf")
    deny_flags: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        # FAIL-CLOSED: a broken policy file must not silently allow everything.
        try:
            data = yaml.safe_load(Path(path).read_text()) or {}
        except (OSError, yaml.YAMLError) as e:
            raise PolicyLoadError(f"cannot load policy: {e}") from e
        return cls(
            default=data.get("default", "deny"),
            allowed_tools=data.get("allowed_tools", []),
            allowed_targets=data.get("allowed_targets", []),
            active_tools=data.get("active_tools", []),
            max_cost_usd=data.get("max_cost_usd", float("inf")),
            deny_flags=data.get("deny_flags", {}),
        )

    def _target_allowed(self, target: str) -> bool:
        for allowed in self.allowed_targets:
            if target == allowed:
                return True
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(allowed, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def check(self, req: ActionRequest) -> PolicyDecision:
        """Evaluate one action. FAIL-CLOSED: any unexpected error -> DENY."""
        try:
            return self._check(req)
        except Exception as e:  # noqa: BLE001 — deliberate: unknown error must deny
            return PolicyDecision(Verdict.DENY, "evaluation_error", str(e))

    def _check(self, req: ActionRequest) -> PolicyDecision:
        # 0. taint: a target that came from tool output is untrusted (injection risk)
        if req.target and req.target_source != "case":
            return PolicyDecision(Verdict.DENY, "tainted_target",
                                  f"target '{req.target}' came from {req.target_source}")

        # 1. raw_command / custom_flags: bypass vectors -> deny outright
        if "raw_command" in req.params:
            return PolicyDecision(Verdict.DENY, "raw_command_forbidden",
                                  "raw_command bypasses the tool allowlist")
        if "custom_flags" in req.params:
            return PolicyDecision(Verdict.DENY, "custom_flags_forbidden",
                                  "custom_flags are not permitted")

        # 2. tool allowlist (default-deny)
        if req.tool not in self.allowed_tools:
            return PolicyDecision(Verdict.DENY, "tool_not_allowed",
                                  f"'{req.tool}' not in allowed_tools")

        # 3. target allowlist
        if req.target and not self._target_allowed(req.target):
            return PolicyDecision(Verdict.DENY, "target_not_allowed",
                                  f"'{req.target}' not in allowed_targets")

        # 4. cost ceiling
        if req.cost_so_far > self.max_cost_usd:
            return PolicyDecision(Verdict.DENY, "cost_exceeded",
                                  f"{req.cost_so_far} > {self.max_cost_usd}")

        # 5. deny_flags (extra blacklist layer, only on top of the allowlist)
        for bad in self.deny_flags.get(req.tool, []):
            if bad.lower() in f"{req.params}".lower():
                return PolicyDecision(Verdict.DENY, "denied_flag",
                                      f"'{bad}' present for '{req.tool}'")

        # 6. active tools need approval (architecture ready; approval flow = W5)
        if req.tool in self.active_tools:
            return PolicyDecision(Verdict.REQUIRE_APPROVAL, "active_scan_needs_approval",
                                  f"'{req.tool}' is an active scan")

        return PolicyDecision(Verdict.ALLOW, "allowed")


class PolicyLoadError(Exception):
    """Raised when a policy file cannot be loaded — callers should treat as deny."""