"""core/executor.py — the shared, policy-gated profile executor.

One place that turns a validated {asset_id, profile_id} into a real, executed action:
    resolve profile+asset  ->  policy gate  ->  run the tool via an AgentAdapter

Both the autonomous ClaudeAdapter loop and a plain profile-driven case use this, so
"every action is policy-checked before it runs" holds uniformly — an autonomous agent
gets no shortcut around the gate.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.adapters.base import RunContext
from core.policy import ActionRequest, Policy, PolicyDecision, Verdict
from core.profiles import AssetRegistry, ProfileCatalog, ProfileError
from core.schemas.models import AgentResult, TaskSpec, TraceEventType


@dataclass
class StepResult:
    admitted: bool  # did it pass the gate and run?
    verdict: str  # policy verdict
    rule: str
    detail: str = ""
    output: str = ""  # tool output if it ran
    port_states: list[str] | None = None


def gate(
    catalog: ProfileCatalog,
    assets: AssetRegistry,
    policy: Policy | None,
    asset_id: str,
    profile_id: str,
) -> tuple[PolicyDecision, dict | None]:
    """Resolve + policy-check a proposed profile. Returns (decision, resolved|None).
    Fail-closed: unknown profile/asset -> deny."""
    try:
        profile = catalog.get(profile_id)
        asset = assets.resolve(asset_id)
    except ProfileError as e:
        return PolicyDecision(Verdict.DENY, "unknown_profile_or_asset", str(e)), None

    # merge params: profile template + asset's ports + asset's target-specific
    # overrides (tool_args). This lets per-target quirks (e.g. gobuster's
    # --exclude-length, which differs per site) live on the ASSET, so the same profile
    # works across targets. Profile stays the reusable capability; asset carries the
    # target's specifics. asset tool_args win on key conflicts.
    merged = dict(profile.parameters, ports=asset.get("ports", ""))
    merged.update(asset.get("tool_args", {}) or {})
    resolved = {
        "tool": profile.tool_id,
        "target": asset.get("target", ""),
        "params": merged,
        "profile": profile,
    }
    if policy is None:
        return PolicyDecision(Verdict.ALLOW, "no_policy"), resolved

    # risk decided by the profile, not the tool name (same rule as the controller)
    prof_policy = Policy(
        default=policy.default,
        allowed_tools=policy.allowed_tools,
        allowed_targets=policy.allowed_targets,
        active_tools=[],
        max_cost_usd=policy.max_cost_usd,
        deny_flags=policy.deny_flags,
    )
    req = ActionRequest(
        tool=resolved["tool"],
        target=resolved["target"],
        params=resolved["params"],
        target_source="case",
    )
    decision = prof_policy.check(req)
    if decision.verdict is Verdict.ALLOW and profile.approval_required:
        decision = PolicyDecision(
            Verdict.REQUIRE_APPROVAL,
            "profile_needs_approval",
            f"profile '{profile_id}' (risk={profile.risk_tier.value})",
        )
    return decision, resolved


def execute_profile(
    executor_adapter, catalog, assets, policy, asset_id, profile_id, task: TaskSpec, ctx: RunContext
) -> StepResult:
    """Gate a proposed profile, and if allowed, execute it via executor_adapter
    (e.g. HexStrikeAdapter). Emits policy_event; only runs on ALLOW."""
    decision, resolved = gate(catalog, assets, policy, asset_id, profile_id)
    ctx.trace.emit(
        TraceEventType.POLICY_EVENT,
        rule=decision.rule,
        verdict=decision.verdict.value,
        text=f"{asset_id} / {profile_id}" + (f" — {decision.detail}" if decision.detail else ""),
    )
    if decision.verdict is not Verdict.ALLOW:
        return StepResult(
            admitted=False,
            verdict=decision.verdict.value,
            rule=decision.rule,
            detail=decision.detail,
        )

    # build a concrete sub-task the executor adapter understands, and run it.
    # inject the profile's fixed tool_id so the adapter dispatches to the right tool
    # (nmap / gobuster / nuclei / ...). The model never sets this — it comes from the
    # profile template, so tool choice stays a capability decision, not a model input.
    sub_params = dict(resolved["params"], tool=resolved["tool"])
    sub = task.model_copy(
        update={
            "target": resolved["target"],
            "agent_params": sub_params,
        }
    )
    result: AgentResult = executor_adapter.run(sub, ctx)
    return StepResult(
        admitted=True, verdict="allow", rule=decision.rule, output=result.final_output
    )
