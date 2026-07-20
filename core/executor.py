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
from core.safety import ApprovalError, ExecutionState, profile_fingerprint
from core.schemas.models import AgentResult, TaskSpec, TraceEventType


@dataclass
class StepResult:
    admitted: bool  # did it pass the gate and run?
    verdict: str  # policy verdict
    rule: str
    detail: str = ""
    output: str = ""  # tool output if it ran
    port_states: list[str] | None = None
    state: ExecutionState = ExecutionState.PROPOSED


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
        denied_targets=policy.denied_targets,
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


def _emit_state(ctx: RunContext, state: ExecutionState, detail: str = "") -> None:
    ctx.trace.emit(
        TraceEventType.EXECUTION_STATE,
        state=state.value,
        text=detail or state.value,
    )


def execute_profile(
    executor_adapter, catalog, assets, policy, asset_id, profile_id, task: TaskSpec, ctx: RunContext
) -> StepResult:
    """Gate, approve, and execute one profile with fail-closed state transitions."""
    _emit_state(ctx, ExecutionState.PROPOSED, f"{asset_id} / {profile_id}")

    if ctx.kill_switch is not None and ctx.kill_switch.engaged():
        _emit_state(ctx, ExecutionState.KILLED, "kill switch engaged before policy gate")
        return StepResult(
            admitted=False,
            verdict="deny",
            rule="kill_switch_engaged",
            state=ExecutionState.KILLED,
        )

    decision, resolved = gate(catalog, assets, policy, asset_id, profile_id)
    ctx.trace.emit(
        TraceEventType.POLICY_EVENT,
        rule=decision.rule,
        verdict=decision.verdict.value,
        text=f"{asset_id} / {profile_id}" + (f" — {decision.detail}" if decision.detail else ""),
    )

    if decision.verdict is Verdict.REQUIRE_APPROVAL:
        if resolved is None or ctx.approval_authority is None or not ctx.approval_token:
            _emit_state(ctx, ExecutionState.BLOCKED, "approval token required")
            return StepResult(
                admitted=False,
                verdict=Verdict.REQUIRE_APPROVAL.value,
                rule="approval_token_required",
                state=ExecutionState.BLOCKED,
            )
        try:
            ctx.approval_authority.verify_and_consume(
                ctx.approval_token,
                asset_id,
                profile_id,
                profile_fingerprint(resolved["profile"]),
            )
        except ApprovalError as exc:
            ctx.trace.emit(
                TraceEventType.POLICY_EVENT,
                rule="approval_invalid",
                verdict=Verdict.DENY.value,
                text=str(exc),
            )
            _emit_state(ctx, ExecutionState.BLOCKED, "approval rejected")
            return StepResult(
                admitted=False,
                verdict=Verdict.DENY.value,
                rule="approval_invalid",
                detail=str(exc),
                state=ExecutionState.BLOCKED,
            )
        _emit_state(ctx, ExecutionState.APPROVED, "single-use approval consumed")
    elif decision.verdict is not Verdict.ALLOW:
        _emit_state(ctx, ExecutionState.BLOCKED, decision.rule)
        return StepResult(
            admitted=False,
            verdict=decision.verdict.value,
            rule=decision.rule,
            detail=decision.detail,
            state=ExecutionState.BLOCKED,
        )

    if resolved is None:
        _emit_state(ctx, ExecutionState.BLOCKED, "profile resolution failed")
        return StepResult(
            admitted=False,
            verdict=Verdict.DENY.value,
            rule="profile_resolution_failed",
            state=ExecutionState.BLOCKED,
        )

    if ctx.kill_switch is not None and ctx.kill_switch.engaged():
        _emit_state(ctx, ExecutionState.KILLED, "kill switch engaged before execution")
        return StepResult(
            admitted=False,
            verdict=Verdict.DENY.value,
            rule="kill_switch_engaged",
            state=ExecutionState.KILLED,
        )

    sub_params = dict(resolved["params"], tool=resolved["tool"])
    sub = task.model_copy(
        update={
            "target": resolved["target"],
            "agent_params": sub_params,
        }
    )
    _emit_state(ctx, ExecutionState.RUNNING)
    result: AgentResult = executor_adapter.run(sub, ctx)

    if ctx.kill_switch is not None and ctx.kill_switch.engaged():
        _emit_state(ctx, ExecutionState.KILLED, "kill switch engaged after execution")
        return StepResult(
            admitted=False,
            verdict=Verdict.DENY.value,
            rule="kill_switch_engaged",
            output=result.final_output,
            state=ExecutionState.KILLED,
        )

    state = ExecutionState.VERIFIED if result.completed else ExecutionState.FAILED
    _emit_state(ctx, state)
    return StepResult(
        admitted=True,
        verdict=Verdict.ALLOW.value,
        rule=decision.rule,
        output=result.final_output,
        state=state,
    )
