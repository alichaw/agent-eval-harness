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
from core.enforcement import (
    authorize_execution,
    effective_approval_fingerprint,
    evaluate_effective_action,
    resolve_effective_action,
)
from core.policy import Policy, PolicyDecision, Verdict
from core.profiles import AssetRegistry, ProfileCatalog, ProfileError
from core.safety import ApprovalError, ExecutionState
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
        action = resolve_effective_action(catalog, assets, asset_id, profile_id)
    except ProfileError as e:
        return PolicyDecision(Verdict.DENY, "unknown_profile_or_asset", str(e)), None

    resolved = {
        "tool": action.tool,
        "target": action.target,
        "params": action.params_dict,
        "profile": action.profile,
        "action": action,
    }
    if policy is None:
        return PolicyDecision(Verdict.DENY, "policy_required"), resolved

    decision = evaluate_effective_action(action, policy)
    if decision.verdict is Verdict.ALLOW and action.profile.approval_required:
        decision = PolicyDecision(
            Verdict.REQUIRE_APPROVAL,
            "profile_needs_approval",
            f"profile '{profile_id}' (risk={action.profile.risk_tier.value})",
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
                effective_approval_fingerprint(resolved["action"]),
                credential_id=getattr(ctx, "t3_credential_ref", ""),
                action_fingerprint=resolved["action"].fingerprint,
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
        ctx.trace.emit(
            TraceEventType.EXECUTION_STATE,
            state=ExecutionState.APPROVED.value,
            text="single-use approval consumed",
            approval_fingerprint=resolved["action"].fingerprint,
        )
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
    ctx.execution_permit = authorize_execution(
        resolved["action"],
        run_id=ctx.run_id,
        policy_rule=decision.rule,
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
