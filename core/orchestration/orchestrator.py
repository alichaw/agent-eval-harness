from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol

from core.enforcement import evaluate_effective_action, resolve_effective_action
from core.orchestration.catalog import Capability, CapabilityCatalog
from core.orchestration.models import (
    ApprovalGrant,
    BudgetLimits,
    ExecutionResult,
    RunContext,
    RunStatus,
)
from core.orchestration.observations import normalize
from core.orchestration.planner import Planner
from core.orchestration.transitions import eligible_capabilities
from core.policy import Policy, Verdict
from core.profiles import AssetRegistry, ProfileCatalog


class Executor(Protocol):
    def execute(self, capability: Capability, run: RunContext) -> ExecutionResult: ...


class Orchestrator:
    def __init__(
        self,
        *,
        catalog: CapabilityCatalog,
        profiles: ProfileCatalog,
        assets: AssetRegistry,
        policy: Policy,
        planner: Planner,
        executor: Executor,
        kill_switch: Callable[[], bool],
        budgets: BudgetLimits | None = None,
        audit: Callable[[dict], None] | None = None,
    ):
        self.catalog, self.profiles, self.assets, self.policy = catalog, profiles, assets, policy
        self.planner, self.executor, self.kill_switch = planner, executor, kill_switch
        self.budgets, self.audit = budgets or BudgetLimits(), audit or (lambda event: None)

    def start(self, *, run_id: str, principal: str, asset_id: str, task: str) -> RunContext:
        self.assets.resolve(asset_id)
        return RunContext(run_id=run_id, principal=principal, asset_id=asset_id, task=task)

    def advance(self, run: RunContext, approval: ApprovalGrant | None = None) -> RunContext:
        if run.status not in {RunStatus.RUNNING, RunStatus.APPROVAL_REQUIRED}:
            return run
        if self.kill_switch():
            return self._stop(run, RunStatus.CANCELLED, "kill_switch")
        if self._budget_reason(run):
            return self._stop(run, RunStatus.BUDGET_EXHAUSTED, self._budget_reason(run) or "budget")
        allowed = eligible_capabilities(run, self.catalog)
        self._event(
            run, "", "eligible_capabilities", "locally_validated", eligible_capabilities=allowed
        )
        if run.pending_capability:
            capability_id = run.pending_capability
        elif posture := next(
            (
                item
                for item in ("rdp.posture_check", "ssh.posture_check", "smb.posture_check")
                if item in allowed
            ),
            None,
        ):
            # Registered posture transitions are selected from trusted normalized
            # facts, not from model recall. Each still passes the policy gate below.
            capability_id = posture
            run.steps += 1
            run.planned.append(capability_id)
            self._event(run, capability_id, "deterministic_transition", "trusted_open_port")
        else:
            self._event(run, "", "planner_request", "bounded_sanitized_context")
            try:
                decision = self.planner.select_next(
                    run.task, run.observations, allowed, self._remaining_budget(run)
                )
            except (RuntimeError, ValueError):
                run.steps += 1
                return self._stop(run, RunStatus.FAILED, "planner_failure")
            run.steps += 1
            self._event(
                run,
                decision.capability_id or "",
                "planner_decision",
                decision.reason,
                planner_stop=decision.stop,
            )
            if decision.stop:
                return self._stop(run, RunStatus.SUCCEEDED, decision.reason)
            capability_id = decision.capability_id or ""
            run.planned.append(capability_id)
        if capability_id not in allowed:
            run.denied.append(capability_id)
            self._event(run, capability_id, "planner_denied", "transition_or_unknown")
            return self._stop(run, RunStatus.DENIED, "planner selected ineligible capability")
        capability = self.catalog.get(capability_id)
        if not set(capability.prerequisites) <= run.evidence_types:
            run.denied.append(capability_id)
            return self._stop(run, RunStatus.DENIED, "prerequisite evidence missing")
        if self.kill_switch():
            return self._stop(run, RunStatus.CANCELLED, "kill_switch")
        policy_rule = "t3_requires_approval"
        if capability.route == "hexstrike":
            action = resolve_effective_action(
                self.profiles, self.assets, run.asset_id, capability.profile_id or ""
            )
            policy_decision = evaluate_effective_action(action, self.policy)
            policy_rule = policy_decision.rule
            missing_allowances: dict[str, list[str]] = {}
            if action.tool not in self.policy.allowed_tools:
                missing_allowances["policy.allowed_tools"] = [action.tool]
            if action.profile.tool_id != capability.tool:
                missing_allowances["profile.tool_id"] = [capability.tool or ""]
            self._event(
                run,
                capability_id,
                "policy_decision",
                policy_rule,
                policy_verdict=policy_decision.verdict.value,
                policy_decision_stage="effective_action_policy_gate",
                resolved_profile_id=action.profile_id,
                resolved_tool_identifier=action.tool,
                capability_tool_identifier=capability.tool,
                profile_tool_identifier=action.profile.tool_id,
                missing_allowances=missing_allowances,
            )
            if policy_decision.verdict is Verdict.DENY:
                run.denied.append(capability_id)
                return self._stop(run, RunStatus.DENIED, policy_rule)
        if capability.approval_required:
            if approval is None:
                run.status, run.pending_capability = RunStatus.APPROVAL_REQUIRED, capability_id
                self._event(run, capability_id, "approval_required", policy_rule)
                return run
            self._consume_approval(approval, run, capability)
        if self.kill_switch():
            return self._stop(run, RunStatus.CANCELLED, "kill_switch")
        self._event(run, capability_id, "execution_dispatch", capability.route)
        result = self.executor.execute(capability, run)
        run.tool_calls += 1
        observation = normalize(capability_id, run.asset_id, result, self.budgets.max_output_bytes)
        run.observations.append(observation)
        self._event(
            run,
            capability_id,
            "observation_normalized",
            observation.status,
            normalized_facts=[item.model_dump(mode="json") for item in observation.facts],
        )
        run.evidence_types.update(result.evidence_types)
        if observation.evidence_ids:
            self._event(
                run,
                capability_id,
                "evidence_created",
                "sanitized_execution_evidence",
                evidence_ids=observation.evidence_ids,
            )
        run.pending_capability = None
        if observation.status == "succeeded":
            run.executed.append(capability_id)
            run.consecutive_failures = 0
        else:
            run.consecutive_failures += 1
            run.failed.append(capability_id)
        run.status = RunStatus.RUNNING
        self._event(run, capability_id, observation.status, policy_rule, observation.evidence_ids)
        if result.run_fatal:
            return self._stop(
                run, RunStatus.FAILED, result.failure_stage or "executor_integrity_failure"
            )
        return run

    def _consume_approval(self, grant: ApprovalGrant, run: RunContext, capability: Capability):
        now = datetime.now(timezone.utc)
        expected = (
            run.principal,
            run.run_id,
            run.asset_id,
            capability.capability_id,
            capability.phase,
        )
        actual = (grant.principal, grant.run_id, grant.asset_id, grant.capability_id, grant.stage)
        if grant.consumed or grant.expires_at <= now or actual != expected:
            raise ValueError("invalid, expired, mismatched, or replayed approval")
        if capability.route == "t3_controller" and not grant.credential_id:
            raise ValueError("T3 approval must bind an approved credential_id")
        grant.consumed = True

    def _budget_reason(self, run):
        elapsed = (datetime.now(timezone.utc) - run.started_at).total_seconds()
        counts = Counter(run.executed)
        if run.steps >= self.budgets.max_steps:
            return "max_steps"
        if run.tool_calls >= self.budgets.max_tool_calls:
            return "max_tool_calls"
        if counts and max(counts.values()) > self.budgets.max_repeated_capability:
            return "repeated_capability"
        if run.consecutive_failures >= self.budgets.max_consecutive_failures:
            return "consecutive_failures"
        if elapsed >= self.budgets.max_total_duration_seconds:
            return "total_duration"
        return None

    def _remaining_budget(self, run):
        elapsed = (datetime.now(timezone.utc) - run.started_at).total_seconds()
        counts = Counter(run.executed)
        highest_repeat = max(counts.values(), default=0)
        return self.budgets.model_copy(
            update={
                "max_steps": max(1, self.budgets.max_steps - run.steps),
                "max_tool_calls": max(1, self.budgets.max_tool_calls - run.tool_calls),
                "max_repeated_capability": max(
                    1, self.budgets.max_repeated_capability - highest_repeat
                ),
                "max_consecutive_failures": max(
                    1, self.budgets.max_consecutive_failures - run.consecutive_failures
                ),
                "max_total_duration_seconds": max(
                    0.001, self.budgets.max_total_duration_seconds - elapsed
                ),
            }
        )

    def _stop(self, run, status, reason):
        run.status, run.stop_reason, run.pending_capability = status, reason, None
        self._event(run, "", "stopped", reason)
        return run

    def _event(self, run, capability, status, reason, evidence_ids=(), **details):
        self.audit(
            {
                "run_id": run.run_id,
                "timestamp": time.time(),
                "principal": run.principal,
                "asset_id": run.asset_id,
                "capability_id": capability,
                "status": status,
                "reason": reason,
                "evidence_ids": list(evidence_ids),
                "steps": run.steps,
                "tool_calls": run.tool_calls,
                **details,
            }
        )
