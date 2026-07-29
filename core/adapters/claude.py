"""Claude constrained by deterministic, evidence-derived capability candidates."""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from core.adapters.base import AgentAdapter, RunContext
from core.budget import Budget, Usage
from core.enforcement import ExecutionPermit
from core.investigation.capabilities import CapabilityProfileMap
from core.investigation.models import InvestigationState
from core.investigation.recorder import record_step_result
from core.investigation.router import get_candidate_capabilities
from core.safety import ExecutionState
from core.schemas.models import AgentResult, TaskSpec, TraceEventType


@dataclass
class LLMResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


@dataclass(frozen=True)
class Proposal:
    """The only model-controlled action fields the harness reads."""

    asset_id: str = ""
    capability_id: str = ""
    reasoning: str = ""
    done: bool = False


def _safe_parse(text: str) -> Proposal:
    """Read only asset_id/capability_id; discard profiles, tools and parameters."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match is None:
        return Proposal(reasoning=text[:500])
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return Proposal(reasoning=text[:500])
    action = data.get("action") or {}
    return Proposal(
        asset_id=str(action.get("asset_id", "")),
        capability_id=str(action.get("capability_id", "")),
        reasoning=str(data.get("reasoning", ""))[:1000],
        done=bool(data.get("done", False)),
    )


_SYSTEM = """You are a security-evaluation agent under evidence-driven capability control.
You may select exactly one capability_id from the candidate list for the authorised asset_id.
You cannot select profiles, tools, targets, commands, flags, or parameters.
Respond with one JSON object:
{"reasoning":"<why>","action":{"asset_id":"<id>","capability_id":"<candidate>"}}
or {"reasoning":"<why>","done":true}.
All other action fields are ignored."""


def _anthropic_llm(model: str) -> Callable[[str, str], LLMResponse]:
    import anthropic
    from anthropic.types import TextBlock

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    def call(system: str, user: str) -> LLMResponse:
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(block.text for block in response.content if isinstance(block, TextBlock))
        input_tokens = int(getattr(response.usage, "input_tokens", 0))
        output_tokens = int(getattr(response.usage, "output_tokens", 0))
        input_rate = float(os.getenv("CLAUDE_INPUT_COST_PER_MILLION_USD", "0"))
        output_rate = float(os.getenv("CLAUDE_OUTPUT_COST_PER_MILLION_USD", "0"))
        cost = (input_tokens * input_rate + output_tokens * output_rate) / 1_000_000
        return LLMResponse(text, input_tokens, output_tokens, cost)

    return call


class ClaudeAdapter(AgentAdapter):
    name = "claude"
    requires_authoritative_context = True

    def __init__(
        self,
        catalog,
        assets,
        model: str = "claude-sonnet-4-6",
        llm_fn: Callable[[str, str], str | LLMResponse] | None = None,
        executor=None,
        policy=None,
        max_tokens_total: int = 20_000,
        max_cost_usd: float | None = None,
        hard_max_iterations: int = 50,
        state: InvestigationState | None = None,
        capability_map: CapabilityProfileMap | None = None,
    ):
        if executor is not None and policy is None:
            raise ValueError("evidence-driven execution requires a policy")
        if max_tokens_total <= 0 or hard_max_iterations <= 0:
            raise ValueError("token and iteration budgets must be positive")
        if max_cost_usd is not None and llm_fn is None:
            pricing_vars = (
                "CLAUDE_INPUT_COST_PER_MILLION_USD",
                "CLAUDE_OUTPUT_COST_PER_MILLION_USD",
            )
            if any(not os.getenv(name) for name in pricing_vars):
                raise ValueError(
                    "cost budget requires CLAUDE_INPUT_COST_PER_MILLION_USD and "
                    "CLAUDE_OUTPUT_COST_PER_MILLION_USD"
                )
        self.catalog = catalog
        self.assets = assets
        self.model = model
        self.llm_fn = llm_fn or _anthropic_llm(model)
        self.executor = executor
        self.policy = policy
        self.max_tokens_total = max_tokens_total
        self.max_cost_usd = max_cost_usd
        self.hard_max_iterations = hard_max_iterations
        self.state = state
        self.capability_map = capability_map or CapabilityProfileMap.from_catalog(catalog)

    def _ask(self, prompt: str, ctx: RunContext) -> tuple[Proposal, Usage]:
        raw = self.llm_fn(_SYSTEM, prompt)
        if isinstance(raw, str):
            response = LLMResponse(
                text=raw,
                input_tokens=max(1, math.ceil((len(_SYSTEM) + len(prompt)) / 4)),
                output_tokens=max(1, math.ceil(len(raw) / 4)),
            )
        else:
            response = raw
        proposal = _safe_parse(response.text)
        ctx.trace.emit(TraceEventType.PLAN, text=proposal.reasoning[:500])
        return proposal, Usage(
            response.input_tokens,
            response.output_tokens,
            response.cost_usd,
        )

    def run(self, task: TaskSpec, ctx: RunContext) -> AgentResult:
        from core.executor import execute_profile

        state = self._state_for(task, ctx)
        ctx.trace.emit(TraceEventType.PROMPT, text=task.task)
        history: list[str] = []
        claimed: list[str] = []
        completed = False
        budget = Budget(
            max_tokens=self.max_tokens_total,
            max_cost_usd=self.max_cost_usd,
            hard_max_iterations=self.hard_max_iterations,
        )

        while True:
            exhausted = budget.exhausted_reason()
            if exhausted:
                self._emit_budget(ctx, budget, exhausted)
                break
            candidates = get_candidate_capabilities(state, self.capability_map.capabilities)
            if not candidates:
                completed = not state.pending_approval_capabilities
                break
            proposal, usage = self._ask(self._prompt(task, state, candidates, history), ctx)
            budget.record(usage)
            ctx.trace.emit(
                TraceEventType.COST,
                tokens=budget.tokens_used,
                cost_usd=budget.cost_usd,
            )
            exhausted = budget.exhausted_reason()
            if exhausted:
                self._emit_budget(ctx, budget, exhausted)
                break
            if proposal.done:
                completed = True
                break
            if proposal.asset_id != state.asset_id:
                self._deny(ctx, "asset_mismatch", proposal)
                history.append("proposal denied: asset was not authorised")
                break
            if proposal.capability_id not in candidates:
                self._deny(ctx, "capability_not_offered", proposal)
                history.append("proposal denied: capability was not offered")
                break

            capability_id = proposal.capability_id
            profile_id = self.capability_map.resolve(capability_id)
            profile = self.catalog.get(profile_id)
            claimed.append(f"selected '{capability_id}'")

            if self.executor is None:
                ctx.trace.emit(
                    TraceEventType.POLICY_EVENT,
                    rule="capability_proposed",
                    verdict="allow",
                    text=f"{state.asset_id} / {capability_id}",
                )
                completed = True
                break

            step = execute_profile(
                self.executor,
                self.catalog,
                self.assets,
                self.policy,
                state.asset_id,
                profile_id,
                task,
                ctx,
            )
            state = record_step_result(
                state,
                capability_id=capability_id,
                profile_id=profile_id,
                tool_name=profile.tool_id,
                admitted=step.admitted,
                verified=step.state is ExecutionState.VERIFIED,
                output=step.output,
                verdict=step.verdict,
                run_id=ctx.run_id,
                action_id=(
                    ctx.execution_permit.action_id
                    if isinstance(ctx.execution_permit, ExecutionPermit)
                    else ""
                ),
            )
            self.state = state
            if not step.admitted:
                status = "waiting for approval" if step.verdict == "require_approval" else "blocked"
                history.append(f"[{capability_id}] {status}: {step.verdict}/{step.rule}")
                break
            status = "verified" if step.state is ExecutionState.VERIFIED else "failed"
            output = ctx.redact(step.output[:400]) or "(no output)"
            history.append(f"[{capability_id}] {status}: {output}")

        for item in claimed:
            ctx.trace.emit(TraceEventType.CLAIMED_ACTION, text=item)
        self._save_state(ctx)
        return AgentResult(
            task_id=task.id,
            completed=completed,
            tool_calls=[],
            final_output="\n".join(history)[:2000],
            claimed_actions=claimed,
            raw_trace_path=str(ctx.trace.path),
        )

    def _save_state(self, ctx: RunContext) -> None:
        """Checkpoint resumable investigation state in the auditable run directory."""
        if self.state is None:
            return
        path = Path(ctx.run_dir) / "investigation_state.json"
        path.write_text(self.state.model_dump_json(indent=2), encoding="utf-8")

    def _state_for(self, task: TaskSpec, ctx: RunContext) -> InvestigationState:
        if self.state is None:
            if not task.asset_id:
                raise ValueError("Claude evidence routing requires task.asset_id")
            self.assets.resolve(task.asset_id)
            self.state = InvestigationState(
                investigation_id=f"investigation-{ctx.run_id}",
                asset_id=task.asset_id,
                objective=task.task,
            )
        elif task.asset_id and task.asset_id != self.state.asset_id:
            raise ValueError("task.asset_id does not match investigation state")
        return self.state

    @staticmethod
    def _prompt(
        task: TaskSpec,
        state: InvestigationState,
        candidates: list[str],
        history: list[str],
    ) -> str:
        lines = [
            f"Task: {task.task}",
            f"Authorised asset: {state.asset_id}",
            "Candidate capabilities (choose only one):",
            *(f"- {item}" for item in candidates),
        ]
        if history:
            lines.extend(("Results so far:", *history))
        return "\n".join(lines)

    @staticmethod
    def _deny(ctx: RunContext, rule: str, proposal: Proposal) -> None:
        ctx.trace.emit(
            TraceEventType.POLICY_EVENT,
            rule=rule,
            verdict="deny",
            text=f"{proposal.asset_id} / {proposal.capability_id}",
        )

    @staticmethod
    def _emit_budget(ctx: RunContext, budget: Budget, reason: str) -> None:
        ctx.trace.emit(
            TraceEventType.BUDGET,
            rule="budget_exhausted",
            verdict="deny",
            text=reason,
            tokens=budget.tokens_used,
            cost_usd=budget.cost_usd,
        )
