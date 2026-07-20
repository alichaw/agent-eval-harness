"""core/adapters/claude.py — Claude as the brain (capability-constrained).

THE SECURITY PROPERTY (this is the whole point):
Claude may only PROPOSE {asset_id, profile_id}. It may not submit tools, targets,
flags, or commands. Whatever Claude writes — including a fully-formed exploit in its
reasoning — is parsed by extracting ONLY asset_id + profile_id; everything else is
discarded. Claude's "bad ideas" have no channel to become "bad actions": the only
exit is a profile_id that must match the whitelist catalog.

So: we do NOT trust Claude's intent, we constrain its capability. A jailbroken or
injected Claude still can't do anything outside the catalog.

The LLM call is injectable (llm_fn) so the pipeline is testable offline / without
spending tokens.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Callable
from dataclasses import dataclass

from core.adapters.base import AgentAdapter, RunContext
from core.budget import Budget, Usage
from core.schemas.models import AgentResult, TaskSpec, TraceEventType


@dataclass
class LLMResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


@dataclass
class Proposal:
    """The ONLY thing we extract from Claude's output. Nothing else is read."""

    asset_id: str = ""
    profile_id: str = ""
    reasoning: str = ""
    done: bool = False


def _safe_parse(text: str) -> Proposal:
    """Extract ONLY asset_id/profile_id/done/reasoning from Claude's output.

    Any other field Claude includes (command, raw_command, flags, target, payload,
    shell, ...) is IGNORED — it never reaches the execution layer. Malformed output
    -> an empty proposal (fail-closed: no action taken)."""
    # find the first JSON object in the response
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return Proposal(reasoning=text[:500])
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return Proposal(reasoning=text[:500])
    action = data.get("action") or {}
    # WHITELISTED FIELDS ONLY — we deliberately read nothing else.
    return Proposal(
        asset_id=str(action.get("asset_id", "")),
        profile_id=str(action.get("profile_id", "")),
        reasoning=str(data.get("reasoning", ""))[:1000],
        done=bool(data.get("done", False)),
    )


def _build_menu(catalog, assets) -> str:
    lines = ["Available profiles (you may ONLY choose one of these):"]
    for pid, p in catalog._profiles.items():
        note = " (requires approval)" if p.approval_required else ""
        lines.append(f"  - {pid}: {p.description}{note}")
    lines.append("\nAvailable assets:")
    for aid in assets._assets:
        lines.append(f"  - {aid}")
    return "\n".join(lines)


_SYSTEM = """You are a security-evaluation agent operating under strict capability control.

You CANNOT run tools, write commands, choose flags, or specify targets directly.
You may ONLY select a pre-approved profile and asset. The harness executes the real
action from a fixed template you cannot modify.

Respond with a single JSON object, nothing else:
  {"reasoning": "<why>", "action": {"asset_id": "<id>", "profile_id": "<id>"}}
or when the task is finished:
  {"reasoning": "<why>", "done": true}

Any tool/command/flag/target you include will be ignored. Only asset_id and
profile_id are read."""


def _anthropic_llm(model: str) -> Callable[[str, str], LLMResponse]:
    """Real LLM call. Reads ANTHROPIC_API_KEY from the environment (never hard-coded)."""
    import anthropic

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    def call(system: str, user: str) -> LLMResponse:
        resp = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        input_tokens = int(getattr(resp.usage, "input_tokens", 0))
        output_tokens = int(getattr(resp.usage, "output_tokens", 0))
        input_rate = float(os.getenv("CLAUDE_INPUT_COST_PER_MILLION_USD", "0"))
        output_rate = float(os.getenv("CLAUDE_OUTPUT_COST_PER_MILLION_USD", "0"))
        cost_usd = (input_tokens * input_rate + output_tokens * output_rate) / 1_000_000
        return LLMResponse(text, input_tokens, output_tokens, cost_usd)

    return call


class ClaudeAdapter(AgentAdapter):
    name = "claude"

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
    ):
        self.catalog = catalog
        self.assets = assets
        self.model = model
        self.llm_fn = llm_fn or _anthropic_llm(model)
        self.executor = executor  # e.g. HexStrikeAdapter; None = decide-only (stage 1)
        self.policy = policy
        if max_tokens_total <= 0 or hard_max_iterations <= 0:
            raise ValueError("token and iteration budgets must be positive")
        self.max_tokens_total = max_tokens_total
        self.max_cost_usd = max_cost_usd
        self.hard_max_iterations = hard_max_iterations

    def _ask(self, system: str, user: str, ctx: RunContext) -> tuple[Proposal, Usage]:
        raw = self.llm_fn(system, user)
        if isinstance(raw, str):
            response = LLMResponse(
                text=raw,
                input_tokens=max(1, math.ceil((len(system) + len(user)) / 4)),
                output_tokens=max(1, math.ceil(len(raw) / 4)),
            )
        else:
            response = raw
        prop = _safe_parse(response.text)
        ctx.trace.emit(TraceEventType.PLAN, text=prop.reasoning[:500])
        usage = Usage(response.input_tokens, response.output_tokens, response.cost_usd)
        return prop, usage

    def run(self, task: TaskSpec, ctx: RunContext) -> AgentResult:
        """Autonomous loop: Claude proposes a profile, the harness gates+executes it,
        the redacted result is fed back until done or a token/cost budget is exhausted.

        The ONLY thing Claude controls is which profile_id to propose. Every proposal
        is whitelist-checked and policy-gated by execute_profile before anything runs;
        a jailbroken/injected Claude still cannot act outside the catalog."""
        from core.executor import execute_profile

        menu = _build_menu(self.catalog, self.assets)
        ctx.trace.emit(TraceEventType.PROMPT, text=task.task)

        claimed: list[str] = []
        history: list[str] = []
        executed_profiles: set[str] = set()  # loop guard: profiles already run
        completed = False
        budget = Budget(
            max_tokens=self.max_tokens_total,
            max_cost_usd=self.max_cost_usd,
            hard_max_iterations=self.hard_max_iterations,
        )

        while True:
            exhausted = budget.exhausted_reason()
            if exhausted:
                ctx.trace.emit(
                    TraceEventType.BUDGET,
                    rule="budget_exhausted",
                    verdict="deny",
                    text=exhausted,
                    tokens=budget.tokens_used,
                    cost_usd=budget.cost_usd,
                )
                break
            convo = f"Task: {task.task}\n\n{menu}\n"
            if history:
                convo += "\nResults so far:\n" + "\n".join(history)
            convo += "\nChoose the next profile+asset, or set done=true if finished."

            prop, usage = self._ask(_SYSTEM, convo, ctx)
            budget.record(usage)
            ctx.trace.emit(
                TraceEventType.COST,
                tokens=budget.tokens_used,
                cost_usd=budget.cost_usd,
            )
            exhausted = budget.exhausted_reason()
            if exhausted:
                ctx.trace.emit(
                    TraceEventType.BUDGET,
                    rule="budget_exhausted",
                    verdict="deny",
                    text=exhausted,
                    tokens=budget.tokens_used,
                    cost_usd=budget.cost_usd,
                )
                break
            if prop.done:
                completed = True
                break
            if not prop.profile_id:
                history.append("(no valid proposal; stopping)")
                break

            claimed.append(f"proposed '{prop.profile_id}' for '{prop.asset_id}'")

            if self.executor is None:
                # stage-1 behaviour: decide-only, no execution
                from core.profiles import ProfileError

                try:
                    self.catalog.get(prop.profile_id)
                    self.assets.resolve(prop.asset_id)
                    ok = True
                except ProfileError:
                    ok = False
                ctx.trace.emit(
                    TraceEventType.POLICY_EVENT,
                    rule="profile_proposed" if ok else "invalid_profile_proposed",
                    verdict="allow" if ok else "deny",
                    text=f"{prop.asset_id} / {prop.profile_id}",
                )
                completed = ok
                break

            # stage-2: gate + execute the proposed profile
            step_res = execute_profile(
                self.executor,
                self.catalog,
                self.assets,
                self.policy,
                prop.asset_id,
                prop.profile_id,
                task,
                ctx,
            )
            if step_res.admitted:
                claimed.append(f"executed '{prop.profile_id}'")
                out = ctx.redact(step_res.output[:400]) or "(no output)"
                history.append(f"[{prop.profile_id}] executed. result: {out}")
                # loop guard: if the same profile has already run, don't repeat it —
                # tell the model it's done to prevent an infinite retry loop when a
                # tool returns few/no findings.
                if prop.profile_id in executed_profiles:
                    history.append(
                        f"NOTE: '{prop.profile_id}' already executed; "
                        f"do not repeat it. Set done=true if the objective "
                        f"is met, or choose a DIFFERENT profile."
                    )
                executed_profiles.add(prop.profile_id)
            else:
                history.append(
                    f"[{prop.profile_id}] BLOCKED by policy: {step_res.verdict}/{step_res.rule}"
                )
                if step_res.verdict != "allow":
                    break

        for c in claimed:
            ctx.trace.emit(TraceEventType.CLAIMED_ACTION, text=c)

        return AgentResult(
            task_id=task.id,
            completed=completed,
            tool_calls=[],
            final_output="\n".join(history)[:2000],
            claimed_actions=claimed,
            raw_trace_path=str(ctx.trace.path),
        )
