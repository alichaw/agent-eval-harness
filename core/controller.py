"""core/controller.py — the Execution Controller.

Turns "a case + an agent" into a complete, reproducible run directory:

    runs/<run_id>/
      manifest.json   # run_id, time, agent, case_id, schema/case hashes (auditable)
      trace.jsonl     # the event stream (written by the adapter via TraceWriter)
      result.json     # completed, elapsed, port_states, final_output (the verdict)

Design: the controller knows about cases, run_ids and directories — NOT about
HexStrike, docker, or nmap. It talks to any AgentAdapter through the base contract.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from core.adapters.base import AgentAdapter, RunContext
from core.policy import Policy
from core.schemas.models import SCHEMA_VERSION, AgentResult, TaskSpec, TraceEventType
from core.trace.writer import TraceWriter


def load_case(path: str | Path) -> TaskSpec:
    """Load and validate a case YAML into a TaskSpec (extra keys fail loudly)."""
    text = Path(path).read_text(encoding="utf-8")
    return TaskSpec(**yaml.safe_load(text))


def _case_hash(path: str | Path) -> str:
    """Short deterministic hash of the case file: same case -> same hash.
    This is what makes a run_id reproducible and ties a run to exact case content."""
    raw = Path(path).read_bytes()
    return hashlib.sha256(raw).hexdigest()[:4]


def make_run_id(case: TaskSpec, case_path: str | Path, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{case.id}-{_case_hash(case_path)}"


class Controller:
    def __init__(self, runs_root: str | Path = "runs", policy: "Policy | None" = None):
        self.runs_root = Path(runs_root)
        self.policy = policy   # optional; when set, every run is policy-gated

    def run_case(self, case_path: str | Path, agent: AgentAdapter,
                 seed: int = 0) -> Path:
        """Execute one case with one agent; return the run directory."""
        case = load_case(case_path)

        run_id = make_run_id(case, case_path)
        run_dir = self.runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        trace = TraceWriter(run_id, run_dir / "trace.jsonl")
        ctx = RunContext(run_id=run_id, run_dir=run_dir, trace=trace, seed=seed)

        # manifest FIRST — so even if the agent crashes, the run is identifiable
        manifest = {
            "run_id": run_id,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "agent": agent.name,
            "case_id": case.id,
            "case_path": str(case_path),
            "case_hash": _case_hash(case_path),
            "schema_version": SCHEMA_VERSION,
            "seed": seed,
            "policy_gated": self.policy is not None,
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

        # POLICY GATE — checked BEFORE the agent runs (defense in depth, application
        # layer, on top of W1's network firewall). Denials are recorded as
        # policy_event in the trace and the agent is NOT run: an unauthorised action
        # is prevented, not merely logged after the fact.
        if self.policy is not None:
            from core.policy import ActionRequest, Verdict
            tool = (case.allowed_tools[0] if case.allowed_tools else "")
            requested_tool = case.agent_params.get("tool", tool)
            # target_source: case-authorised target is trusted; if a case models an
            # injected target it sets agent_params.target_source = "tool_output".
            req = ActionRequest(
                tool=requested_tool,
                target=case.target,
                params=case.agent_params,
                target_source=case.agent_params.get("target_source", "case"),
            )
            decision = self.policy.check(req)
            ctx.trace.emit(
                TraceEventType.POLICY_EVENT,
                rule=decision.rule,
                verdict=decision.verdict.value,
                text=decision.detail,
            )
            if decision.verdict is not Verdict.ALLOW:
                result_doc = {
                    "run_id": run_id,
                    "completed": False,
                    "agent_reported_completed": False,
                    "elapsed_s": 0.0,
                    "task_id": case.id,
                    "policy_denied": decision.denied,
                    "policy_verdict": decision.verdict.value,
                    "policy_rule": decision.rule,
                    "policy_detail": decision.detail,
                    "tool_calls": [],
                    "claimed_actions": [],
                    "final_output_head": "",
                }
                (run_dir / "result.json").write_text(json.dumps(result_doc, indent=2))
                return run_dir

        started = time.time()
        result: AgentResult = agent.run(case, ctx)
        elapsed = round(time.time() - started, 3)

        # The verdict is derived from the TRACE by one rule (the same rule replay
        # uses), NOT taken from AgentResult.completed. This guarantees result.json
        # and a later replay always agree — that's what "auditable" means here.
        # We still keep the agent's self-reported completion for comparison.
        from core.replay import replay_run
        verdict = replay_run(run_dir)

        result_doc = {
            "run_id": run_id,
            "completed": verdict["completed"],
            "agent_reported_completed": result.completed,
            "elapsed_s": elapsed,
            "task_id": result.task_id,
            "tool_calls": [tc.model_dump() for tc in result.tool_calls],
            "claimed_actions": result.claimed_actions,
            "final_output_head": result.final_output[:500],
        }
        (run_dir / "result.json").write_text(json.dumps(result_doc, indent=2))

        return run_dir