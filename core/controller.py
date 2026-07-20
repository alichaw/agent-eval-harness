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
from core.redaction import Redactor
from core.safety import ApprovalAuthority, ApprovalError, ExecutionState, KillSwitch, profile_fingerprint
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
    def __init__(
        self,
        runs_root: str | Path = "runs",
        policy: Policy | None = None,
        catalog=None,
        assets=None,
        approval_token: str = "",
        approval_authority: ApprovalAuthority | None = None,
        kill_switch: KillSwitch | None = None,
    ):
        self.runs_root = Path(runs_root)
        self.policy = policy
        self.catalog = catalog  # ProfileCatalog | None (enables profile-driven mode)
        self.assets = assets  # AssetRegistry | None
        self.approval_token = approval_token
        self.approval_authority = approval_authority
        self.kill_switch = kill_switch

    def _resolve_profile(self, case):
        """If the case is profile-driven ({asset_id, profile_id}), resolve it into a
        concrete (tool, target, params, profile). Model never sets tool/target — the
        Harness derives them from the fixed profile. Returns None for legacy cases."""
        if not case.profile_id:
            return None
        from core.profiles import ProfileError

        if self.catalog is None or self.assets is None:
            raise ProfileError("profile-driven case but no catalog/assets loaded")
        profile = self.catalog.get(case.profile_id)  # fail-closed on unknown
        asset = self.assets.resolve(case.asset_id)  # fail-closed on unknown
        params = dict(
            profile.parameters,
            ports=asset.get("ports", ""),
        )
        params.update(asset.get("tool_args", {}) or {})

        return {
            "tool": profile.tool_id,
            "target": asset.get("target", ""),
            "params": params,
            "profile": profile,
        }

    # optional; when set, every run is policy-gated

    def run_case(self, case_path: str | Path, agent: AgentAdapter, seed: int = 0) -> Path:
        """Execute one case with one agent; return the run directory."""
        case = load_case(case_path)

        run_id = make_run_id(case, case_path)
        run_dir = self.runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        redactor = Redactor.from_assets(self.assets)
        trace = TraceWriter(run_id, run_dir / "trace.jsonl", redactor=redactor)
        ctx = RunContext(
            run_id=run_id,
            run_dir=run_dir,
            trace=trace,
            seed=seed,
            redactor=redactor,
            approval_token=self.approval_token,
            approval_authority=self.approval_authority,
            kill_switch=self.kill_switch,
        )

        # manifest FIRST — so even if the agent crashes, the run is identifiable
        manifest = {
            "run_id": run_id,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "agent": agent.name,
            "case_id": case.id,
            "case_path": Path(case_path).name,
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
        # resolve a profile-driven case into concrete (tool, target, params) — the
        # model only named {asset_id, profile_id}; the Harness derives the rest.
        resolved = self._resolve_profile(case)  # None for legacy cases
        if resolved is not None:
            ctx.trace.emit(
                TraceEventType.EXECUTION_STATE,
                state=ExecutionState.PROPOSED.value,
                text=f"{case.asset_id} / {case.profile_id}",
            )

        if self.kill_switch is not None and self.kill_switch.engaged():
            ctx.trace.emit(
                TraceEventType.EXECUTION_STATE,
                state=ExecutionState.KILLED.value,
                text="kill switch engaged before policy gate",
            )
            result_doc = {
                "run_id": run_id,
                "completed": False,
                "agent_reported_completed": False,
                "elapsed_s": 0.0,
                "task_id": case.id,
                "policy_denied": True,
                "policy_verdict": "deny",
                "policy_rule": "kill_switch_engaged",
                "policy_detail": "kill switch engaged before policy gate",
                "tool_calls": [],
                "claimed_actions": [],
                "final_output_head": "",
            }
            (run_dir / "result.json").write_text(
                json.dumps(redactor.value(result_doc), indent=2)
            )
            return run_dir

        if self.policy is not None:
            from core.policy import ActionRequest, Verdict

            if resolved is not None:
                # RISK IS DECIDED BY THE PROFILE, NOT THE TOOL NAME. The same nmap is
                # low-risk under an A1 profile (5 ports) and needs approval under A2
                # (20 ports). So for profile-driven runs we do NOT use the policy's
                # tool-level active_tools list; approval comes from the profile.
                prof_policy = Policy(
                    default=self.policy.default,
                    allowed_tools=self.policy.allowed_tools,
                    allowed_targets=self.policy.allowed_targets,
                    denied_targets=self.policy.denied_targets,
                    active_tools=[],
                    max_cost_usd=self.policy.max_cost_usd,
                    deny_flags=self.policy.deny_flags,
                )
                req = ActionRequest(
                    tool=resolved["tool"],
                    target=resolved["target"],
                    params=resolved["params"],
                    target_source="case",  # profile targets come from the asset registry = trusted
                )
                decision = prof_policy.check(req)
                # a profile that requires approval short-circuits to REQUIRE_APPROVAL
                if decision.verdict is Verdict.ALLOW and resolved["profile"].approval_required:
                    from core.policy import PolicyDecision

                    decision = PolicyDecision(
                        Verdict.REQUIRE_APPROVAL,
                        "profile_needs_approval",
                        f"profile '{case.profile_id}' (risk={resolved['profile'].risk_tier.value})",
                    )
                if decision.verdict is Verdict.REQUIRE_APPROVAL:
                    if self.approval_authority is not None and self.approval_token:
                        try:
                            self.approval_authority.verify_and_consume(
                                self.approval_token,
                                case.asset_id,
                                case.profile_id,
                                profile_fingerprint(resolved["profile"]),
                            )
                        except ApprovalError as exc:
                            decision = PolicyDecision(
                                Verdict.DENY, "approval_invalid", str(exc)
                            )
                        else:
                            ctx.trace.emit(
                                TraceEventType.EXECUTION_STATE,
                                state=ExecutionState.APPROVED.value,
                                text="single-use approval consumed",
                            )
                            decision = PolicyDecision(
                                Verdict.ALLOW,
                                "approval_valid",
                                "single-use approval consumed",
                            )
            else:
                tool = case.allowed_tools[0] if case.allowed_tools else ""
                requested_tool = case.agent_params.get("tool", tool)
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
                safe_result_doc = redactor.value(result_doc)
                (run_dir / "result.json").write_text(json.dumps(safe_result_doc, indent=2))
                return run_dir

        execution_case = case

        if resolved is not None:
            execution_params = {
                **resolved["params"],
                "tool": resolved["tool"],
            }
            execution_case = case.model_copy(
                update={
                    "target": resolved["target"],
                    "agent_params": execution_params,
                }
            )

        if resolved is not None:
            ctx.trace.emit(
                TraceEventType.EXECUTION_STATE,
                state=ExecutionState.RUNNING.value,
                text=ExecutionState.RUNNING.value,
            )
        started = time.time()
        result: AgentResult = agent.run(execution_case, ctx)
        elapsed = round(time.time() - started, 3)
        if resolved is not None:
            final_state = ExecutionState.VERIFIED if result.completed else ExecutionState.FAILED
            ctx.trace.emit(
                TraceEventType.EXECUTION_STATE,
                state=final_state.value,
                text=final_state.value,
            )

        # ACTION VERIFIER (W4): don't trust the agent's self-report. Cross-check its
        # claimed_actions against the trace evidence, and against the profile's
        # required evidence. Emit a verification event per claim.
        from core.verifier import Verifier, load_env_evidence, load_trace

        events = load_trace(run_dir)
        env_evidence = redactor.value(load_env_evidence(run_dir))
        safe_claims = redactor.value(result.claimed_actions)
        evidence_required = resolved["profile"].evidence_required if resolved else []
        report = Verifier().verify(
            safe_claims, events, evidence_required, env_evidence=env_evidence
        )
        for cv in report.claim_verdicts:
            ctx.trace.emit(
                TraceEventType.VERIFICATION,
                verified=(cv.status.value == "honest"),
                text=f"{cv.status.value}: {cv.claim}",
                evidence=cv.evidence,
            )

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
            "tool_calls": redactor.value([tc.model_dump() for tc in result.tool_calls]),
            "claimed_actions": safe_claims,
            "final_output_head": redactor.text(result.final_output[:500]),
            "verification": report.to_dict(),
        }
        safe_result_doc = redactor.value(result_doc)
        (run_dir / "result.json").write_text(json.dumps(safe_result_doc, indent=2))

        return run_dir
