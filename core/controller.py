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
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

from core.adapters.base import AgentAdapter, RunContext
from core.investigation.models import InvestigationState
from core.policy import Policy
from core.redaction import Redactor
from core.safety import (
    ApprovalAuthority,
    ApprovalError,
    ExecutionState,
    KillSwitch,
    profile_fingerprint,
)
from core.schemas.models import SCHEMA_VERSION, AgentResult, TaskSpec, TraceEventType
from core.t3.executor import (
    LAB_EXECUTION_SCOPE,
    LAB_PLATFORM,
    LAB_SSH_CAPABILITY,
    LAB_SSH_METHOD,
    LAB_SSH_PORT,
    LabObservation,
    LabSshExecutionPlan,
    LabSshT3Executor,
    LabT3Outcome,
    MockT3ExecutionPlan,
    MockT3Executor,
    MockT3Outcome,
    T3Executor,
    lab_target_is_locally_permitted,
    valid_pinned_host_key,
)
from core.t3.models import T3ActionRequest, t3_action_fingerprint
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
        job_create_token: str = "",
        approval_authority: ApprovalAuthority | None = None,
        kill_switch: KillSwitch | None = None,
    ):
        self.runs_root = Path(runs_root)
        self.policy = policy
        self.catalog = catalog  # ProfileCatalog | None (enables profile-driven mode)
        self.assets = assets  # AssetRegistry | None
        self.approval_token = approval_token
        self.job_create_token = job_create_token
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

    def run_t3_action(
        self,
        request: T3ActionRequest | dict[str, object],
        state: InvestigationState,
        executor: T3Executor,
        approval_token: str | None = None,
    ) -> Path:
        """Run the mock-only T3 control chain and persist auditable artifacts.

        Validation order is request, assets, policy, evidence, fingerprint,
        approval consumption, then the non-executing mock boundary.
        """
        from core.policy import T3PolicyRequest, Verdict
        from core.t3.gate import validate_t3_prerequisites

        run_id = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-t3-{time.time_ns()}"
        run_dir = self.runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        redactor = Redactor.from_assets(self.assets, redact_credentials=True)
        trace = TraceWriter(run_id, run_dir / "trace.jsonl", redactor=redactor)

        lab_executor = type(executor) is LabSshT3Executor
        mock_executor = type(executor) is MockT3Executor
        manifest = {
            "run_id": run_id,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "agent": "lab-ssh-t3" if lab_executor else "mock-t3",
            "schema_version": SCHEMA_VERSION,
            "policy_gated": True,
            "mock_only": not lab_executor,
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

        def emit(rule: str, verdict: str, text: str) -> None:
            trace.emit(
                TraceEventType.POLICY_EVENT,
                rule=rule,
                verdict=verdict,
                text=text,
            )

        def finish(
            *,
            completed: bool,
            status: str,
            rule: str,
            control_authorized: bool = False,
            approval_consumed: bool = False,
            executor_invoked: bool = False,
            outcome: MockT3Outcome | LabT3Outcome | None = None,
        ) -> Path:
            emit(
                "t3_final_result",
                Verdict.ALLOW.value if completed else Verdict.DENY.value,
                "T3 flow completed" if completed else "T3 flow denied",
            )
            result = {
                "run_id": run_id,
                "completed": completed,
                "status": status,
                "rule": rule,
                "control_authorized": control_authorized,
                "approval_consumed": approval_consumed,
                "mock_executor_invoked": executor_invoked and mock_executor,
                "lab_executor_invoked": executor_invoked and lab_executor,
                "real_action_performed": (
                    outcome.real_action_performed if outcome is not None else False
                ),
                "mock_outcome": (
                    asdict(outcome) if isinstance(outcome, MockT3Outcome) else None
                ),
                "lab_outcome": (
                    outcome.result_document() if isinstance(outcome, LabT3Outcome) else None
                ),
            }
            (run_dir / "result.json").write_text(
                json.dumps(redactor.value(result), indent=2)
            )
            return run_dir

        # A. Revalidate model instances too: model_copy(update=...) can bypass checks.
        try:
            if isinstance(request, T3ActionRequest):
                request = T3ActionRequest.model_validate(request.model_dump())
            else:
                request = T3ActionRequest.model_validate(request)
        except Exception:  # noqa: BLE001 - request failures must not expose input
            emit("t3_request_invalid", Verdict.DENY.value, "T3 request rejected")
            return finish(completed=False, status="denied", rule="t3_request_invalid")
        emit("t3_request_accepted", Verdict.ALLOW.value, "T3 request accepted for evaluation")

        if not (mock_executor or lab_executor):
            emit("t3_executor_required", Verdict.DENY.value, "T3 executor rejected")
            return finish(completed=False, status="denied", rule="t3_executor_required")
        if lab_executor:
            emit("lab_executor_selected", Verdict.ALLOW.value, "Lab executor selected")

        if self.kill_switch is not None and self.kill_switch.engaged():
            emit("kill_switch_engaged", Verdict.DENY.value, "T3 action blocked")
            return finish(completed=False, status="denied", rule="kill_switch_engaged")

        # B/C. Resolve registry-controlled targets before making policy requests.
        if self.assets is None:
            emit("t3_source_asset_unresolved", Verdict.DENY.value, "Source asset rejected")
            return finish(completed=False, status="denied", rule="t3_source_asset_unresolved")
        try:
            source = self.assets.resolve(request.source_asset_id)
        except Exception:  # noqa: BLE001 - registry failures must not expose details
            emit("t3_source_asset_unresolved", Verdict.DENY.value, "Source asset rejected")
            return finish(completed=False, status="denied", rule="t3_source_asset_unresolved")
        source_target_value = source.get("target")
        if not isinstance(source_target_value, str) or not source_target_value.strip():
            emit("t3_source_target_invalid", Verdict.DENY.value, "Source asset rejected")
            return finish(completed=False, status="denied", rule="t3_source_target_invalid")
        source_target = source_target_value.strip()

        lab_observation = None
        if lab_executor:
            if not executor.enabled:
                emit(
                    "lab_execution_disabled",
                    Verdict.DENY.value,
                    "Lab execution is disabled",
                )
                return finish(
                    completed=False,
                    status="lab_execution_disabled",
                    rule="lab_execution_disabled",
                )
            emit(
                "lab_execution_enablement_checked",
                Verdict.ALLOW.value,
                "Lab execution explicitly enabled",
            )
            try:
                lab_observation = LabObservation(request.command_scope[0])
            except (IndexError, ValueError):
                lab_observation = None
            lab_request_permitted = (
                request.stage.value == "initial_access"
                and request.destination_asset_id is None
                and request.capability_id == LAB_SSH_CAPABILITY
                and request.method == LAB_SSH_METHOD
                and len(request.command_scope) == 1
                and lab_observation is not None
                and request.credential_ref is not None
            )
            asset_permitted = (
                source.get("asset_type") == "host"
                and source.get("execution_scope") == LAB_EXECUTION_SCOPE
                and source.get("platform") == LAB_PLATFORM
                and type(source.get("ssh_port")) is int
                and source.get("ssh_port") == LAB_SSH_PORT
                and valid_pinned_host_key(source.get("ssh_host_key"))
                and source_target == executor.permitted_target
                and 0 < executor.timeout_seconds <= 10
                and lab_target_is_locally_permitted(source_target)
            )
            if not lab_request_permitted or not asset_permitted:
                emit(
                    "lab_target_not_permitted",
                    Verdict.DENY.value,
                    "Lab target constraints rejected",
                )
                return finish(
                    completed=False,
                    status="lab_target_not_permitted",
                    rule="lab_target_not_permitted",
                )
            emit(
                "lab_target_constraint_checked",
                Verdict.ALLOW.value,
                "Lab target constraints accepted",
            )

        destination = None
        destination_target = None
        if request.destination_asset_id is not None:
            try:
                destination = self.assets.resolve(request.destination_asset_id)
            except Exception:  # noqa: BLE001 - registry failures must not expose details
                emit(
                    "t3_destination_asset_unresolved",
                    Verdict.DENY.value,
                    "Destination asset rejected",
                )
                return finish(
                    completed=False,
                    status="denied",
                    rule="t3_destination_asset_unresolved",
                )
            destination_target_value = destination.get("target")
            if (
                not isinstance(destination_target_value, str)
                or not destination_target_value.strip()
            ):
                emit(
                    "t3_destination_target_invalid",
                    Verdict.DENY.value,
                    "Destination asset rejected",
                )
                return finish(
                    completed=False,
                    status="denied",
                    rule="t3_destination_target_invalid",
                )
            destination_target = destination_target_value.strip()
            # AssetRegistry has no canonical identity API yet. Exact resolved target
            # equality prevents aliases with identical target strings from being
            # treated as movement; hostname/IP equivalence remains out of scope.
            if destination_target == source_target:
                emit(
                    "t3_destination_same_as_source",
                    Verdict.DENY.value,
                    "Destination asset rejected",
                )
                return finish(
                    completed=False,
                    status="denied",
                    rule="t3_destination_same_as_source",
                )

        # D. Each resolved target is independently checked by the existing policy.
        if self.policy is None:
            emit("t3_policy_required", Verdict.DENY.value, "T3 policy authorization denied")
            return finish(completed=False, status="denied", rule="t3_policy_required")

        source_decision = self.policy.check_t3(
            T3PolicyRequest(
                capability_id=request.capability_id,
                stage=request.stage.value,
                target=source_target,
            )
        )
        if source_decision.verdict is not Verdict.REQUIRE_APPROVAL:
            emit(source_decision.rule, Verdict.DENY.value, "Source policy authorization denied")
            return finish(completed=False, status="denied", rule=source_decision.rule)
        emit("t3_source_authorized", Verdict.ALLOW.value, "Source policy authorization accepted")

        if destination is not None:
            destination_decision = self.policy.check_t3(
                T3PolicyRequest(
                    capability_id=request.capability_id,
                    stage=request.stage.value,
                    target=destination_target,
                )
            )
            if destination_decision.verdict is not Verdict.REQUIRE_APPROVAL:
                emit(
                    destination_decision.rule,
                    Verdict.DENY.value,
                    "Destination policy authorization denied",
                )
                return finish(
                    completed=False,
                    status="denied",
                    rule=destination_decision.rule,
                )
            emit(
                "t3_destination_authorized",
                Verdict.ALLOW.value,
                "Destination policy authorization accepted",
            )

        # E. Evidence suitability is independent of target authorization.
        gate_decision = validate_t3_prerequisites(request, state, self.assets)
        if gate_decision.denied:
            emit(gate_decision.rule, Verdict.DENY.value, "T3 prerequisites rejected")
            return finish(completed=False, status="denied", rule=gate_decision.rule)
        emit(
            "t3_prerequisites_satisfied",
            Verdict.ALLOW.value,
            "T3 prerequisites accepted",
        )

        # F/G/H. The Controller computes and requires the exact action binding.
        action_fingerprint = t3_action_fingerprint(request)
        if not action_fingerprint:
            emit("t3_fingerprint_invalid", Verdict.DENY.value, "T3 approval rejected")
            return finish(completed=False, status="denied", rule="t3_fingerprint_invalid")
        token = self.approval_token if approval_token is None else approval_token
        if not token or self.approval_authority is None:
            emit("t3_approval_required", Verdict.DENY.value, "T3 approval required")
            return finish(completed=False, status="denied", rule="t3_approval_required")
        try:
            self.approval_authority.verify_and_consume(
                token,
                request.source_asset_id,
                request.capability_id,
                action_fingerprint,
                action_fingerprint=action_fingerprint,
            )
        except Exception:  # noqa: BLE001 - approval details must not escape
            emit("t3_approval_invalid", Verdict.DENY.value, "T3 approval rejected")
            return finish(completed=False, status="denied", rule="t3_approval_invalid")
        emit("t3_approval_verified", Verdict.ALLOW.value, "T3 approval consumed")

        # I/J/K. Only a narrow immutable plan crosses the selected executor boundary.
        if lab_executor:
            assert lab_observation is not None
            trace.emit(
                TraceEventType.EXECUTION_STATE,
                rule="lab_execution_started",
                state=ExecutionState.RUNNING.value,
                text="Lab observation started",
            )
            plan = LabSshExecutionPlan(
                action_id=request.action_id,
                source_asset_id=request.source_asset_id,
                capability_id=request.capability_id,
                observation=lab_observation,
                target=source_target,
                port=LAB_SSH_PORT,
                credential_handle=request.credential_ref or "",
                timeout_seconds=executor.timeout_seconds,
                pinned_host_key=source["ssh_host_key"],
            )
            try:
                lab_outcome = executor.run(plan)
                if not isinstance(lab_outcome, LabT3Outcome):
                    raise TypeError("invalid lab T3 outcome")
            except Exception:  # noqa: BLE001 - consumed approvals are never retried
                emit(
                    "lab_observation_failed",
                    Verdict.DENY.value,
                    "Lab observation failed",
                )
                return finish(
                    completed=False,
                    status="lab_observation_failed",
                    rule="lab_observation_failed",
                    control_authorized=True,
                    approval_consumed=True,
                    executor_invoked=True,
                )
            for code in lab_outcome.trace_codes:
                emit(
                    code,
                    (
                        Verdict.DENY.value
                        if code.endswith("_failed")
                        else Verdict.ALLOW.value
                    ),
                    "Lab execution stage recorded",
                )
            completed = lab_outcome.status == "lab_observation_completed"
            return finish(
                completed=completed,
                status=lab_outcome.status,
                rule=lab_outcome.rule,
                control_authorized=True,
                approval_consumed=True,
                executor_invoked=True,
                outcome=lab_outcome,
            )

        trace.emit(
            TraceEventType.EXECUTION_STATE,
            rule="t3_mock_execution_started",
            state=ExecutionState.RUNNING.value,
            text="Mock T3 execution started",
        )
        try:
            outcome = executor.run(MockT3ExecutionPlan.from_request(request))
            if not isinstance(outcome, MockT3Outcome):
                raise TypeError("invalid mock T3 outcome")
        except Exception:  # noqa: BLE001 - consumed approvals are never retried
            trace.emit(
                TraceEventType.EXECUTION_STATE,
                rule="t3_mock_execution_failed",
                state=ExecutionState.FAILED.value,
                text="Mock T3 execution failed",
            )
            return finish(
                completed=False,
                status="mock_failed",
                rule="t3_mock_execution_failed",
                control_authorized=True,
                approval_consumed=True,
                executor_invoked=True,
            )

        trace.emit(
            TraceEventType.EXECUTION_STATE,
            rule="t3_mock_execution_completed",
            state=ExecutionState.VERIFIED.value,
            text="Mock T3 execution completed; no real action occurred",
        )
        return finish(
            completed=True,
            status="mock_completed",
            rule="t3_result_completed",
            control_authorized=True,
            approval_consumed=True,
            executor_invoked=True,
            outcome=outcome,
        )

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
            job_create_token=self.job_create_token,
            approval_authority=self.approval_authority,
            kill_switch=self.kill_switch,
            t3_credential_ref=case.t3_credential_ref,
            t3_written_justification=case.t3_written_justification,
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
            (run_dir / "result.json").write_text(json.dumps(redactor.value(result_doc), indent=2))
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
                    t3_credential_ref=case.t3_credential_ref,
                    t3_written_justification=case.t3_written_justification,
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
                                credential_id=case.t3_credential_ref,
                            )
                        except ApprovalError as exc:
                            decision = PolicyDecision(Verdict.DENY, "approval_invalid", str(exc))
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
                    t3_credential_ref=case.t3_credential_ref,
                    t3_written_justification=case.t3_written_justification,
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
            if result.completed:
                final_state = ExecutionState.VERIFIED
            elif self.kill_switch is not None and self.kill_switch.engaged():
                final_state = ExecutionState.KILLED
            else:
                final_state = ExecutionState.FAILED
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
