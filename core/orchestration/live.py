"""Server-bound HexStrike execution for the fixed host-assessment capabilities."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from core.adapters.base import RunContext as AdapterRunContext
from core.adapters.hexstrike import HexStrikeAdapter
from core.enforcement import SERVICE_DISCOVERY_PORTS
from core.executor import execute_profile
from core.orchestration.catalog import Capability
from core.orchestration.models import ExecutionResult, Fact, RunContext
from core.policy import Policy
from core.profiles import AssetRegistry, ProfileCatalog
from core.redaction import Redactor
from core.safety import ApprovalAuthority, ExecutionState, KillSwitch
from core.schemas.models import CaseToolMode, Scoring, TaskSpec
from core.trace.writer import TraceWriter


class LiveHexStrikeExecutor:
    """Adapt the existing policy/permit executor to the unified orchestration contract."""

    def __init__(
        self,
        *,
        profiles: ProfileCatalog,
        assets: AssetRegistry,
        policy: Policy,
        job_create_token: str,
        kill_switch: KillSwitch,
        runs_root: str | Path = "runs",
        base_url: str = "http://127.0.0.1:8888",
        timeout_seconds: int = 90,
        approval_authority: ApprovalAuthority | None = None,
        approval_tokens: dict[str, str] | None = None,
    ):
        endpoint = urlsplit(base_url)
        if (
            endpoint.scheme != "http"
            or endpoint.hostname != "127.0.0.1"
            or endpoint.port != 8888
            or endpoint.username
            or endpoint.password
            or endpoint.path not in {"", "/"}
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError("HexStrike URL must be exactly http://127.0.0.1:8888")
        if not job_create_token:
            raise ValueError("HexStrike job creation capability is required")
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("HexStrike timeout must be between 1 and 120 seconds")
        self.profiles, self.assets, self.policy = profiles, assets, policy
        self.job_create_token, self.kill_switch = job_create_token, kill_switch
        self.runs_root, self.base_url = Path(runs_root), base_url
        self.adapter = HexStrikeAdapter(base_url, timeout=float(timeout_seconds))
        self.last_job_id = ""
        self.last_job_status = ""
        self.last_evidence_id = ""
        self.last_trace_path = ""
        self.last_error = ""
        self.job_states: list[str] = []
        self.executions: list[dict[str, Any]] = []
        self.health_succeeded = False
        self.approval_authority = approval_authority
        self.approval_tokens = dict(approval_tokens or {})

    def health(self) -> bool:
        self.health_succeeded = self.adapter.health()
        return self.health_succeeded

    def execute(self, capability: Capability, run: RunContext) -> ExecutionResult:
        execution_id = f"execution:{len(self.executions) + 1}:{time.time_ns()}"
        created_at = datetime.now(timezone.utc).isoformat()
        allowed_bindings = {
            "network.service_discovery": "nmap",
            "ssh.posture_check": "ssh-posture",
            "rdp.posture_check": "rdp-posture",
            "smb.posture_check": "smb-posture",
        }
        if allowed_bindings.get(capability.capability_id) != capability.tool:
            return ExecutionResult(
                status="failed",
                parser_warnings=["live executor capability denied"],
                execution_id=execution_id,
                failure_stage="executor_mapping",
                structured_error={"code": "capability_tool_mismatch"},
                run_fatal=True,
            )
        run_dir = self.runs_root / run.run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        redactor = Redactor.from_assets(self.assets, redact_credentials=True)
        trace_path = run_dir / "trace.jsonl"
        trace_offset = trace_path.stat().st_size if trace_path.exists() else 0
        trace = TraceWriter(run.run_id, trace_path, redactor=redactor)
        self.last_trace_path = str(trace.path)
        context = AdapterRunContext(
            run_id=run.run_id,
            run_dir=run_dir,
            trace=trace,
            redactor=redactor,
            job_create_token=self.job_create_token,
            approval_authority=self.approval_authority,
            approval_token=self.approval_tokens.get(capability.capability_id, ""),
            kill_switch=self.kill_switch,
        )
        task = TaskSpec(
            id=run.run_id,
            category="live-host-assessment",
            task=run.task,
            allowed_tools=[capability.tool or ""],
            scoring=Scoring(success_predicate="real_hexstrike_job_succeeded"),
            tool_mode=CaseToolMode.REAL,
            asset_id=run.asset_id,
            profile_id=capability.profile_id or "",
        )
        step = execute_profile(
            self.adapter,
            self.profiles,
            self.assets,
            self.policy,
            run.asset_id,
            capability.profile_id or "",
            task,
            context,
        )
        # Correlate only events appended by this capability dispatch. Reading the
        # full run trace here was the source of cross-capability job/result reuse.
        with trace.path.open("r", encoding="utf-8") as stream:
            stream.seek(trace_offset)
            events = [json.loads(line) for line in stream.read().splitlines()]
        self.job_states = [str(item["job_status"]) for item in events if item.get("job_status")]
        error: dict[str, Any] = next(
            (item for item in reversed(events) if item.get("error_class")), {}
        )
        execution_error = str(error.get("text", ""))
        terminal: dict[str, Any] = next(
            (
                item
                for item in reversed(events)
                if item.get("job_status") in {"succeeded", "failed", "cancelled"}
            ),
            {},
        )
        created: dict[str, Any] = next(
            (item for item in events if item.get("state") == "job_created"), {}
        )
        job_id = str(created.get("job_id", ""))
        job_status = str(terminal.get("job_status", ""))
        result_event: dict[str, Any] = next(
            (item for item in reversed(events) if item.get("type") == "tool_result"), {}
        )
        digest = str(result_event.get("result_digest", ""))
        expected_profile = capability.profile_id or ""
        correlation_mismatch = bool(result_event) and (
            result_event.get("tool") != capability.tool
            or result_event.get("profile_id") != expected_profile
        )
        correlation_mismatch = correlation_mismatch or "correlation mismatch" in execution_error
        succeeded = (
            step.state is ExecutionState.VERIFIED
            and job_status == "succeeded"
            and bool(job_id and digest)
            and not correlation_mismatch
        )
        evidence_id = ""
        if succeeded:
            execution_error = ""
            evidence_id = (
                "evidence:hexstrike:"
                + hashlib.sha256(
                    f"{run.run_id}:{execution_id}:{job_id}:{digest}".encode()
                ).hexdigest()
            )
        else:
            # Never fall back to AgentResult.final_output on a failed dispatch: an
            # adapter instance may have prior output. Current trace events are the
            # authoritative execution-local diagnostic source.
            diagnostic = str(result_event.get("diagnostic_output", ""))
            execution_error = redactor.text(diagnostic)[:2000] or execution_error
            if correlation_mismatch:
                execution_error = "terminal result correlation mismatch"
            if not execution_error and result_event.get("return_code") is not None:
                execution_error = (
                    f"HexStrike execution failed: return_code={result_event['return_code']}"
                )
        failure_stage = None
        if not succeeded:
            failure_stage = (
                "result_correlation"
                if correlation_mismatch
                else "job_create"
                if not job_id
                else "job_poll_or_execution"
            )
        job_state_sequence = [str(item["job_status"]) for item in events if item.get("job_status")]
        structured_error: dict[str, Any] | None = (
            {"code": "result_correlation_mismatch"}
            if correlation_mismatch
            else (
                {"code": str(error.get("error_class", "execution_failed"))}
                if not succeeded
                else None
            )
        )
        summary: dict[str, Any] = {
            "run_id": run.run_id,
            "asset_id": run.asset_id,
            "capability_id": capability.capability_id,
            "execution_id": execution_id,
            "profile_id": expected_profile,
            "tool_identifier": capability.tool,
            "endpoint": f"/api/jobs/{capability.tool}",
            "policy_decision_reference": hashlib.sha256(
                f"{run.run_id}:{execution_id}:{capability.capability_id}:{expected_profile}".encode()
            ).hexdigest(),
            "created_at": created_at,
            "job_id": job_id,
            "job_state_sequence": job_state_sequence,
            "job_status": job_status,
            "observation_status": "succeeded" if succeeded else "failed",
            "evidence_ids": [evidence_id] if evidence_id else [],
            "failure_stage": failure_stage,
            "structured_error": structured_error,
        }
        self.executions.append(summary)
        self.last_job_id, self.last_job_status = job_id, job_status
        self.job_states = job_state_sequence
        self.last_evidence_id, self.last_error = evidence_id, execution_error
        return ExecutionResult(
            status="succeeded" if succeeded else "failed",
            output=str(result_event.get("diagnostic_output", "")) if succeeded else "",
            facts=(
                [
                    Fact(type="scanned_port", values={"port": int(port), "protocol": "tcp"})
                    for port in SERVICE_DISCOVERY_PORTS.split(",")
                ]
                if succeeded and capability.capability_id == "network.service_discovery"
                else [
                    Fact(
                        type="posture_check_completed",
                        values={
                            "capability_id": capability.capability_id,
                            "negative_result_evidenced": True,
                        },
                    )
                ]
                if succeeded
                else []
            ),
            evidence_ids=[evidence_id] if succeeded else [],
            evidence_types={
                "real_hexstrike_nmap_result"
                if capability.capability_id == "network.service_discovery"
                else "real_hexstrike_posture_result"
            }
            if succeeded
            else set(),
            parser_warnings=[]
            if succeeded
            else [execution_error or "live HexStrike execution failed"],
            execution_id=execution_id,
            failure_stage=failure_stage,
            structured_error=structured_error,
            run_fatal=correlation_mismatch,
        )
