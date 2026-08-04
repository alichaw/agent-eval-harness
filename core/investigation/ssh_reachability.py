"""Canonical Windows SSH/22 reachability state production."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from core.investigation.models import InvestigationState
from core.investigation.recorder import record_step_result
from core.policy import ActionRequest, Policy, Verdict
from core.profiles import AssetRegistry, ProfileCatalog
from core.redaction import Redactor
from core.safety import KillSwitch
from core.schemas.models import TraceEventType
from core.trace.writer import TraceWriter

CAPABILITY_ID = "windows.ssh.reachability"
PROFILE_ID = "windows-ssh-reachability-check"
TOOL_ID = "t3-ssh-reachability"
ACTION_ID = "t3a.ssh22_reachability.v1"
AUTHORIZED_ASSET_ID = "asset:winsrv2025-01"
PORT = 22
TIMEOUT_SECONDS = 5


class SshReachabilityDiagnostic(RuntimeError):
    """Sanitized local diagnostic that never carries target or response content."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def target_binding(asset_id: str, target: str, port: int = PORT) -> str:
    return hashlib.sha256(f"{asset_id}\0{target}\0{port}".encode()).hexdigest()


@dataclass(frozen=True)
class SshReachabilityResult:
    asset_id: str
    port: int
    protocol: str
    service: str
    state: str
    target_binding: str = ""


class SshReachabilityExecutor(Protocol):
    invocation_count: int

    def probe(self, asset_id: str) -> SshReachabilityResult: ...


class HexStrikeSshReachabilityExecutor:
    """Loopback adapter exposing no target, port, command, or credential input."""

    def __init__(self, base_url: str = "http://127.0.0.1:8888"):
        if base_url.rstrip("/") != "http://127.0.0.1:8888":
            raise ValueError("loopback HexStrike endpoint required")
        self.base_url = base_url.rstrip("/")
        self.invocation_count = 0

    def probe(self, asset_id: str) -> SshReachabilityResult:
        import requests

        self.invocation_count += 1
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/t3/ssh-reachability",
                json={"action_id": ACTION_ID, "asset_id": asset_id},
                timeout=TIMEOUT_SECONDS + 1,
            )
        except requests.RequestException as exc:
            raise SshReachabilityDiagnostic("reachability_connection_error") from exc
        if not 200 <= response.status_code < 300:
            raise SshReachabilityDiagnostic("reachability_http_error")
        try:
            value = response.json()
        except (TypeError, ValueError) as exc:
            raise SshReachabilityDiagnostic("reachability_response_schema_invalid") from exc
        required = {
            "schema_version",
            "action_id",
            "asset_id",
            "port",
            "protocol",
            "service",
            "state",
            "target_binding",
        }
        if (
            not isinstance(value, dict)
            or set(value) != required
            or value.get("schema_version") != "hexstrike-t3-ssh-reachability/v1"
            or value.get("action_id") != ACTION_ID
            or value.get("asset_id") != asset_id
            or value.get("port") != PORT
            or value.get("protocol") != "tcp"
            or value.get("service") != "ssh"
            or value.get("state") not in {"reachable", "unreachable", "error"}
            or not isinstance(value.get("target_binding"), str)
        ):
            raise SshReachabilityDiagnostic("reachability_response_schema_invalid")
        return SshReachabilityResult(
            asset_id=value["asset_id"],
            port=value["port"],
            protocol=value["protocol"],
            service=value["service"],
            state=value["state"],
            target_binding=value["target_binding"],
        )


def produce_ssh_reachability_state(
    *,
    asset_id: str,
    assets_path: str | Path,
    profiles_path: str | Path,
    policy_path: str | Path,
    runs_root: str | Path,
    executor: SshReachabilityExecutor,
    kill_switch: KillSwitch,
    assurance_profile: str = "hardened",
) -> Path:
    """Produce one auditable InvestigationState using the canonical state transition."""

    if asset_id != AUTHORIZED_ASSET_ID:
        raise ValueError("asset is not authorized for the T3 SSH reachability probe")
    assets = AssetRegistry.from_yaml(assets_path)
    asset = assets.resolve(asset_id)
    if (
        asset.get("asset_type") != "host"
        or asset.get("execution_scope") != "isolated_lab"
        or asset.get("platform") != "windows_openssh"
        or asset.get("ssh_port") != PORT
    ):
        raise ValueError("approved Windows OpenSSH lab asset required")
    profile = ProfileCatalog.from_yaml(profiles_path).get(PROFILE_ID)
    if (
        profile.tool_id != TOOL_ID
        or profile.approval_required
        or profile.parameters != {"action_id": ACTION_ID, "port": PORT}
        or profile.allowed_asset_types != ["host"]
    ):
        raise ValueError("canonical SSH reachability profile invalid")
    target = asset.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("registered target required")
    target = target.strip()
    expected_target_binding = target_binding(asset_id, target)
    policy = Policy.from_yaml(policy_path)
    if assurance_profile not in {"poc", "hardened"}:
        raise ValueError("known assurance profile required")
    registered_poc_targets = [
        value.get("target")
        for _, value in assets.items()
        if value.get("asset_type") == "host"
        and value.get("execution_scope") == "isolated_lab"
        and value.get("platform") == "windows_openssh"
        and value.get("ssh_port") == PORT
        and isinstance(value.get("target"), str)
        and value.get("target", "").strip()
    ]
    if not policy.denied_targets and (
        assurance_profile != "poc"
        or policy.default != "deny"
        or registered_poc_targets != [target]
    ):
        raise ValueError("operator denied-target CIDRs are required")
    decision = policy.check(ActionRequest(tool=TOOL_ID, target=target))
    if decision.verdict is not Verdict.ALLOW:
        raise ValueError(f"SSH reachability policy denied: {decision.rule}")
    if kill_switch.engaged():
        raise ValueError("kill switch engaged")

    run_id = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-t3-state-{time.time_ns()}"
    root = Path(runs_root) / run_id
    root.mkdir(mode=0o700, parents=True)
    redactor = Redactor.from_assets(assets)
    trace = TraceWriter(run_id, root / "trace.jsonl", redactor=redactor)
    state = InvestigationState(
        investigation_id=f"investigation-{uuid.uuid4().hex}",
        asset_id=asset_id,
        objective="Establish canonical TCP/22 SSH reachability evidence for bounded T3-A",
    )
    started = datetime.now(timezone.utc)
    diagnostic_code = "none"
    trace.emit(
        TraceEventType.POLICY_EVENT,
        rule=decision.rule,
        verdict=decision.verdict.value,
        asset_id=asset_id,
        profile_id=PROFILE_ID,
        action_id=ACTION_ID,
        text="Canonical Windows SSH/22 reachability admitted",
    )
    trace.emit(
        TraceEventType.TOOL_CALL,
        tool=TOOL_ID,
        asset_id=asset_id,
        profile_id=PROFILE_ID,
        action_id=ACTION_ID,
        command_id=ACTION_ID,
        attempted=True,
        executed=True,
        text="Fixed TCP/22 reachability probe invoked",
    )
    try:
        if kill_switch.engaged():
            raise ValueError("kill switch engaged")
        result = executor.probe(asset_id)
        if result.target_binding != expected_target_binding:
            raise SshReachabilityDiagnostic("reachability_target_binding_mismatch")
        if (
            result.asset_id != asset_id
            or result.port != PORT
            or result.protocol != "tcp"
            or result.service not in {"ssh", "openssh"}
            or result.state not in {"reachable", "unreachable", "error"}
        ):
            raise SshReachabilityDiagnostic("reachability_response_schema_invalid")
        if result.state == "error":
            raise SshReachabilityDiagnostic("reachability_connector_error")
        reachable = result.state == "reachable"
        facts = {
            "port": PORT,
            "open_ports": [PORT] if reachable else [],
            "protocol": "tcp",
            "service": "ssh",
            "state": result.state,
        }
        state = record_step_result(
            state,
            capability_id=CAPABILITY_ID,
            profile_id=PROFILE_ID,
            tool_name=TOOL_ID,
            admitted=True,
            verified=reachable,
            output=json.dumps(facts, sort_keys=True),
            verdict=decision.verdict.value,
            run_id=run_id,
            action_id=ACTION_ID,
            observed_at=started,
            facts=facts,
        )
        rule = "ssh22_reachable" if reachable else "ssh22_unreachable"
        trace.emit(
            TraceEventType.TOOL_RESULT,
            tool=TOOL_ID,
            asset_id=asset_id,
            profile_id=PROFILE_ID,
            action_id=ACTION_ID,
            command_id=ACTION_ID,
            attempted=True,
            executed=True,
            return_code=0 if reachable else 1,
            outcome="succeeded" if reachable else "failed",
            evidence_predicate_passed=reachable,
            result_digest=hashlib.sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest(),
            text=rule,
        )
    except Exception as exc:
        diagnostic_code = (
            exc.code
            if isinstance(exc, SshReachabilityDiagnostic)
            else "reachability_internal_error"
        )
        facts = {
            "port": PORT,
            "open_ports": [],
            "protocol": "tcp",
            "service": "ssh",
            "state": "error",
        }
        state = record_step_result(
            state,
            capability_id=CAPABILITY_ID,
            profile_id=PROFILE_ID,
            tool_name=TOOL_ID,
            admitted=True,
            verified=False,
            output=json.dumps(facts, sort_keys=True),
            verdict=decision.verdict.value,
            run_id=run_id,
            action_id=ACTION_ID,
            observed_at=started,
            facts=facts,
        )
        rule = "ssh22_probe_error"
        trace.emit(
            TraceEventType.ERROR,
            rule=rule,
            asset_id=asset_id,
            profile_id=PROFILE_ID,
            action_id=ACTION_ID,
            error_class="ReachabilityProbeError",
            text="Canonical SSH/22 reachability probe failed closed",
        )

    completed = CAPABILITY_ID in state.executed_capabilities
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "created_utc": started.isoformat(),
                "agent": "canonical-state-producer",
                "asset_id": asset_id,
                "profile_id": PROFILE_ID,
                "action_id": ACTION_ID,
                "target_binding": expected_target_binding,
                "network_scope": "one registered target, TCP/22 only",
                "credential_resolved": False,
                "ssh_login_attempted": False,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / "investigation_state.json").write_text(
        state.model_dump_json(indent=2), encoding="utf-8"
    )
    (root / "result.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "asset_id": asset_id,
                "profile_id": PROFILE_ID,
                "completed": completed,
                "status": "verified" if completed else "failed",
                "rule": rule,
                "diagnostic_code": diagnostic_code,
                "credential_resolved": False,
                "ssh_login_attempted": False,
                "production_ready": False,
                "aisvs_level_2_or_3_compliance_claimed": False,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return root
