"""Single-asset reversible T3-C controlled-impact orchestration."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, HttpUrl, field_validator, model_validator

from core.artifacts import ArtifactSealAuthority
from core.safety import ApprovalAuthority, KillSwitch
from core.t3.poc_authorization import issue_poc_authorization_id

ACTION_ID = "t3c.controlled_impact_proof.v1"
SCENARIO_ID = "lab.synthetic-marker.v2"
STAGE = "T3-C"
MAX_CALLS = 6
TIMEOUT_SECONDS = 60


class T3CConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    assurance_profile: str
    scenario_id: str
    asset_id: str
    target: str
    credential_ref: str
    marker_path: str
    marker_content_sha256: str
    evidence_root: str
    hexstrike_url: HttpUrl
    executor_type: str
    allowlisted_targets: tuple[str, ...]
    denied_networks: tuple[str, ...]
    cleanup_required: bool
    rollback_verification_required: bool
    maximum_duration_seconds: int
    maximum_tool_calls: int
    isolated_lab_ready: bool

    @field_validator("assurance_profile")
    @classmethod
    def poc_only(cls, value: str) -> str:
        if value != "poc":
            raise ValueError("protected poc assurance profile required")
        return value

    @field_validator("executor_type")
    @classmethod
    def fixed_executor(cls, value: str) -> str:
        if value != "hexstrike_t3c_v2":
            raise ValueError("approved fixed T3-C executor required")
        return value

    @field_validator("hexstrike_url")
    @classmethod
    def loopback_only(cls, value: HttpUrl) -> HttpUrl:
        if str(value).rstrip("/") != "http://127.0.0.1:8888":
            raise ValueError("HexStrike must use loopback endpoint")
        return value

    @model_validator(mode="after")
    def fixed_contract(self) -> T3CConfig:
        if self.scenario_id != SCENARIO_ID:
            raise ValueError("unknown T3-C scenario")
        if self.asset_id != "asset:winsrv2025-01":
            raise ValueError("unapproved T3-C asset")
        if (
            not self.cleanup_required
            or not self.rollback_verification_required
            or not self.isolated_lab_ready
        ):
            raise ValueError("cleanup, rollback verification, and isolated lab readiness required")
        if self.maximum_duration_seconds != TIMEOUT_SECONDS or self.maximum_tool_calls != MAX_CALLS:
            raise ValueError("fixed T3-C execution limits required")
        if len(self.marker_content_sha256) != 64 or any(
            c not in "0123456789abcdef" for c in self.marker_content_sha256
        ):
            raise ValueError("marker digest must be lowercase SHA-256")
        return self


class T3CAgentProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_id: str

    @field_validator("action_id")
    @classmethod
    def canonical_action(cls, value: str) -> str:
        if value != ACTION_ID:
            raise ValueError("unknown T3-C action")
        return value


@dataclass(frozen=True)
class T3CPlan:
    authorization_id: str
    canonical_action: str = ACTION_ID
    timeout_seconds: int = TIMEOUT_SECONDS


@dataclass(frozen=True)
class T3CExecutorResult:
    status: str
    marker_absent_preflight: bool
    marker_created: bool
    proof_verified: bool
    cleanup_completed: bool
    rollback_verified: bool
    connector_invoked: bool
    operator_warning: str | None = None


class T3CExecutor(Protocol):
    invocation_count: int

    def run(self, plan: T3CPlan) -> T3CExecutorResult: ...


class MockT3CExecutor:
    def __init__(self, result: T3CExecutorResult | None = None):
        self.invocation_count = 0
        self.result = result or T3CExecutorResult("succeeded", True, True, True, True, True, True)

    def run(self, plan: T3CPlan) -> T3CExecutorResult:
        self.invocation_count += 1
        return self.result


class HexStrikeT3CExecutor:
    def __init__(self, base_url: str = "http://127.0.0.1:8888"):
        if base_url.rstrip("/") != "http://127.0.0.1:8888":
            raise ValueError("loopback HexStrike endpoint required")
        self.base_url = base_url.rstrip("/")
        self.invocation_count = 0

    def run(self, plan: T3CPlan) -> T3CExecutorResult:
        import requests

        self.invocation_count += 1
        response = requests.post(
            f"{self.base_url}/api/v1/t3c/executions",
            json={
                "authorization_id": plan.authorization_id,
                "canonical_action": plan.canonical_action,
            },
            timeout=plan.timeout_seconds,
        )
        value = response.json()
        expected = {
            "schema_version",
            "canonical_action",
            "scenario_id",
            "status",
            "marker_absent_preflight",
            "marker_created",
            "proof_verified",
            "cleanup_completed",
            "rollback_verified",
            "connector_invoked",
            "operator_warning",
        }
        if set(value) != expected:
            response.raise_for_status()
            raise ValueError("invalid HexStrike T3-C response")
        return T3CExecutorResult(
            **{key: value[key] for key in T3CExecutorResult.__dataclass_fields__}
        )


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sealed_stage(
    path: Path, stages: tuple[str, ...], authority: ArtifactSealAuthority
) -> dict[str, object]:
    if path.name != "result.json" or not path.is_file():
        raise ValueError("prerequisite sealed result.json is missing")
    error = authority.verify(path.parent)
    if error:
        raise ValueError("prerequisite artifact verification failed")
    value = json.loads(path.read_text(encoding="utf-8"))
    completed = value.get("completed") is True or value.get("status") in {"completed", "verified"}
    if value.get("stage") not in stages or not completed:
        raise ValueError("prerequisite result unsuccessful")
    return value


def validate_readiness(
    config: T3CConfig, t3a_path: Path, t3b_path: Path, *, seal_authority: ArtifactSealAuthority
) -> tuple[str, str]:
    address = ipaddress.ip_address(config.target)
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise ValueError("registered T3-C target is in a forbidden address class")
    if config.allowlisted_targets != (config.target,) or not config.denied_networks:
        raise ValueError("exact single-target allowlist and denied networks required")
    if any(address in ipaddress.ip_network(net, strict=False) for net in config.denied_networks):
        raise ValueError("T3-C target is operator-denied")
    t3a = _sealed_stage(t3a_path, ("T3-A", "initial_access", "authorized_access"), seal_authority)
    t3a_digest = digest_file(t3a_path)
    t3b = _sealed_stage(t3b_path, ("T3-B", "windows_enumeration"), seal_authority)
    t3a_manifest = json.loads((t3a_path.parent / "manifest.json").read_text(encoding="utf-8"))
    expected_ref = f"t3a-run:{t3a_manifest.get('run_id')}"
    expected_fingerprint = hashlib.sha256(
        (t3a_path.parent / "trace.jsonl").read_bytes()
    ).hexdigest()
    if (
        t3a.get("asset_id") != config.asset_id
        or t3b.get("prerequisite_evidence_ref") != expected_ref
        or t3b.get("prerequisite_evidence_fingerprint") != expected_fingerprint
    ):
        raise ValueError("T3-B evidence binding mismatch")
    root = Path(config.evidence_root)
    root.mkdir(parents=True, exist_ok=True)
    probe = root / f".t3c-write-check-{uuid.uuid4().hex}"
    probe.touch(exist_ok=False)
    probe.unlink()
    return t3a_digest, digest_file(t3b_path)


def binding(config: T3CConfig, t3a_digest: str, t3b_digest: str) -> str:
    value = {
        "action_id": ACTION_ID,
        "stage": STAGE,
        "scenario_id": config.scenario_id,
        "asset_id": config.asset_id,
        "credential_ref_digest": hashlib.sha256(config.credential_ref.encode()).hexdigest(),
        "t3a_digest": t3a_digest,
        "t3b_digest": t3b_digest,
        "marker_path_digest": hashlib.sha256(config.marker_path.encode()).hexdigest(),
        "marker_content_sha256": config.marker_content_sha256,
        "limits": [MAX_CALLS, TIMEOUT_SECONDS],
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run_t3c(
    *,
    proposal: T3CAgentProposal | dict[str, object],
    config: T3CConfig,
    t3a_path: Path,
    t3b_path: Path,
    authority: ApprovalAuthority,
    approval_token: str,
    executor: T3CExecutor,
    kill_switch: KillSwitch,
) -> Path:
    proposal = T3CAgentProposal.model_validate(proposal)
    t3a_digest, t3b_digest = validate_readiness(
        config,
        t3a_path,
        t3b_path,
        seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
    )
    fingerprint = binding(config, t3a_digest, t3b_digest)
    run_id = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-t3c-{time.time_ns()}"
    run_dir = Path(config.evidence_root) / run_id
    run_dir.mkdir(mode=0o700)
    trace: list[dict[str, object]] = []
    consumed = invoked = completed = False
    outcome = T3CExecutorResult("precondition_failed", False, False, False, False, False, False)
    rule = "precondition_failed"
    try:
        if kill_switch.engaged():
            raise ValueError("kill_switch_engaged")
        authority.verify_and_consume(
            approval_token,
            config.asset_id,
            ACTION_ID,
            fingerprint,
            credential_id=config.credential_ref,
            action_fingerprint=fingerprint,
        )
        consumed = True
        authorization_id = issue_poc_authorization_id(STAGE)
        trace.append({"event": "t3c_authorization_accepted", "fingerprint": fingerprint})
        if kill_switch.engaged():
            raise ValueError("kill_switch_engaged")
        outcome = executor.run(T3CPlan(authorization_id))
        invoked = True
        completed = (
            outcome.status == "succeeded"
            and outcome.marker_absent_preflight
            and outcome.marker_created
            and outcome.proof_verified
            and outcome.cleanup_completed
            and outcome.rollback_verified
        )
        rule = "succeeded" if completed else outcome.status
    except Exception as exc:
        rule = (
            "authorization_rejected"
            if not consumed and str(exc) != "kill_switch_engaged"
            else str(exc)
            if str(exc) == "kill_switch_engaged"
            else "create_failed"
        )
        trace.append({"event": "execution_denied", "rule": rule, "error": type(exc).__name__})
    for event, verified in (
        ("marker_absence_preflight", outcome.marker_absent_preflight),
        ("marker_created", outcome.marker_created),
        ("proof_verified", outcome.proof_verified),
        ("cleanup_completed", outcome.cleanup_completed),
        ("rollback_verified", outcome.rollback_verified),
    ):
        trace.append({"event": event, "verified": verified})
    manifest = {
        "run_id": run_id,
        "stage": STAGE,
        "canonical_action_id": proposal.action_id,
        "scenario_id": config.scenario_id,
        "approved_asset_references": [config.asset_id],
        "t3a_evidence_digest": t3a_digest,
        "t3b_evidence_digest": t3b_digest,
        "authorization_fingerprint": fingerprint,
        "executor_type": "offline_mock"
        if isinstance(executor, MockT3CExecutor)
        else config.executor_type,
        "production_ready": False,
        "aisvs_conformity_claimed": False,
    }
    result = {
        "run_id": run_id,
        "stage": STAGE,
        "completed": completed,
        "status": rule,
        "rule": rule,
        "approval_decision": "approved" if consumed else "denied",
        "authorization_consumed": consumed,
        "executor_invoked": invoked,
        "marker_absent_preflight": outcome.marker_absent_preflight,
        "marker_created": outcome.marker_created,
        "proof_verified": outcome.proof_verified,
        "cleanup_completed": outcome.cleanup_completed,
        "rollback_verified": outcome.rollback_verified,
        "operator_warning": outcome.operator_warning,
        "production_ready": False,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (run_dir / "trace.jsonl").write_text(
        "".join(
            json.dumps({"run_id": run_id, "seq": i, **item}) + "\n" for i, item in enumerate(trace)
        ),
        encoding="utf-8",
    )
    (run_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return run_dir
