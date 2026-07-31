"""Closed T3-C controlled-impact proof for the isolated research lab."""

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

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from core.artifacts import ArtifactSealAuthority
from core.safety import ApprovalAuthority, KillSwitch
from core.t3.poc_authorization import issue_poc_authorization_id

ACTION_ID = "t3c.controlled_impact_proof.v1"
STAGE = "T3-C"
MAX_HOPS = 1
MAX_CALLS = 1
TIMEOUT_SECONDS = 15
OUTPUT_LIMIT = 4096


class T3CConfig(BaseModel):
    """Protected operator configuration; Agent-facing objects never contain these fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    assurance_profile: str
    scenario_id: str
    source_asset_id: str
    source_target: str
    destination_asset_id: str | None = None
    destination_target: str | None = None
    credential_ref: str
    proof_marker: str = Field(min_length=8, max_length=128)
    rollback_checkpoint: str = Field(min_length=1, max_length=256)
    evidence_root: str
    hexstrike_url: HttpUrl
    executor_type: str
    allowlisted_targets: tuple[str, ...]
    denied_networks: tuple[str, ...]
    isolated_lab: bool
    rollback_ready: bool

    @field_validator("assurance_profile")
    @classmethod
    def poc_only(cls, value: str) -> str:
        if value != "poc":
            raise ValueError("real T3-C requires protected poc profile")
        return value

    @field_validator("executor_type")
    @classmethod
    def approved_executor(cls, value: str) -> str:
        if value != "hexstrike_t3c_v1":
            raise ValueError("approved T3-C executor required")
        return value

    @field_validator("hexstrike_url")
    @classmethod
    def loopback_hexstrike(cls, value: HttpUrl) -> HttpUrl:
        if str(value).rstrip("/") != "http://127.0.0.1:8888":
            raise ValueError("HexStrike must use http://127.0.0.1:8888")
        return value

    @model_validator(mode="after")
    def two_asset_scenario_is_explicit(self) -> T3CConfig:
        if self.scenario_id != "lab.synthetic-marker.v1":
            raise ValueError("unknown T3-C scenario")
        if not self.destination_asset_id or not self.destination_target:
            raise ValueError(
                "lab.synthetic-marker.v1 requires a separately approved destination asset"
            )
        if self.source_asset_id == self.destination_asset_id:
            raise ValueError("T3-C source and destination assets must be distinct")
        if self.source_target == self.destination_target:
            raise ValueError("T3-C source and destination targets must be distinct")
        return self


class T3CAgentProposal(BaseModel):
    """The complete Agent surface: it may request only the canonical action."""

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
    scenario_id: str
    source_asset_id: str
    destination_asset_id: str | None
    authorization_id: str
    prerequisite_digest: str
    proof_marker: str
    timeout_seconds: int = TIMEOUT_SECONDS
    output_limit: int = OUTPUT_LIMIT
    max_calls: int = MAX_CALLS
    max_hops: int = MAX_HOPS


@dataclass(frozen=True)
class T3CExecutorResult:
    proof_output: str
    cleanup_succeeded: bool
    cleanup_evidence: str
    executor_type: str


class T3CExecutor(Protocol):
    invocation_count: int

    def run(self, plan: T3CPlan) -> T3CExecutorResult: ...


class MockT3CExecutor:
    """Deterministic, network-free acceptance seam."""

    def __init__(self, *, include_marker: bool = True):
        self.invocation_count = 0
        self.include_marker = include_marker

    def run(self, plan: T3CPlan) -> T3CExecutorResult:
        self.invocation_count += 1
        return T3CExecutorResult(
            proof_output=plan.proof_marker if self.include_marker else "marker-not-reached",
            cleanup_succeeded=True,
            cleanup_evidence="mock rollback verified",
            executor_type="offline_mock",
        )


class HexStrikeT3CExecutor:
    """Loopback-only adapter; HexStrike owns all connection and action parameters."""

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
            json={"authorization_id": plan.authorization_id, "canonical_action": ACTION_ID},
            timeout=plan.timeout_seconds,
        )
        response.raise_for_status()
        value = response.json()
        if set(value) != {
            "schema_version",
            "canonical_action",
            "scenario_id",
            "proof_output",
            "cleanup_succeeded",
            "cleanup_evidence",
        }:
            raise ValueError("invalid HexStrike T3-C response")
        return T3CExecutorResult(
            proof_output=str(value["proof_output"])[: plan.output_limit],
            cleanup_succeeded=value["cleanup_succeeded"] is True,
            cleanup_evidence=str(value["cleanup_evidence"])[:512],
            executor_type="hexstrike_t3c_v1",
        )


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def binding(config: T3CConfig, prerequisite_digest: str) -> str:
    value = {
        "action_id": ACTION_ID,
        "stage": STAGE,
        "scenario_id": config.scenario_id,
        "source_asset_id": config.source_asset_id,
        "destination_asset_id": config.destination_asset_id,
        "credential_ref_digest": hashlib.sha256(config.credential_ref.encode()).hexdigest(),
        "prerequisite_digest": prerequisite_digest,
        "limits": [MAX_HOPS, MAX_CALLS, TIMEOUT_SECONDS, OUTPUT_LIMIT],
        "rollback_checkpoint": config.rollback_checkpoint,
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def validate_readiness(
    config: T3CConfig,
    evidence_path: Path,
    *,
    seal_authority: ArtifactSealAuthority,
) -> str:
    if not config.isolated_lab or not config.rollback_ready:
        raise ValueError("isolated lab and rollback readiness are required")
    targets = tuple(x for x in (config.source_target, config.destination_target) if x)
    if not targets or set(targets) != set(config.allowlisted_targets):
        raise ValueError("targets must exactly match the approved lab configuration")
    if not config.denied_networks:
        raise ValueError("operator denied networks are required for T3-C")
    denied = tuple(ipaddress.ip_network(item, strict=False) for item in config.denied_networks)
    for target in targets:
        address = ipaddress.ip_address(target)
        if not address.is_private or address.is_loopback:
            raise ValueError(
                "T3-C requires private non-loopback addresses on an approved isolated network"
            )
        if any(address in net for net in denied):
            raise ValueError("T3-C target is in an operator-denied network")
    if not evidence_path.is_file():
        raise ValueError("T3-B prerequisite evidence is missing")
    if evidence_path.name != "result.json":
        raise ValueError("T3-B prerequisite must be a sealed result.json")
    seal_error = seal_authority.verify(evidence_path.parent)
    if seal_error:
        raise ValueError(f"T3-B prerequisite artifact verification failed: {seal_error}")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if evidence.get("stage") not in ("T3-B", "windows_enumeration") or not evidence.get(
        "completed"
    ):
        raise ValueError("T3-B prerequisite evidence is invalid")
    root = Path(config.evidence_root)
    root.mkdir(parents=True, exist_ok=True)
    probe = root / f".t3c-write-check-{uuid.uuid4().hex}"
    probe.touch(exist_ok=False)
    probe.unlink()
    return digest_file(evidence_path)


def run_t3c(
    *,
    proposal: T3CAgentProposal | dict[str, object],
    config: T3CConfig,
    prerequisite_path: Path,
    authority: ApprovalAuthority,
    approval_token: str,
    executor: T3CExecutor,
    kill_switch: KillSwitch,
) -> Path:
    """Consume a stage-specific approval, execute once, and verify marker plus cleanup."""
    proposal = T3CAgentProposal.model_validate(proposal)
    prerequisite_digest = validate_readiness(
        config,
        prerequisite_path,
        seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
    )
    fingerprint = binding(config, prerequisite_digest)
    run_id = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-t3c-{time.time_ns()}"
    run_dir = Path(config.evidence_root) / run_id
    run_dir.mkdir(mode=0o700)
    started = datetime.now(timezone.utc).isoformat()
    manifest = {
        "run_id": run_id,
        "assurance_profile": config.assurance_profile,
        "signed_permit_status": "SKIPPED_BY_PROFILE",
        "signed_permit_reason": "poc_profile",
        "stage": STAGE,
        "canonical_action_id": proposal.action_id,
        "authorization_fingerprint": fingerprint,
        "approved_asset_references": [
            item for item in (config.source_asset_id, config.destination_asset_id) if item
        ],
        "scenario_id": config.scenario_id,
        "prerequisite_evidence_digest": prerequisite_digest,
        "executor_type": "offline_mock"
        if isinstance(executor, MockT3CExecutor)
        else config.executor_type,
        "started_at": started,
        "production_ready": False,
        "aisvs_level_2_or_3_compliance_claimed": False,
    }
    trace: list[dict[str, object]] = []
    completed = consumed = invoked = marker_verified = cleanup = False
    rule = "t3c_denied"
    try:
        if kill_switch.engaged():
            rule = "kill_switch_engaged"
            raise ValueError(rule)
        trace.append({"event": "kill_switch_checked", "decision": "inactive"})
        authority.verify_and_consume(
            approval_token,
            config.source_asset_id,
            ACTION_ID,
            fingerprint,
            credential_id=config.credential_ref,
            action_fingerprint=fingerprint,
        )
        consumed = True
        authorization_id = issue_poc_authorization_id("T3-C")
        trace.append({"event": "authorization_consumed", "fingerprint": fingerprint})
        if kill_switch.engaged():
            rule = "kill_switch_engaged"
            raise ValueError(rule)
        outcome = executor.run(
            T3CPlan(
                config.scenario_id,
                config.source_asset_id,
                config.destination_asset_id,
                authorization_id,
                prerequisite_digest,
                config.proof_marker,
            )
        )
        invoked = True
        marker_verified = config.proof_marker in outcome.proof_output
        cleanup = outcome.cleanup_succeeded and bool(outcome.cleanup_evidence)
        completed = marker_verified and cleanup
        rule = "t3c_proof_verified" if completed else "t3c_proof_not_verified"
        trace.append({"event": "proof_marker_verification", "verified": marker_verified})
        trace.append({"event": "cleanup_verification", "verified": cleanup})
    except Exception as exc:
        if rule == "t3c_denied":
            rule = "t3c_approval_invalid" if not consumed else "t3c_execution_failed"
        trace.append({"event": "execution_denied", "rule": rule, "error": type(exc).__name__})
    ended = datetime.now(timezone.utc).isoformat()
    manifest["ended_at"] = ended
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (run_dir / "trace.jsonl").write_text(
        "".join(
            json.dumps({"run_id": run_id, "seq": i, **item}) + "\n" for i, item in enumerate(trace)
        ),
        encoding="utf-8",
    )
    result = {
        "run_id": run_id,
        "stage": STAGE,
        "canonical_action_id": ACTION_ID,
        "assurance_profile": config.assurance_profile,
        "signed_permit_status": "SKIPPED_BY_PROFILE",
        "signed_permit_reason": "poc_profile",
        "approval_decision": "approved" if consumed else "denied",
        "authorization_consumed": consumed,
        "executor_invoked": invoked,
        "completed": completed,
        "rule": rule,
        "proof_marker_verified": marker_verified,
        "cleanup_or_rollback_verified": cleanup,
        "production_ready": False,
        "aisvs_level_2_or_3_compliance_claimed": False,
    }
    (run_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return run_dir
