"""Offline negative regressions for T3-B authorization and audit integrity."""

from __future__ import annotations

import base64
import ipaddress
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from core.replay import validate_run_artifacts
from core.safety import ApprovalAuthority, ApprovalError, KillSwitch
from core.schemas.models import ToolMode, TraceEventType
from core.t3.binding import RuntimeBinding
from core.t3.enumeration import (
    T3B_PROFILE,
    ExecutionMode,
    T3BExecutor,
    WindowsActionId,
    _ParamikoT3BSession,
    load_t3a_prerequisite,
)
from core.t3.enumeration_runtime import (
    T3BComposition,
    execute_t3b_composition,
    validate_prerequisite_freshness,
)
from core.trace.writer import TraceWriter
from tests.test_t3_enumeration import (
    FakeResolver,
    FakeSession,
    FakeTransport,
    plan,
    prerequisite,
    proposal,
    result,
)


def _valid_t3a(tmp_path):
    run_id = "fixture-t3a"
    root = tmp_path / run_id
    root.mkdir(parents=True)
    created = datetime.now(timezone.utc).isoformat()
    (root / "manifest.json").write_text(
        json.dumps({"run_id": run_id, "created_utc": created, "schema_version": "v1"})
    )
    trace = TraceWriter(run_id, root / "trace.jsonl")
    trace.emit(
        TraceEventType.POLICY_EVENT,
        rule="t3_approval_required",
        verdict="require_approval",
    )
    trace.emit(
        TraceEventType.POLICY_EVENT,
        rule="t3_approval_verified",
        verdict="allow",
    )
    trace.emit(
        TraceEventType.EXECUTION_STATE,
        state="approved",
        approval_fingerprint="approved",
    )
    trace.emit(
        TraceEventType.POLICY_EVENT,
        rule="credential_lease_created",
        verdict="allow",
    )
    trace.emit(
        TraceEventType.POLICY_EVENT,
        rule="authentication_succeeded",
        verdict="allow",
    )
    for command in ("host_identity", "current_identity", "privilege_context"):
        action_id = f"t3a:{command}"
        trace.emit(
            TraceEventType.TOOL_CALL,
            tool="t3-fixed-observation",
            command_id=command,
            action_id=action_id,
            asset_id="asset-1",
            profile_id="t3-authorized-access-bounded",
            executed=True,
            mode=ToolMode.REAL,
            approval_fingerprint="approved",
        )
        trace.emit(
            TraceEventType.TOOL_RESULT,
            tool="t3-fixed-observation",
            command_id=command,
            action_id=action_id,
            asset_id="asset-1",
            profile_id="t3-authorized-access-bounded",
            executed=True,
            mode=ToolMode.REAL,
            return_code=0,
            outcome="succeeded",
            evidence_predicate_passed=True,
            result_digest="d" * 64,
        )
    for rule in ("session_closed", "credential_lease_invalidated", "cleanup_result"):
        trace.emit(TraceEventType.POLICY_EVENT, rule=rule, verdict="allow")
    (root / "result.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "asset_id": "asset-1",
                "profile_id": "t3-authorized-access-bounded",
                "stage": "authorized_access",
                "runtime_binding_fingerprint": "a" * 64,
                "completed": True,
                "status": "completed",
                "replayed": False,
                "approval_consumed": True,
                "real_action_performed": True,
                "lab_outcome": {
                    "asset_id": "asset-1",
                    "completed": True,
                    "assessment_succeeded": True,
                    "authentication_succeeded": True,
                    "session_closed": True,
                    "cleanup_succeeded": True,
                    "credential_lease_invalidated": True,
                },
            }
        )
    )
    return root


@pytest.mark.parametrize("mutation", ["event", "digest", "foreign_run", "duplicate", "gap"])
def test_modified_t3a_artifacts_are_rejected(tmp_path, mutation):
    root = _valid_t3a(tmp_path)
    lines = (root / "trace.jsonl").read_text().splitlines()
    event = json.loads(lines[4])
    if mutation == "event":
        event["rule"] = "modified"
    elif mutation == "digest":
        event["previous_digest"] = "0" * 64
    elif mutation == "foreign_run":
        event["run_id"] = "foreign"
    elif mutation == "duplicate":
        event["seq"] = 3
    else:
        event["seq"] = 9
    lines[4] = json.dumps(event)
    (root / "trace.jsonl").write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="prerequisite rejected"):
        load_t3a_prerequisite(root)


def test_manifest_result_trace_mismatch_and_truncation_fail_closed(tmp_path):
    root = _valid_t3a(tmp_path)
    result_doc = json.loads((root / "result.json").read_text())
    result_doc["run_id"] = "other"
    (root / "result.json").write_text(json.dumps(result_doc))
    assert validate_run_artifacts(root).code == "artifact_run_id_mismatch"

    root = _valid_t3a(tmp_path / "second")
    raw = (root / "trace.jsonl").read_bytes()
    (root / "trace.jsonl").write_bytes(raw[:-3])
    assert validate_run_artifacts(root).code == "malformed_or_truncated_artifacts"


@pytest.mark.parametrize(
    "field,value",
    [
        ("asset_id", ""),
        ("profile_id", "windows-host-enumeration-readonly"),
        ("stage", "windows_enumeration"),
        ("status", "failed"),
        ("completed", False),
    ],
)
def test_wrong_t3a_result_binding_or_outcome_is_rejected(tmp_path, field, value):
    root = _valid_t3a(tmp_path)
    document = json.loads((root / "result.json").read_text())
    document[field] = value
    (root / "result.json").write_text(json.dumps(document))
    with pytest.raises(ValueError):
        load_t3a_prerequisite(root)


def test_valid_schema_compatible_t3a_fixture_is_accepted(tmp_path):
    prerequisite = load_t3a_prerequisite(_valid_t3a(tmp_path))
    assert prerequisite.verified
    assert prerequisite.stage == "authorized_access"


def test_prerequisite_freshness_boundaries_and_timezone_conversion():
    now = datetime(2026, 7, 30, tzinfo=timezone.utc)
    exactly_old = now - timedelta(seconds=3600)
    assert validate_prerequisite_freshness(
        exactly_old.isoformat(),
        proposal_time=now,
        max_age_seconds=3600,
        clock_skew_seconds=30,
    )
    assert validate_prerequisite_freshness(
        "2026-07-30T08:00:20+08:00",
        proposal_time=now,
        max_age_seconds=3600,
        clock_skew_seconds=30,
    )
    with pytest.raises(ValueError, match="stale"):
        validate_prerequisite_freshness(
            (exactly_old - timedelta(microseconds=1)).isoformat(),
            proposal_time=now,
            max_age_seconds=3600,
            clock_skew_seconds=30,
        )
    with pytest.raises(ValueError, match="after"):
        validate_prerequisite_freshness(
            (now + timedelta(seconds=31)).isoformat(),
            proposal_time=now,
            max_age_seconds=3600,
            clock_skew_seconds=30,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        validate_prerequisite_freshness(
            "2026-07-30T00:00:00",
            proposal_time=now,
            max_age_seconds=3600,
            clock_skew_seconds=30,
        )


def _runtime_binding() -> RuntimeBinding:
    return RuntimeBinding(
        asset_id="asset-1",
        target_identity="target-id",
        host="example.invalid",
        port=22,
        credential_ref="credential:fixture",
        principal="fixture-user",
        host_key_algorithm="ssh-ed25519",
        host_key_fingerprint="host-key-digest",
        transport_type="ssh_paramiko",
        runtime_config_digest="runtime-digest",
        asset_registry_digest="asset-digest",
        policy_digest="policy-digest",
        profile_digest="profile-digest",
        prerequisite_stage="authorized_access",
        prerequisite_capability="t3-authorized-access-bounded",
        session_limits_digest="limits-digest",
        action_registry_digest="registry-digest",
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "changed.invalid"),
        ("port", 2222),
        ("credential_ref", "credential:changed"),
        ("principal", "changed-user"),
        ("host_key_fingerprint", "changed-key"),
        ("transport_type", "winrm"),
        ("asset_registry_digest", "changed-asset"),
        ("runtime_config_digest", "changed-runtime"),
        ("profile_digest", "changed-profile"),
        ("policy_digest", "changed-policy"),
        ("prerequisite_stage", "initial_access"),
        ("prerequisite_capability", "t3-access-bounded"),
        ("session_limits_digest", "changed-limits"),
    ],
)
def test_runtime_binding_security_field_drift_changes_fingerprint(field, value):
    original = _runtime_binding()
    assert replace(original, **{field: value}).fingerprint != original.fingerprint


def test_runtime_binding_is_canonical_and_contains_no_credential_material():
    first = _runtime_binding()
    second = RuntimeBinding(**dict(reversed(list(first.__dict__.items()))))
    assert first.fingerprint == second.fingerprint
    assert "private-key-material" not in first.fingerprint


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_action_id", "changed-request"),
        ("asset_id", "changed-asset"),
        ("resolved_target_identity", "changed-target"),
        ("stage_id", "changed-stage"),
        ("capability_id", "changed-capability"),
        ("profile_id", "changed-profile"),
        ("profile_fingerprint", "changed-profile-digest"),
        ("policy_digest", "changed-policy"),
        ("asset_registry_digest", "changed-registry-entry"),
        ("execution_mode", "lab_real"),
        ("command_ids", ("windows_running_services",)),
        ("registry_digest", "changed-action-registry"),
        ("runtime_binding_fingerprint", "changed-runtime"),
        ("credential_reference_fingerprint", "changed-credential-reference"),
        ("prerequisite_run_id", "changed-prerequisite"),
        ("prerequisite_evidence_ref", "changed-evidence-reference"),
        ("prerequisite_evidence_fingerprint", "changed-evidence"),
        ("justification", "changed-justification"),
        ("max_command_count", 4),
        ("policy_version", "changed-freshness-policy"),
    ],
)
def test_every_approval_bound_field_change_invalidates_token(tmp_path, field, value):
    original = plan().bindings
    changed = replace(original, **{field: value})
    authority = ApprovalAuthority(b"a" * 32, tmp_path / field)
    token = authority.issue(
        original.asset_id,
        T3B_PROFILE,
        original.fingerprint,
        credential_id="credential:fake",
        action_fingerprint=original.fingerprint,
    )
    with pytest.raises(ApprovalError):
        authority.verify_and_consume(
            token,
            changed.asset_id,
            T3B_PROFILE,
            changed.fingerprint,
            credential_id="credential:fake",
            action_fingerprint=changed.fingerprint,
        )


class NetworkTransport:
    execution_mode = ExecutionMode.LAB_REAL
    network_capable = True

    def __init__(self):
        self.calls = 0

    def open(self, connection, credential):
        self.calls += 1
        raise AssertionError("network transport must not be reached")


@pytest.mark.parametrize("enablement", [None, "", "false", "TRUE", "1"])
def test_direct_real_executor_denied_before_resolver_or_transport(monkeypatch, enablement):
    monkeypatch.delenv("T3_LAB_EXECUTION_ENABLED", raising=False)
    resolver, transport = FakeResolver(), NetworkTransport()
    outcome = T3BExecutor(
        resolver,
        transport,
        execution_mode=ExecutionMode.LAB_REAL,
        enablement=enablement,
    ).run(replace(plan(), bindings=replace(plan().bindings, execution_mode="lab_real")))
    assert not outcome.completed
    assert resolver.calls == transport.calls == 0
    assert "execution_boundary_denied" in outcome.trace_codes


def test_direct_composition_call_cannot_bypass_execution_opt_in(tmp_path, monkeypatch):
    monkeypatch.delenv("T3_LAB_EXECUTION_ENABLED", raising=False)
    selected_plan = plan()
    selected_plan = replace(
        selected_plan,
        bindings=replace(selected_plan.bindings, execution_mode="lab_real"),
    )
    prereq = prerequisite()
    composition = T3BComposition(
        proposal(),
        prereq,
        selected_plan.bindings,
        selected_plan,
        object(),  # not read on this resolver-injected offline denial path
        object(),  # not read on this resolver-injected offline denial path
    )
    authority = ApprovalAuthority(b"a" * 32, tmp_path / "spent")
    token = authority.issue(
        selected_plan.asset_id,
        T3B_PROFILE,
        selected_plan.bindings.fingerprint,
        credential_id=selected_plan.credential_ref,
        action_fingerprint=selected_plan.bindings.fingerprint,
    )
    resolver, transport = FakeResolver(), NetworkTransport()
    run_dir = execute_t3b_composition(
        composition,
        authority=authority,
        token=token,
        transport=transport,
        resolver=resolver,
        runs_root=tmp_path / "runs",
        kill_switch=KillSwitch(tmp_path / "KILL"),
    )
    assert resolver.calls == transport.calls == 0
    outcome = json.loads((run_dir / "result.json").read_text())["outcome"]
    assert "execution_boundary_denied" in outcome["trace_codes"]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["execution_mode"] == "lab_real"
    assert manifest["mock_only"] is False


def test_explicit_offline_transport_executes_without_real_opt_in():
    payload = '{"Caption":"W","Version":"1","BuildNumber":"2"}'
    transport = FakeTransport(FakeSession([result(payload)]))
    resolver = FakeResolver()
    outcome = T3BExecutor(resolver, transport).run(plan())
    assert outcome.completed
    assert resolver.calls == transport.calls == 1


class NoInvalidationResolver:
    calls = 0

    def resolve_for_lab_ssh(self, credential_handle, source_asset_id):
        self.calls += 1
        return type("Credential", (), {"username": "fixture", "private_key": object()})()


def test_invalidation_is_not_claimed_when_method_is_absent():
    outcome = T3BExecutor(
        NoInvalidationResolver(),
        FakeTransport(FakeSession([result('{"Caption":"W","Version":"1","BuildNumber":"2"}')])),
    ).run(plan())
    assert not outcome.credential_lease_invalidated
    assert "invalidation_not_supported" in outcome.trace_codes
    assert not outcome.completed


def test_stdout_stderr_and_decode_metadata_remain_separate():
    raw = result('{"Caption":"W","Version":"1","BuildNumber":"2"}', stderr=b"fatal:\xff")
    outcome = T3BExecutor(
        FakeResolver(),
        FakeTransport(FakeSession([raw])),
    ).run(plan())
    evidence = outcome.action_evidence[0]
    assert evidence.stdout.startswith('{"Caption"')
    assert evidence.stderr.startswith("fatal:")
    assert evidence.stderr_decoding_errors
    assert evidence.stdout_original_bytes == evidence.stdout_retained_bytes
    assert evidence.stderr_original_bytes == evidence.stderr_retained_bytes


class _Stream:
    def __init__(self, value=b""):
        self.value = value
        self.channel = self

    def read(self, size):
        return self.value[:size]

    def recv_exit_status(self):
        return 0


class _Client:
    def __init__(self):
        self.command = ""

    def exec_command(self, command, timeout):
        self.command = command
        return None, _Stream(b"{}"), _Stream()


def test_windows_command_is_fixed_encoded_powershell_not_posix_quoted():
    client = _Client()
    session = _ParamikoT3BSession(client)
    from core.t3.enumeration import WINDOWS_ACTION_REGISTRY

    definition = WINDOWS_ACTION_REGISTRY[WindowsActionId.RUNNING_SERVICES]
    session.execute_registered(definition)
    assert client.command.startswith(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "
    )
    encoded = client.command.rsplit(" ", 1)[1]
    assert base64.b64decode(encoded).decode("utf-16le") == definition.argv[-1]
    assert definition.argv[-1] not in client.command


def test_tracked_windows_target_is_documentation_only():
    assets = yaml.safe_load(Path("assets.yaml").read_text(encoding="utf-8"))["assets"]
    target = assets["asset:winsrv2025-01"]["target"]
    address = ipaddress.ip_address(target)
    assert address in ipaddress.ip_network("198.51.100.0/24")
    policy = yaml.safe_load(Path("policy.yaml").read_text(encoding="utf-8"))
    assert f"{target}/32" in policy["allowed_targets"]
