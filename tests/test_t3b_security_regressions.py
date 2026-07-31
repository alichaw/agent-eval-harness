"""Offline negative regressions for T3-B authorization and audit integrity."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import socket
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from core.artifacts import SEAL_FILENAME, ArtifactSealAuthority
from core.replay import validate_run_artifacts
from core.safety import ApprovalAuthority, ApprovalError, KillSwitch
from core.schemas.models import ToolMode, TraceEventType
from core.t3.binding import RuntimeBinding
from core.t3.enumeration import (
    T3B_PROFILE,
    ExecutionMode,
    T3BExecutor,
    T3BOutputLimits,
    WindowsActionId,
    _ParamikoT3BSession,
    load_t3a_prerequisite,
    run_t3b,
)
from core.t3.enumeration_runtime import (
    T3BComposition,
    execute_t3b_composition,
    validate_prerequisite_freshness,
)
from core.t3.executor import LabSshTransportResult
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


def _valid_t3a(tmp_path, run_id="fixture-t3a"):
    root = tmp_path / run_id
    root.mkdir(parents=True)
    created = datetime.now(timezone.utc).isoformat()
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "created_utc": created,
                "schema_version": "v1",
                "execution_mode": "lab_real",
                "stage": "authorized_access",
            }
        )
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
    artifact_authority().seal(root)
    return root


def artifact_authority():
    return ArtifactSealAuthority.for_test(b"s" * 32)


def _rechain(root):
    previous = "0" * 64
    output = []
    for seq, line in enumerate((root / "trace.jsonl").read_text().splitlines()):
        event = json.loads(line)
        event["seq"] = seq
        event["previous_digest"] = previous
        event.pop("event_digest", None)
        digest = hashlib.sha256(
            json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        event["event_digest"] = digest
        previous = digest
        output.append(json.dumps(event, separators=(",", ":")))
    (root / "trace.jsonl").write_text("\n".join(output) + "\n")


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
        load_t3a_prerequisite(root, seal_authority=artifact_authority())


def test_manifest_result_trace_mismatch_and_truncation_fail_closed(tmp_path):
    root = _valid_t3a(tmp_path)
    result_doc = json.loads((root / "result.json").read_text())
    result_doc["run_id"] = "other"
    (root / "result.json").write_text(json.dumps(result_doc))
    assert (
        validate_run_artifacts(root, seal_authority=artifact_authority()).code
        == "artifact_seal_content_mismatch"
    )

    root = _valid_t3a(tmp_path / "second")
    raw = (root / "trace.jsonl").read_bytes()
    (root / "trace.jsonl").write_bytes(raw[:-3])
    assert (
        validate_run_artifacts(root, seal_authority=artifact_authority()).code
        == "malformed_artifact_seal"
    )


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
        load_t3a_prerequisite(root, seal_authority=artifact_authority())


def test_valid_schema_compatible_t3a_fixture_is_accepted(tmp_path):
    prerequisite = load_t3a_prerequisite(
        _valid_t3a(tmp_path),
        seal_authority=artifact_authority(),
    )
    assert prerequisite.verified
    assert prerequisite.stage == "authorized_access"


def test_recalculated_trace_chain_is_rejected_without_valid_authenticated_seal(tmp_path):
    root = _valid_t3a(tmp_path)
    rows = (root / "trace.jsonl").read_text().splitlines()
    event = json.loads(rows[5])
    event["text"] = "attacker-rewritten event"
    rows[5] = json.dumps(event)
    (root / "trace.jsonl").write_text("\n".join(rows) + "\n")
    _rechain(root)
    validated = validate_run_artifacts(root, seal_authority=artifact_authority())
    assert not validated.valid
    assert validated.code == "artifact_seal_content_mismatch"


def test_synchronized_artifact_rewrite_is_rejected(tmp_path):
    root = _valid_t3a(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    result_doc = json.loads((root / "result.json").read_text())
    manifest["run_id"] = result_doc["run_id"] = "rewritten-run"
    manifest["execution_mode"] = "offline_mock"
    result_doc["execution_mode"] = "offline_mock"
    (root / "manifest.json").write_text(json.dumps(manifest))
    (root / "result.json").write_text(json.dumps(result_doc))
    rows = []
    for line in (root / "trace.jsonl").read_text().splitlines():
        event = json.loads(line)
        event["run_id"] = "rewritten-run"
        rows.append(json.dumps(event))
    (root / "trace.jsonl").write_text("\n".join(rows) + "\n")
    _rechain(root)
    assert (
        validate_run_artifacts(root, seal_authority=artifact_authority()).code
        == "artifact_seal_content_mismatch"
    )


def test_missing_malformed_wrong_key_and_copied_seals_are_rejected(tmp_path):
    missing = _valid_t3a(tmp_path / "missing")
    (missing / SEAL_FILENAME).unlink()
    assert (
        validate_run_artifacts(missing, seal_authority=artifact_authority()).code
        == "missing_artifact_seal"
    )

    malformed = _valid_t3a(tmp_path / "malformed")
    (malformed / SEAL_FILENAME).write_text("{")
    assert (
        validate_run_artifacts(malformed, seal_authority=artifact_authority()).code
        == "malformed_artifact_seal"
    )

    wrong_key = _valid_t3a(tmp_path / "wrong")
    wrong_authority = ArtifactSealAuthority.for_test(
        b"w" * 32,
        key_id=artifact_authority().key_id,
    )
    assert (
        validate_run_artifacts(wrong_key, seal_authority=wrong_authority).code
        == "invalid_artifact_seal"
    )

    source = _valid_t3a(tmp_path / "source", "source-run")
    destination = _valid_t3a(tmp_path / "destination", "destination-run")
    (destination / SEAL_FILENAME).write_bytes((source / SEAL_FILENAME).read_bytes())
    assert (
        validate_run_artifacts(destination, seal_authority=artifact_authority()).code
        == "artifact_seal_content_mismatch"
    )


@pytest.mark.parametrize(
    "artifact,field,value",
    [
        ("manifest.json", "run_id", "changed-run"),
        ("manifest.json", "execution_mode", "offline_mock"),
        ("result.json", "status", "failed"),
        ("result.json", "completed", False),
    ],
)
def test_seal_rejects_changed_identity_mode_or_result(tmp_path, artifact, field, value):
    root = _valid_t3a(tmp_path)
    document = json.loads((root / artifact).read_text())
    document[field] = value
    (root / artifact).write_text(json.dumps(document))
    assert (
        validate_run_artifacts(root, seal_authority=artifact_authority()).code
        == "artifact_seal_content_mismatch"
    )


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
    transport_type = "ssh_paramiko"

    def __init__(self):
        self.calls = 0

    def open(self, connection, credential):
        self.calls += 1
        raise AssertionError("network transport must not be reached")


def real_plan():
    selected = plan()
    runtime = replace(selected.runtime_binding, transport_type="ssh_paramiko")
    bindings = replace(
        selected.bindings,
        execution_mode="lab_real",
        runtime_binding_fingerprint=runtime.fingerprint,
    )
    return replace(selected, runtime_binding=runtime, bindings=bindings)


@pytest.mark.parametrize(
    "mutation",
    [
        "target",
        "port",
        "host_key",
        "credential_ref",
        "execution_mode",
        "transport_type",
        "action_definition",
        "registry_digest",
        "session_limit",
        "prerequisite_identity",
    ],
)
def test_post_approval_plan_substitution_fails_before_consumption_or_io(
    tmp_path, monkeypatch, mutation
):
    original = plan()
    mutated = original
    transport = FakeTransport(FakeSession([result("{}")]))
    if mutation == "target":
        mutated = replace(mutated, target="changed.invalid")
    elif mutation == "port":
        mutated = replace(mutated, port=2222)
    elif mutation == "host_key":
        mutated = replace(mutated, pinned_host_key="ssh-ed25519 " + "B" * 68)
    elif mutation == "credential_ref":
        mutated = replace(mutated, credential_ref="credential:changed")
    elif mutation == "execution_mode":
        transport.execution_mode = ExecutionMode.LAB_REAL
        transport.network_capable = True
    elif mutation == "transport_type":
        transport.transport_type = "winrm"
    elif mutation == "action_definition":
        mutated = replace(
            mutated,
            definitions=(replace(mutated.definitions[0], verifier="changed"),),
        )
    elif mutation == "registry_digest":
        mutated = replace(
            mutated,
            bindings=replace(mutated.bindings, registry_digest="changed"),
        )
    elif mutation == "session_limit":
        mutated = replace(
            mutated,
            bindings=replace(mutated.bindings, total_timeout_seconds=61),
        )
    else:
        mutated = replace(mutated, prerequisite_run_id="changed-run")

    network_calls = []

    def forbidden_network(*args, **kwargs):
        network_calls.append((args, kwargs))
        raise AssertionError("network-capable boundary reached")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_network)
    monkeypatch.setattr(socket, "create_connection", forbidden_network)

    authority = ApprovalAuthority(b"a" * 32, tmp_path / "spent")
    token = authority.issue(
        original.asset_id,
        T3B_PROFILE,
        original.bindings.fingerprint,
        credential_id=original.credential_ref,
        action_fingerprint=original.bindings.fingerprint,
    )
    resolver = FakeResolver()
    run_dir = run_t3b(
        plan=mutated,
        prerequisite=prerequisite(),
        executor=T3BExecutor(resolver, transport),
        authority=authority,
        approval_token=token,
        runs_root=tmp_path / "runs",
    )
    assert resolver.calls == transport.calls == 0
    assert network_calls == []
    stored = json.loads((run_dir / "result.json").read_text())
    assert stored["rule"] == "runtime_binding_mismatch"
    assert stored["completed"] is False
    trace_text = (run_dir / "trace.jsonl").read_text()
    assert "runtime_binding_mismatch" in trace_text
    assert "observation_verified" not in trace_text

    # A failed pre-execution binding check must not spend the valid approval.
    authority.verify_and_consume(
        token,
        original.asset_id,
        T3B_PROFILE,
        original.bindings.fingerprint,
        credential_id=original.credential_ref,
        action_fingerprint=original.bindings.fingerprint,
    )


def test_direct_executor_rejects_substituted_plan_before_resolver_or_transport():
    original = plan()
    resolver = FakeResolver()
    transport = FakeTransport(FakeSession([result("{}")]))
    outcome = T3BExecutor(resolver, transport).run(replace(original, target="changed.invalid"))
    assert outcome.trace_codes == ("runtime_binding_mismatch",)
    assert resolver.calls == transport.calls == 0
    assert not outcome.action_evidence


@pytest.mark.parametrize("enablement", [None, "", "false", "TRUE", "1", "true"])
def test_direct_real_executor_denied_before_resolver_or_transport(monkeypatch, enablement):
    monkeypatch.delenv("T3_LAB_EXECUTION_ENABLED", raising=False)
    resolver, transport = FakeResolver(), NetworkTransport()
    outcome = T3BExecutor(
        resolver,
        transport,
        execution_mode=ExecutionMode.LAB_REAL,
        enablement=enablement,
    ).run(real_plan())
    assert not outcome.completed
    assert resolver.calls == transport.calls == 0
    assert "execution_boundary_denied" in outcome.trace_codes


def test_direct_composition_call_cannot_bypass_execution_opt_in(tmp_path, monkeypatch):
    monkeypatch.delenv("T3_LAB_EXECUTION_ENABLED", raising=False)
    selected_plan = real_plan()
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


def _raw(stdout: bytes, stderr: bytes = b"", code: int = 0):
    return LabSshTransportResult(stdout, stderr, code)


@pytest.mark.parametrize(
    "stdout,stderr,limits,expected_stdout,expected_stderr",
    [
        (b"x" * 20, b"", T3BOutputLimits(8, 8, 16, 16), 8, 0),
        (b"", b"e" * 20, T3BOutputLimits(8, 7, 16, 16), 0, 7),
        (b"x" * 12, b"FATAL!" * 2, T3BOutputLimits(20, 20, 14, 14), 2, 12),
    ],
)
def test_actual_retained_bytes_drive_stream_truncation_metadata(
    stdout, stderr, limits, expected_stdout, expected_stderr
):
    outcome = T3BExecutor(
        FakeResolver(),
        FakeTransport(FakeSession([_raw(stdout, stderr)])),
        output_limits=limits,
    ).run(plan())
    evidence = outcome.action_evidence[0]
    assert evidence.stdout_original_bytes == len(stdout)
    assert evidence.stderr_original_bytes == len(stderr)
    assert evidence.stdout_retained_bytes == expected_stdout
    assert evidence.stderr_retained_bytes == expected_stderr
    assert evidence.stdout_truncated is (expected_stdout < len(stdout))
    assert evidence.stderr_truncated is (expected_stderr < len(stderr))
    assert evidence.verification_status != "verified"


def test_cumulative_run_budget_truncates_later_action():
    selected = proposal(
        WindowsActionId.OS_VERSION,
        WindowsActionId.RUNNING_SERVICES,
    )
    first = json.dumps({"Caption": "W", "Version": "1", "BuildNumber": "2"}).encode()
    second = json.dumps({"Name": "svc", "Status": "Running"}).encode()
    run_limit = len(first) + 5
    outcome = T3BExecutor(
        FakeResolver(),
        FakeTransport(FakeSession([_raw(first), _raw(second)])),
        output_limits=T3BOutputLimits(100, 20, 100, run_limit),
    ).run(plan(selected))
    assert outcome.action_evidence[0].stdout_truncated is False
    assert outcome.action_evidence[1].stdout_retained_bytes == 5
    assert outcome.action_evidence[1].stdout_truncated is True
    assert outcome.action_evidence[1].verification_status != "verified"
    assert "total_output_limit_reached" in outcome.trace_codes


def test_stderr_is_truncated_by_remaining_cumulative_budget():
    selected = proposal(
        WindowsActionId.OS_VERSION,
        WindowsActionId.RUNNING_SERVICES,
    )
    first = json.dumps({"Caption": "W", "Version": "1", "BuildNumber": "2"}).encode()
    second_stdout = b"{}"
    second_stderr = b"fatal-diagnostic"
    outcome = T3BExecutor(
        FakeResolver(),
        FakeTransport(FakeSession([_raw(first), _raw(second_stdout, second_stderr)])),
        output_limits=T3BOutputLimits(
            100,
            100,
            100,
            len(first) + 5,
        ),
    ).run(plan(selected))
    evidence = outcome.action_evidence[1]
    assert evidence.stderr == "fatal"
    assert evidence.stderr_retained_bytes == 5
    assert evidence.stderr_truncated
    assert evidence.stdout_retained_bytes == 0
    assert evidence.verification_status != "verified"


def test_utf8_boundary_and_invalid_bytes_cannot_verify():
    prefix = b'{"Caption":"W","Version":"1","BuildNumber":"2"}'
    for payload, limit in (
        (prefix + "\N{EURO SIGN}".encode(), len(prefix) + 1),
        (prefix + b"\xff", len(prefix) + 1),
    ):
        outcome = T3BExecutor(
            FakeResolver(),
            FakeTransport(FakeSession([_raw(payload)])),
            output_limits=T3BOutputLimits(limit, 8, limit, limit),
        ).run(plan())
        evidence = outcome.action_evidence[0]
        assert evidence.stdout_decoding_errors
        assert evidence.verification_status != "verified"


def test_important_stderr_is_retained_before_noisy_stdout():
    outcome = T3BExecutor(
        FakeResolver(),
        FakeTransport(FakeSession([_raw(b"x" * 100, b"FATAL")])),
        output_limits=T3BOutputLimits(100, 10, 10, 10),
    ).run(plan())
    evidence = outcome.action_evidence[0]
    assert evidence.stderr == "FATAL"
    assert evidence.stdout_retained_bytes == 5
    assert evidence.stdout_truncated


def test_truncation_metadata_is_persisted_and_never_verified(tmp_path):
    selected_plan = plan()
    authority = ApprovalAuthority(b"a" * 32, tmp_path / "spent")
    token = authority.issue(
        selected_plan.asset_id,
        T3B_PROFILE,
        selected_plan.bindings.fingerprint,
        credential_id=selected_plan.credential_ref,
        action_fingerprint=selected_plan.bindings.fingerprint,
    )
    executor = T3BExecutor(
        FakeResolver(),
        FakeTransport(FakeSession([_raw(b"x" * 20, b"fatal-error")])),
        output_limits=T3BOutputLimits(8, 5, 10, 10),
    )
    run_dir = run_t3b(
        plan=selected_plan,
        prerequisite=prerequisite(),
        executor=executor,
        authority=authority,
        approval_token=token,
        runs_root=tmp_path / "runs",
    )
    result_doc = json.loads((run_dir / "result.json").read_text())
    evidence = result_doc["outcome"]["action_evidence"][0]
    assert evidence["stdout_original_bytes"] == 20
    assert evidence["stdout_retained_bytes"] == 5
    assert evidence["stdout_truncated"] is True
    assert evidence["stderr_original_bytes"] == 11
    assert evidence["stderr_retained_bytes"] == 5
    assert evidence["stderr_truncated"] is True
    assert evidence["verification_status"] != "verified"
    assert "observation_verified" not in (run_dir / "trace.jsonl").read_text()


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
