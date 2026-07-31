import json
from datetime import datetime, timezone

import pytest

from core.controller import Controller
from core.investigation.models import Evidence, Finding, InvestigationState
from core.policy import Policy
from core.profiles import AssetRegistry
from core.safety import ApprovalAuthority, ApprovalError
from core.schemas.models import TraceEvent
from core.t3.assurance import DEFERRED_CHECKS, AssuranceContext, AssuranceProfile
from core.t3.executor import MockT3Executor
from core.t3.models import T3ActionRequest, T3Stage, t3_action_fingerprint

SOURCE_TARGET = "192.0.2.10"
DESTINATION_TARGET = "192.0.2.11"
DENIED_TARGET = "192.0.2.13"
CAPABILITY = "controlled.access"
CREDENTIAL_REFERENCE = "credential-reference"
MISSING = object()


def assets() -> AssetRegistry:
    return AssetRegistry(
        {
            "asset-source": {"asset_type": "host", "target": SOURCE_TARGET},
            "asset-destination": {"asset_type": "host", "target": DESTINATION_TARGET},
            "asset-denied": {"asset_type": "host", "target": DENIED_TARGET},
        }
    )


def policy(**updates) -> Policy:
    values = {
        "allowed_targets": [SOURCE_TARGET, DESTINATION_TARGET],
        "t3_allowed_capabilities": [CAPABILITY],
        "t3_allowed_stages": [
            T3Stage.INITIAL_ACCESS.value,
            T3Stage.LATERAL_MOVEMENT.value,
        ],
    }
    values.update(updates)
    return Policy(**values)


def evidence(**updates) -> Evidence:
    values = {
        "evidence_id": "evidence-1",
        "asset_id": "asset-source",
        "capability_id": "investigation.access",
        "tool_name": "controlled-recorder",
        "execution_status": "completed",
        "facts": {},
        "raw_output_sha256": "a" * 64,
        "observed_at": datetime.now(timezone.utc),
        "complete": True,
    }
    values.update(updates)
    return Evidence(**values)


def initial_state(item: Evidence | None = None) -> InvestigationState:
    item = item or evidence()
    return InvestigationState(
        investigation_id="investigation-1",
        asset_id="asset-source",
        objective="Validate a confirmed finding",
        evidence=[item],
        findings=[
            Finding(
                finding_id="finding-1",
                asset_id="asset-source",
                title="Confirmed controlled finding",
                classification="confirmed_vulnerability",
                status="confirmed",
                severity="high",
                confidence=0.95,
                evidence_ids=[item.evidence_id],
            )
        ],
    )


def lateral_state(raw_marker: str = "") -> InvestigationState:
    facts = {"access_confirmed": True}
    if raw_marker:
        facts["private_note"] = raw_marker
    return InvestigationState(
        investigation_id="investigation-1",
        asset_id="asset-source",
        objective="Validate bounded movement controls",
        evidence=[evidence(facts=facts)],
    )


def initial_request(**updates) -> T3ActionRequest:
    values = {
        "action_id": "action-initial",
        "stage": T3Stage.INITIAL_ACCESS,
        "source_asset_id": "asset-source",
        "capability_id": CAPABILITY,
        "method": "controlled-method",
        "finding_refs": ["finding-1"],
        "evidence_refs": ["evidence-1"],
        "command_scope": ["identity.read"],
        "written_justification": "Validate the bounded control flow.",
    }
    values.update(updates)
    return T3ActionRequest(**values)


def lateral_request(**updates) -> T3ActionRequest:
    values = {
        "action_id": "action-lateral",
        "stage": T3Stage.LATERAL_MOVEMENT,
        "source_asset_id": "asset-source",
        "destination_asset_id": "asset-destination",
        "capability_id": CAPABILITY,
        "method": "controlled-method",
        "finding_refs": [],
        "evidence_refs": ["evidence-1"],
        "credential_ref": CREDENTIAL_REFERENCE,
        "command_scope": ["identity.read"],
        "written_justification": "Validate the bounded control flow.",
    }
    values.update(updates)
    return T3ActionRequest(**values)


def authority(tmp_path) -> ApprovalAuthority:
    return ApprovalAuthority(b"x" * 32, tmp_path / "spent")


def approval(authority: ApprovalAuthority, request: T3ActionRequest) -> str:
    fingerprint = t3_action_fingerprint(request)
    return authority.issue(
        request.source_asset_id,
        request.capability_id,
        fingerprint,
        action_fingerprint=fingerprint,
    )


def controller(tmp_path, approval_authority, **updates) -> Controller:
    values = {
        "runs_root": tmp_path / "runs",
        "policy": policy(),
        "assets": assets(),
        "approval_authority": approval_authority,
    }
    values.update(updates)
    return Controller(**values)


def artifacts(run_dir):
    result = json.loads((run_dir / "result.json").read_text())
    events = [
        TraceEvent.model_validate_json(line)
        for line in (run_dir / "trace.jsonl").read_text().splitlines()
    ]
    return result, events


def test_initial_access_completes_end_to_end_mock_flow(tmp_path):
    request = initial_request()
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    executor = MockT3Executor()

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), executor, token
    )
    result, events = artifacts(run_dir)

    assert result["status"] == "mock_completed"
    assert result["control_authorized"] is True
    assert result["approval_consumed"] is True
    assert result["mock_executor_invoked"] is True
    assert result["real_action_performed"] is False
    assert result["mock_outcome"]["real_action_performed"] is False
    assert executor.invocation_count == 1
    assert [event.rule for event in events] == [
        "t3_request_accepted",
        "t3_source_authorized",
        "t3_prerequisites_satisfied",
        "t3_approval_verified",
        "t3_mock_execution_started",
        "t3_mock_execution_completed",
        "t3_final_result",
    ]

    reuse_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), executor, token
    )
    assert artifacts(reuse_dir)[0]["rule"] == "t3_approval_invalid"
    assert executor.invocation_count == 1


def test_explicit_assurance_profile_is_recorded_without_compliance_overclaim(tmp_path):
    request = initial_request()
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    poc_controller = controller(
        tmp_path,
        approval_authority,
        assurance=AssuranceContext(AssuranceProfile.POC),
    )
    run_dir = poc_controller.run_t3_action(
        request,
        initial_state(),
        MockT3Executor(),
        token,
    )
    result, events = artifacts(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["assurance_profile"] == result["assurance_profile"] == "poc"
    assert manifest["assurance_config_source"] == "operator_runtime_config"
    assert result["production_ready"] is False
    assert result["aisvs_level_2_or_3_compliance_claimed"] is False
    assurance_event = next(event for event in events if event.rule == "assurance_profile_resolved")
    assert assurance_event.assurance_profile == "poc"
    assert assurance_event.assurance_config_source == "operator_runtime_config"
    skipped = [event for event in events if event.readiness_status == "SKIPPED_BY_PROFILE"]
    assert {event.rule for event in skipped} == set(DEFERRED_CHECKS)
    replay = poc_controller.run_t3_action(
        request,
        initial_state(),
        MockT3Executor(),
        token,
    )
    assert artifacts(replay)[0]["rule"] == "t3_approval_invalid"


def test_lateral_movement_completes_and_redacts_sensitive_inputs(tmp_path):
    raw_marker = "private-evidence-marker"
    request = lateral_request()
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    executor = MockT3Executor()

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        request,
        lateral_state(raw_marker),
        executor,
        token,
    )
    serialized = "".join(
        (run_dir / name).read_text() for name in ("manifest.json", "trace.jsonl", "result.json")
    )
    result, events = artifacts(run_dir)

    assert result["status"] == "mock_completed"
    assert result["mock_outcome"] == {
        "status": "mock_completed",
        "mock_only": True,
        "real_action_performed": False,
        "action_id": request.action_id,
        "stage": request.stage.value,
        "capability_id": request.capability_id,
    }
    assert "t3_destination_authorized" in [event.rule for event in events]
    for forbidden in (token, CREDENTIAL_REFERENCE, raw_marker, request.model_dump_json()):
        assert forbidden not in serialized


def test_invalid_request_and_unresolved_assets_never_invoke_executor(tmp_path):
    approval_authority = authority(tmp_path)
    executor = MockT3Executor()
    invalid = initial_request().model_dump()
    invalid["raw_command"] = "forbidden"

    invalid_dir = controller(tmp_path, approval_authority).run_t3_action(
        invalid, initial_state(), executor, ""
    )
    unresolved_source = initial_request(source_asset_id="asset-missing")
    source_dir = controller(tmp_path, approval_authority).run_t3_action(
        unresolved_source, initial_state(), executor, ""
    )
    unresolved_destination = lateral_request(destination_asset_id="asset-missing")
    destination_dir = controller(tmp_path, approval_authority).run_t3_action(
        unresolved_destination, lateral_state(), executor, ""
    )

    assert artifacts(invalid_dir)[0]["rule"] == "t3_request_invalid"
    assert artifacts(source_dir)[0]["rule"] == "t3_source_asset_unresolved"
    assert artifacts(destination_dir)[0]["rule"] == "t3_destination_asset_unresolved"
    assert executor.invocation_count == 0


def test_equal_destination_is_rejected_during_request_validation(tmp_path):
    approval_authority = authority(tmp_path)
    executor = MockT3Executor()
    invalid = lateral_request().model_dump()
    invalid["destination_asset_id"] = invalid["source_asset_id"]

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        invalid, lateral_state(), executor, ""
    )

    assert artifacts(run_dir)[0]["rule"] == "t3_request_invalid"
    assert executor.invocation_count == 0


def test_distinct_asset_ids_with_same_resolved_target_are_denied_before_consumption(tmp_path):
    approval_authority = authority(tmp_path)
    request = lateral_request(destination_asset_id="asset-source-alias")
    token = approval(approval_authority, request)
    executor = MockT3Executor()
    alias_assets = AssetRegistry(
        {
            "asset-source": {"asset_type": "host", "target": SOURCE_TARGET},
            "asset-source-alias": {"asset_type": "host", "target": SOURCE_TARGET},
        }
    )

    denied_dir = controller(
        tmp_path,
        approval_authority,
        assets=alias_assets,
    ).run_t3_action(request, lateral_state(), executor, token)
    denied_result, denied_events = artifacts(denied_dir)
    denied_serialized = (denied_dir / "trace.jsonl").read_text() + (
        denied_dir / "result.json"
    ).read_text()

    assert denied_result["rule"] == "t3_destination_same_as_source"
    assert "t3_source_authorized" not in [event.rule for event in denied_events]
    assert executor.invocation_count == 0
    assert SOURCE_TARGET not in denied_serialized

    corrected_assets = AssetRegistry(
        {
            "asset-source": {"asset_type": "host", "target": SOURCE_TARGET},
            "asset-source-alias": {
                "asset_type": "host",
                "target": DESTINATION_TARGET,
            },
        }
    )
    accepted_dir = controller(
        tmp_path,
        approval_authority,
        assets=corrected_assets,
    ).run_t3_action(request, lateral_state(), executor, token)
    assert artifacts(accepted_dir)[0]["status"] == "mock_completed"
    assert executor.invocation_count == 1


@pytest.mark.parametrize("target", [pytest.param(MISSING, id="missing"), "", "   ", None, []])
def test_invalid_resolved_source_target_is_denied_before_consumption(tmp_path, target):
    approval_authority = authority(tmp_path)
    request = initial_request()
    token = approval(approval_authority, request)
    executor = MockT3Executor()
    source_record = {"asset_type": "host"}
    if target is not MISSING:
        source_record["target"] = target
    invalid_assets = AssetRegistry({"asset-source": source_record})

    denied_dir = controller(
        tmp_path,
        approval_authority,
        assets=invalid_assets,
    ).run_t3_action(request, initial_state(), executor, token)
    denied_result, denied_events = artifacts(denied_dir)

    assert denied_result["rule"] == "t3_source_target_invalid"
    assert "t3_source_authorized" not in [event.rule for event in denied_events]
    assert executor.invocation_count == 0

    accepted_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), executor, token
    )
    assert artifacts(accepted_dir)[0]["status"] == "mock_completed"
    assert executor.invocation_count == 1


@pytest.mark.parametrize("target", [pytest.param(MISSING, id="missing"), "", "   ", None, {}])
def test_invalid_resolved_destination_target_is_denied_before_consumption(tmp_path, target):
    approval_authority = authority(tmp_path)
    request = lateral_request()
    token = approval(approval_authority, request)
    executor = MockT3Executor()
    destination_record = {"asset_type": "host"}
    if target is not MISSING:
        destination_record["target"] = target
    invalid_assets = AssetRegistry(
        {
            "asset-source": {"asset_type": "host", "target": SOURCE_TARGET},
            "asset-destination": destination_record,
        }
    )

    denied_dir = controller(
        tmp_path,
        approval_authority,
        assets=invalid_assets,
    ).run_t3_action(request, lateral_state(), executor, token)
    denied_result, denied_events = artifacts(denied_dir)

    assert denied_result["rule"] == "t3_destination_target_invalid"
    assert "t3_source_authorized" not in [event.rule for event in denied_events]
    assert executor.invocation_count == 0

    accepted_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, lateral_state(), executor, token
    )
    assert artifacts(accepted_dir)[0]["status"] == "mock_completed"
    assert executor.invocation_count == 1


@pytest.mark.parametrize(
    ("policy_updates", "request_factory", "expected_rule"),
    [
        (
            {"allowed_targets": [DESTINATION_TARGET]},
            initial_request,
            "target_not_allowed",
        ),
        (
            {
                "allowed_targets": [SOURCE_TARGET, DENIED_TARGET],
                "denied_targets": [SOURCE_TARGET],
            },
            initial_request,
            "target_forbidden_zone",
        ),
        (
            {"allowed_targets": [SOURCE_TARGET]},
            lateral_request,
            "target_not_allowed",
        ),
        (
            {
                "allowed_targets": [SOURCE_TARGET, DESTINATION_TARGET, DENIED_TARGET],
                "denied_targets": [DENIED_TARGET],
            },
            lambda: lateral_request(destination_asset_id="asset-denied"),
            "target_forbidden_zone",
        ),
    ],
)
def test_source_and_destination_require_independent_authorization(
    tmp_path, policy_updates, request_factory, expected_rule
):
    approval_authority = authority(tmp_path)
    request = request_factory()
    token = approval(approval_authority, request)
    executor = MockT3Executor()
    state = initial_state() if request.stage is T3Stage.INITIAL_ACCESS else lateral_state()

    run_dir = controller(
        tmp_path,
        approval_authority,
        policy=policy(**policy_updates),
    ).run_t3_action(request, state, executor, token)

    assert artifacts(run_dir)[0]["rule"] == expected_rule
    assert executor.invocation_count == 0


def test_missing_or_disallowed_t3_policy_authorization_denies(tmp_path):
    approval_authority = authority(tmp_path)
    request = initial_request()
    token = approval(approval_authority, request)
    executor = MockT3Executor()

    missing_dir = controller(
        tmp_path,
        approval_authority,
        policy=Policy(allowed_targets=[SOURCE_TARGET]),
    ).run_t3_action(request, initial_state(), executor, token)
    disallowed_dir = controller(
        tmp_path,
        approval_authority,
        policy=policy(t3_allowed_capabilities=["other.capability"]),
    ).run_t3_action(request, initial_state(), executor, token)

    assert artifacts(missing_dir)[0]["rule"] == "t3_capability_not_allowed"
    assert artifacts(disallowed_dir)[0]["rule"] == "t3_capability_not_allowed"
    assert executor.invocation_count == 0


def test_policy_and_evidence_denials_do_not_consume_approval(tmp_path):
    approval_authority = authority(tmp_path)
    request = initial_request()
    token = approval(approval_authority, request)
    executor = MockT3Executor()
    denied_controller = controller(
        tmp_path,
        approval_authority,
        policy=policy(t3_allowed_capabilities=[]),
    )

    policy_dir = denied_controller.run_t3_action(request, initial_state(), executor, token)
    evidence_dir = controller(tmp_path, approval_authority).run_t3_action(
        request,
        initial_state(evidence(execution_status="failed", complete=False)),
        executor,
        token,
    )
    accepted_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), executor, token
    )

    assert artifacts(policy_dir)[0]["rule"] == "t3_capability_not_allowed"
    assert artifacts(evidence_dir)[0]["rule"] == "incomplete_evidence"
    assert artifacts(accepted_dir)[0]["status"] == "mock_completed"
    assert executor.invocation_count == 1
    denied_serialized = (evidence_dir / "trace.jsonl").read_text()
    assert "evidence-1" not in denied_serialized
    assert CREDENTIAL_REFERENCE not in denied_serialized


def test_missing_legacy_and_mismatched_approvals_fail_before_invocation(tmp_path):
    approval_authority = authority(tmp_path)
    request = initial_request()
    fingerprint = t3_action_fingerprint(request)
    legacy = approval_authority.issue(
        request.source_asset_id,
        request.capability_id,
        fingerprint,
    )
    mismatched = approval_authority.issue(
        request.source_asset_id,
        request.capability_id,
        fingerprint,
        action_fingerprint="b" * 64,
    )
    executor = MockT3Executor()
    ctrl = controller(tmp_path, approval_authority)

    missing_dir = ctrl.run_t3_action(request, initial_state(), executor, "")
    legacy_dir = ctrl.run_t3_action(request, initial_state(), executor, legacy)
    mismatch_dir = ctrl.run_t3_action(request, initial_state(), executor, mismatched)

    assert artifacts(missing_dir)[0]["rule"] == "t3_approval_required"
    assert artifacts(legacy_dir)[0]["rule"] == "t3_approval_invalid"
    assert artifacts(mismatch_dir)[0]["rule"] == "t3_approval_invalid"
    assert executor.invocation_count == 0


def test_request_mutation_mismatch_does_not_consume_matching_token(tmp_path):
    approval_authority = authority(tmp_path)
    request = initial_request()
    token = approval(approval_authority, request)
    executor = MockT3Executor()
    ctrl = controller(tmp_path, approval_authority)
    changed = initial_request(method="other-method")

    mismatch_dir = ctrl.run_t3_action(changed, initial_state(), executor, token)
    accepted_dir = ctrl.run_t3_action(request, initial_state(), executor, token)

    assert artifacts(mismatch_dir)[0]["rule"] == "t3_approval_invalid"
    assert artifacts(accepted_dir)[0]["status"] == "mock_completed"
    assert executor.invocation_count == 1


def test_mock_failure_is_safe_and_approval_remains_consumed(tmp_path, monkeypatch):
    approval_authority = authority(tmp_path)
    request = initial_request()
    token = approval(approval_authority, request)
    executor = MockT3Executor()

    def fail(_plan):
        executor.invocation_count += 1
        raise RuntimeError("synthetic-private-exception")

    monkeypatch.setattr(executor, "run", fail)
    ctrl = controller(tmp_path, approval_authority)

    run_dir = ctrl.run_t3_action(request, initial_state(), executor, token)
    result, _ = artifacts(run_dir)

    assert result["status"] == "mock_failed"
    assert result["control_authorized"] is True
    assert result["approval_consumed"] is True
    assert result["mock_executor_invoked"] is True
    assert executor.invocation_count == 1
    assert "synthetic-private-exception" not in (run_dir / "trace.jsonl").read_text()
    with pytest.raises(ApprovalError, match="already consumed"):
        approval_authority.verify_and_consume(
            token,
            request.source_asset_id,
            request.capability_id,
            t3_action_fingerprint(request),
            action_fingerprint=t3_action_fingerprint(request),
        )
