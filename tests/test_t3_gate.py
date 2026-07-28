from datetime import datetime, timezone

from core.investigation.models import Evidence, Finding, InvestigationState
from core.profiles import AssetRegistry
from core.t3.gate import validate_t3_prerequisites
from core.t3.models import T3ActionRequest, T3Stage


def evidence(evidence_id="e-1", **updates):
    values = {
        "evidence_id": evidence_id,
        "asset_id": "asset-1",
        "capability_id": "access",
        "tool_name": "controlled-adapter",
        "execution_status": "completed",
        "facts": {},
        "raw_output_sha256": "a" * 64,
        "observed_at": datetime.now(timezone.utc),
        "complete": True,
    }
    values.update(updates)
    return Evidence(**values)


def request(stage=T3Stage.INITIAL_ACCESS, **updates):
    values = {
        "action_id": "a-1",
        "stage": stage,
        "source_asset_id": "asset-1",
        "capability_id": "access",
        "method": "controlled-method",
        "finding_refs": ["f-1"] if stage is T3Stage.INITIAL_ACCESS else [],
        "evidence_refs": ["e-1"],
        "command_scope": ["identity.read"],
        "written_justification": "Evidence supports this bounded action.",
    }
    values.update(updates)
    return T3ActionRequest(**values)


def finding(**updates):
    values = {
        "finding_id": "f-1",
        "asset_id": "asset-1",
        "title": "Confirmed issue",
        "classification": "confirmed_vulnerability",
        "status": "confirmed",
        "severity": "high",
        "confidence": 0.9,
        "evidence_ids": ["e-1"],
    }
    values.update(updates)
    return Finding(**values)


def state(items, findings=None):
    evidence_items = items if isinstance(items, list) else [items]
    return InvestigationState(
        investigation_id="inv-1",
        asset_id="asset-1",
        objective="Assess",
        evidence=evidence_items,
        findings=findings or [],
    )


def registry():
    return AssetRegistry({"asset-1": {}, "asset-2": {}})


def test_initial_access_requires_confirmed_vulnerability():
    item = evidence()
    assert validate_t3_prerequisites(request(), state(item, [finding()]), registry()).allowed


def test_initial_access_rejects_finding_without_evidence():
    malformed = finding().model_copy(update={"evidence_ids": []})
    decision = validate_t3_prerequisites(request(), state(evidence(), [malformed]), registry())
    assert decision.denied and decision.rule == "finding_evidence_missing"


def test_dangling_evidence_reference_is_denied():
    decision = validate_t3_prerequisites(
        request(evidence_refs=["e-missing"]), state(evidence()), registry()
    )
    assert decision.denied and decision.rule == "dangling_evidence"


def test_wrong_asset_evidence_is_denied():
    decision = validate_t3_prerequisites(
        request(), state(evidence(asset_id="asset-other"), [finding()]), registry()
    )
    assert decision.denied and decision.rule == "wrong_asset_evidence"


def test_incomplete_evidence_fails_closed():
    decision = validate_t3_prerequisites(
        request(), state(evidence(execution_status="failed", complete=False)), registry()
    )
    assert decision.denied and decision.rule == "incomplete_evidence"


def test_truncated_evidence_fails_closed():
    decision = validate_t3_prerequisites(
        request(), state(evidence(truncated=True), [finding()]), registry()
    )
    assert decision.denied and decision.rule == "incomplete_evidence"


def test_failed_or_error_evidence_fails_closed():
    failed = validate_t3_prerequisites(
        request(), state(evidence(execution_status="failed", complete=False)), registry()
    )
    errored = validate_t3_prerequisites(
        request(), state(evidence(error="collection failed"), [finding()]), registry()
    )
    assert failed.denied and failed.rule == "incomplete_evidence"
    assert errored.denied and errored.rule == "incomplete_evidence"


def test_unconfirmed_finding_is_denied():
    decision = validate_t3_prerequisites(
        request(), state(evidence(), [finding(status="unconfirmed")]), registry()
    )
    assert decision.denied and decision.rule == "unsuitable_finding"


def test_unsuitable_finding_classification_is_denied():
    decision = validate_t3_prerequisites(
        request(), state(evidence(), [finding(classification="potential_risk")]), registry()
    )
    assert decision.denied and decision.rule == "unsuitable_finding"


def test_finding_evidence_must_be_in_request_references():
    second = evidence("e-2")
    decision = validate_t3_prerequisites(
        request(),
        state([evidence(), second], [finding(evidence_ids=["e-2"])]),
        registry(),
    )
    assert decision.denied and decision.rule == "finding_evidence_missing"


def test_wrong_source_asset_is_denied():
    decision = validate_t3_prerequisites(
        request(source_asset_id="asset-other"), state(evidence()), registry()
    )
    assert decision.denied and decision.rule == "wrong_source_asset"


def test_privilege_escalation_requires_low_privilege_access_proof():
    denied = validate_t3_prerequisites(
        request(T3Stage.PRIVILEGE_ESCALATION), state(evidence()), registry()
    )
    allowed = validate_t3_prerequisites(
        request(T3Stage.PRIVILEGE_ESCALATION),
        state(evidence(facts={"access_level": "low_privilege"})),
        registry(),
    )
    assert denied.denied and allowed.allowed


def test_lateral_movement_requires_source_access_and_registered_destination():
    action = request(
        T3Stage.LATERAL_MOVEMENT,
        destination_asset_id="asset-2",
        credential_ref="credential-reference",
    )
    assert validate_t3_prerequisites(
        action, state(evidence(facts={"access_confirmed": True})), registry()
    ).allowed
    missing = action.model_copy(update={"destination_asset_id": "asset-missing"})
    assert validate_t3_prerequisites(
        missing, state(evidence(facts={"access_confirmed": True})), registry()
    ).denied


def test_destination_lookup_failure_is_denied():
    action = request(
        T3Stage.LATERAL_MOVEMENT,
        destination_asset_id="asset-missing",
        credential_ref="credential-reference",
    )
    decision = validate_t3_prerequisites(
        action,
        state(evidence(facts={"access_confirmed": True})),
        registry(),
    )
    assert decision.denied


def test_registry_exception_detail_is_not_exposed(monkeypatch):
    action = request(
        T3Stage.LATERAL_MOVEMENT,
        destination_asset_id="asset-2",
        credential_ref="credential-reference",
    )
    assets = registry()
    sensitive_message = "internal registry path and credential-reference"

    def fail(_asset_id):
        raise RuntimeError(sensitive_message)

    monkeypatch.setattr(assets, "resolve", fail)
    decision = validate_t3_prerequisites(
        action,
        state(evidence(facts={"access_confirmed": True})),
        assets,
    )

    assert decision.rule == "prerequisite_validation_error"
    assert decision.detail == "prerequisite validation failed"
    assert sensitive_message not in decision.detail
    assert action.credential_ref not in decision.detail
