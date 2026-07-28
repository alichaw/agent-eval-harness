import pytest
from pydantic import ValidationError

from core.t3.models import T3ActionRequest, T3Stage, t3_action_fingerprint


def request(**updates):
    values = {
        "action_id": "action-1",
        "stage": "initial_access",
        "source_asset_id": "asset-1",
        "capability_id": "access.control",
        "method": "validated-method",
        "finding_refs": ["finding-1"],
        "evidence_refs": ["evidence-2", "evidence-1"],
        "command_scope": ["identity.read"],
        "written_justification": "Validate the confirmed finding.",
    }
    values.update(updates)
    return T3ActionRequest(**values)


def test_fingerprint_canonicalizes_set_like_references():
    first = request(finding_refs=["finding-2", "finding-1"])
    assert t3_action_fingerprint(first) == t3_action_fingerprint(
        request(
            finding_refs=list(reversed(first.finding_refs)),
            evidence_refs=list(reversed(first.evidence_refs)),
        )
    )


def test_fingerprint_binds_security_sensitive_fields():
    baseline = request(
        stage=T3Stage.LATERAL_MOVEMENT,
        destination_asset_id="asset-2",
        credential_ref="credential-reference",
        finding_refs=["finding-1", "finding-2"],
        command_scope=["identity.read", "system.info"],
    )
    changes = {
        "stage": T3Stage.PRIVILEGE_ESCALATION,
        "source_asset_id": "asset-other",
        "destination_asset_id": "asset-3",
        "capability_id": "access.other",
        "method": "other-method",
        "finding_refs": ["finding-1", "finding-3"],
        "evidence_refs": ["evidence-1", "evidence-3"],
        "credential_ref": "other-reference",
        "command_scope": ["identity.read", "network.info"],
    }
    original = t3_action_fingerprint(baseline)
    # model_copy(update=...) bypasses normal revalidation; use it only to isolate
    # fingerprint mutations, never to construct production requests.
    for field, value in changes.items():
        assert t3_action_fingerprint(baseline.model_copy(update={field: value})) != original


def test_fingerprint_preserves_command_scope_order():
    baseline = request(command_scope=["identity.read", "system.info"])
    reordered = request(command_scope=list(reversed(baseline.command_scope)))
    assert t3_action_fingerprint(reordered) != t3_action_fingerprint(baseline)


@pytest.mark.parametrize("scope", [["whoami;id"], ["$(id)"], ["sh -c id"], ["a|b"]])
def test_command_scope_rejects_shell_constructs(scope):
    with pytest.raises(ValidationError):
        request(command_scope=scope)


def test_lateral_movement_requires_distinct_destination_and_credential():
    with pytest.raises(ValidationError):
        request(stage=T3Stage.LATERAL_MOVEMENT, destination_asset_id="asset-1")
    assert request(
        stage=T3Stage.LATERAL_MOVEMENT,
        destination_asset_id="asset-2",
        credential_ref="credential-reference",
    )


def test_unknown_fields_are_forbidden():
    with pytest.raises(ValidationError):
        request(raw_command="not allowed")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("action_id", " leading"),
        ("source_asset_id", "asset\nother"),
        ("destination_asset_id", "asset other"),
        ("capability_id", "a" * 129),
        ("finding_refs", ["finding;other"]),
        ("evidence_refs", ["evidence\tother"]),
        ("credential_ref", "reference$other"),
        ("method", "method/with/slash"),
    ],
)
def test_identifiers_and_method_use_bounded_allowlists(field, value):
    updates = {field: value}
    if field == "destination_asset_id":
        updates.update(
            stage=T3Stage.LATERAL_MOVEMENT,
            credential_ref="credential-reference",
        )
    with pytest.raises(ValidationError):
        request(**updates)
