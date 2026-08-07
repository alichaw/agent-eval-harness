import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.cli import main
from core.investigation.models import Evidence, InvestigationState
from core.profiles import AssetRegistry
from core.t3.access import (
    T3_ACCESS_PROFILE,
    T3_AUTHORIZED_ACCESS_PROFILE,
    T3AccessProposal,
    materialize_t3_access_request,
)
from core.t3.gate import validate_t3_prerequisites
from core.t3.models import T3Stage
from core.t3.runtime import compose_t3_runtime
from tests.test_t3_lab_executor import PINNED_HOST_KEY

CREDENTIAL_REF = "credential:authorized-test"
_DEFAULT = object()


def ssh_evidence(**updates):
    values = {
        "evidence_id": "ssh-evidence",
        "asset_id": "asset-source",
        "capability_id": "tcp-service-inventory-low",
        "tool_name": "fake-nmap",
        "execution_status": "completed",
        "facts": {
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "state": "open",
        },
        "raw_output_sha256": "a" * 64,
        "observed_at": datetime.now(timezone.utc),
        "complete": True,
        "truncated": False,
        "error": None,
    }
    values.update(updates)
    return Evidence(**values)


def state(evidence=None):
    items = [] if evidence is None else [evidence]
    return InvestigationState(
        investigation_id="authorized-access-investigation",
        asset_id="asset-source",
        objective="Validate approved bounded SSH access",
        evidence=items,
    )


def registry(**updates):
    asset = {
        "asset_type": "host",
        "target": "authorized-lab.invalid",
        "execution_scope": "isolated_lab",
        "platform": "windows_openssh",
        "ssh_port": 22,
        "credential_ref": CREDENTIAL_REF,
    }
    asset.update(updates)
    return AssetRegistry({"asset-source": asset})


def proposal(profile_id=T3_AUTHORIZED_ACCESS_PROFILE, **updates):
    values = {
        "asset_id": "asset-source",
        "profile_id": profile_id,
        "objective": "Validate approved bounded SSH access",
        "command_ids": ["current_identity", "privilege_context"],
    }
    values.update(updates)
    return T3AccessProposal(**values)


def materialize(evidence=_DEFAULT, selected_proposal=None, assets=None):
    selected_evidence = ssh_evidence() if evidence is _DEFAULT else evidence
    return materialize_t3_access_request(
        selected_proposal or proposal(),
        action_id="authorized-access-action",
        state=state(selected_evidence),
        assets=assets or registry(),
    )


def runtime_files(tmp_path, *, evidence=None, asset_updates=None, config_updates=None):
    asset = dict(registry(**(asset_updates or {})).resolve("asset-source"))
    assets_path = tmp_path / "assets.yaml"
    assets_path.write_text(
        "assets:\n  asset-source:\n"
        + "".join(f"    {key}: {json.dumps(value)}\n" for key, value in asset.items())
    )
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
default: deny
allowed_targets: [authorized-lab.invalid]
denied_targets: []
t3_allowed_capabilities: [t3-authorized-access-bounded]
t3_allowed_stages: [authorized_access]
"""
    )
    state_path = tmp_path / "state.json"
    state_path.write_text(state(evidence or ssh_evidence()).model_dump_json())
    config = {
        "asset_id": "asset-source",
        "profile_id": T3_AUTHORIZED_ACCESS_PROFILE,
        "credential_ref": CREDENTIAL_REF,
        "username": "authorized-observer",
        "private_key_path": str(tmp_path / "not-read-during-readiness"),
        "pinned_host_key": PINNED_HOST_KEY,
        "assurance": {"profile": "poc"},
    }
    config.update(config_updates or {})
    config_path = tmp_path / "runtime.json"
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    return assets_path, policy_path, state_path, config_path


def compose(tmp_path, **updates):
    files = runtime_files(tmp_path, **updates)
    assets_path, policy_path, state_path, config_path = files
    return compose_t3_runtime(
        proposal=proposal(),
        runtime_config_path=config_path,
        assets_path=assets_path,
        profiles_path="profiles.yaml",
        policy_path=policy_path,
        investigation_state_path=state_path,
    )


def cli_args(files):
    assets_path, policy_path, state_path, config_path = files
    return [
        "--asset-id",
        "asset-source",
        "--profile-id",
        T3_AUTHORIZED_ACCESS_PROFILE,
        "--objective",
        "Validate approved bounded SSH access",
        "--runtime-config",
        str(config_path),
        "--assets",
        str(assets_path),
        "--profiles",
        "profiles.yaml",
        "--policy",
        str(policy_path),
        "--investigation-state",
        str(state_path),
    ]


def test_authorized_access_uses_complete_ssh_evidence_without_finding():
    request = materialize()
    assert request.stage is T3Stage.AUTHORIZED_ACCESS
    assert request.finding_refs == []
    assert request.evidence_refs == ["ssh-evidence"]
    assert validate_t3_prerequisites(request, state(ssh_evidence()), registry()).allowed


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        ssh_evidence(execution_status="partial", complete=False),
        ssh_evidence(truncated=True),
        ssh_evidence(execution_status="failed", complete=False),
        ssh_evidence(error="synthetic failure"),
        ssh_evidence(observed_at=datetime(2020, 1, 1, tzinfo=timezone.utc)),
        ssh_evidence(asset_id="other-asset"),
        ssh_evidence(facts={"port": 80, "protocol": "tcp", "service": "http", "state": "open"}),
    ],
)
def test_authorized_access_rejects_missing_or_unsuitable_evidence(evidence):
    with pytest.raises(ValueError):
        materialize(evidence=evidence, selected_proposal=proposal())


def test_gate_requires_explicitly_referenced_same_asset_complete_ssh_evidence():
    request = materialize()
    missing = request.model_copy(update={"evidence_refs": ["missing"]})
    assert validate_t3_prerequisites(missing, state(ssh_evidence()), registry()).denied
    wrong = request.model_copy(update={"evidence_refs": ["ssh-evidence"]})
    assert validate_t3_prerequisites(
        wrong, state(ssh_evidence(asset_id="other-asset")), registry()
    ).denied


@pytest.mark.parametrize(
    "asset_updates",
    [
        {"credential_ref": None},
        {"credential_ref": "credential:mismatch"},
        {"platform": "linux"},
        {"execution_scope": "production"},
        {"ssh_port": 2222},
    ],
)
def test_runtime_rejects_wrong_registered_asset_controls(tmp_path, asset_updates):
    with pytest.raises(ValueError):
        compose(tmp_path, asset_updates=asset_updates)


@pytest.mark.parametrize(
    "config_updates",
    [
        {"asset_id": "other-asset"},
        {"credential_ref": "credential:mismatch"},
        {"pinned_host_key": ""},
        {"pinned_host_key": "not-a-host-key"},
    ],
)
def test_runtime_rejects_wrong_private_bindings_without_sensitive_error(tmp_path, config_updates):
    sensitive = "credential:mismatch"
    with pytest.raises(ValueError) as caught:
        compose(tmp_path, config_updates=config_updates)
    assert sensitive not in str(caught.value)
    assert PINNED_HOST_KEY not in str(caught.value)


def test_profile_selection_is_explicit_and_commands_remain_allowlisted():
    with pytest.raises(ValidationError):
        proposal(command_ids=["whoami /all"])
    initial = proposal(T3_ACCESS_PROFILE)
    with pytest.raises(ValueError, match="confirmed initial-access prerequisite"):
        materialize_t3_access_request(
            initial,
            action_id="initial-action",
            state=state(ssh_evidence()),
            assets=registry(),
        )


def test_offline_readiness_never_resolves_credentials_or_opens_transport(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr("core.t3.assurance.loopback_listener_ready", lambda port: True)
    files = runtime_files(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("credential or transport access attempted")

    monkeypatch.setattr(
        "core.t3.runtime.OperatorFileLabSshCredentialResolver.resolve_for_lab_ssh",
        forbidden,
    )
    monkeypatch.setattr("core.t3.runtime.ParamikoBoundedSshTransport.open", forbidden)
    assert main(["t3-ready", *cli_args(files)]) == 0
    output = capsys.readouterr().out
    assert "network : not contacted" in output
    assert "credential: not resolved" in output
    assert CREDENTIAL_REF not in output
    assert PINNED_HOST_KEY not in output


def test_runtime_composition_has_distinct_stage_profile_and_approval_fingerprint(tmp_path):
    built = compose(tmp_path)
    assert built.request.stage is T3Stage.AUTHORIZED_ACCESS
    assert built.request.capability_id == T3_AUTHORIZED_ACCESS_PROFILE
    initial_request = built.request.model_copy(
        update={
            "stage": T3Stage.INITIAL_ACCESS,
            "capability_id": T3_ACCESS_PROFILE,
            "finding_refs": ["finding"],
        }
    )
    from core.t3.access import t3_access_approval_fingerprint

    assert built.fingerprint != t3_access_approval_fingerprint(initial_request)


def test_runtime_configuration_drift_changes_authorized_access_approval(tmp_path):
    files = runtime_files(tmp_path)
    assets_path, policy_path, state_path, config_path = files
    first = compose_t3_runtime(
        proposal=proposal(),
        runtime_config_path=config_path,
        assets_path=assets_path,
        profiles_path="profiles.yaml",
        policy_path=policy_path,
        investigation_state_path=state_path,
    )
    config = json.loads(config_path.read_text())
    config["username"] = "different-authorized-observer"
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    second = compose_t3_runtime(
        proposal=proposal(),
        runtime_config_path=config_path,
        assets_path=assets_path,
        profiles_path="profiles.yaml",
        policy_path=policy_path,
        investigation_state_path=state_path,
    )
    assert first.fingerprint != second.fingerprint
