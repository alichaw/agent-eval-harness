import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.artifacts import ArtifactSealAuthority
from core.safety import ApprovalAuthority, KillSwitch
from core.t3.impact import (
    ACTION_ID,
    MockT3CExecutor,
    T3CAgentProposal,
    T3CConfig,
    binding,
    digest_file,
    run_t3c,
)


def setup(tmp_path: Path):
    t3b_run = tmp_path / "t3b-run"
    t3b_run.mkdir()
    evidence = t3b_run / "result.json"
    evidence.write_text(json.dumps({"stage": "T3-B", "completed": True}))
    (t3b_run / "manifest.json").write_text(json.dumps({"run_id": "t3b-test-run", "stage": "T3-B"}))
    (t3b_run / "trace.jsonl").write_text(
        json.dumps({"run_id": "t3b-test-run", "event_digest": "a" * 64}) + "\n"
    )
    config = T3CConfig(
        assurance_profile="poc",
        scenario_id="lab.synthetic-marker.v1",
        source_asset_id="asset:lab-source",
        source_target="10.77.0.10",
        destination_asset_id="asset:lab-destination",
        destination_target="10.77.0.11",
        credential_ref="credential:lab-t3c",
        proof_marker="T3C_SYNTHETIC_PROOF_7F91",
        rollback_checkpoint="snapshot:lab-clean",
        evidence_root=str(tmp_path / "runs"),
        hexstrike_url="http://127.0.0.1:8888",
        executor_type="hexstrike_t3c_v1",
        allowlisted_targets=("10.77.0.10", "10.77.0.11"),
        denied_networks=("10.0.0.0/24", "192.0.2.0/24"),
        isolated_lab=True,
        rollback_ready=True,
    )
    authority = ApprovalAuthority(b"t3c-test-secret-material-32-bytes!!", tmp_path / "spent")
    ArtifactSealAuthority.from_approval_authority(authority).seal(t3b_run)
    fingerprint = binding(config, digest_file(evidence))
    token = authority.issue(
        config.source_asset_id,
        ACTION_ID,
        fingerprint,
        credential_id=config.credential_ref,
        action_fingerprint=fingerprint,
    )
    return config, evidence, authority, token


def result(path):
    return json.loads((path / "result.json").read_text())


def test_approved_t3c_verifies_marker_and_artifacts_are_secret_free(tmp_path):
    config, evidence, authority, token = setup(tmp_path)
    path = run_t3c(
        proposal={"action_id": ACTION_ID},
        config=config,
        prerequisite_path=evidence,
        authority=authority,
        approval_token=token,
        executor=MockT3CExecutor(),
        kill_switch=KillSwitch(tmp_path / "kill"),
    )
    selected_result = result(path)
    assert selected_result["completed"] is True
    assert selected_result["assurance_profile"] == "poc"
    assert selected_result["signed_permit_status"] == "SKIPPED_BY_PROFILE"
    assert selected_result["signed_permit_reason"] == "poc_profile"
    artifacts = "".join(item.read_text() for item in path.iterdir())
    assert token not in artifacts
    assert "t3c-test-secret-material" not in artifacts
    assert config.credential_ref not in artifacts


def test_missing_marker_does_not_pass(tmp_path):
    config, evidence, authority, token = setup(tmp_path)
    path = run_t3c(
        proposal=T3CAgentProposal(action_id=ACTION_ID),
        config=config,
        prerequisite_path=evidence,
        authority=authority,
        approval_token=token,
        executor=MockT3CExecutor(include_marker=False),
        kill_switch=KillSwitch(tmp_path / "kill"),
    )
    assert result(path)["completed"] is False
    assert result(path)["rule"] == "t3c_proof_not_verified"


@pytest.mark.parametrize(
    "field",
    ["command", "target", "credential", "executor", "stage", "assurance_profile", "scenario_id"],
)
def test_agent_cannot_supply_execution_fields(field):
    with pytest.raises(ValidationError):
        T3CAgentProposal.model_validate({"action_id": ACTION_ID, field: "attacker-value"})


def test_unknown_action_is_denied():
    with pytest.raises(ValidationError):
        T3CAgentProposal(action_id="unknown")


def test_missing_or_modified_prerequisite_denied_before_execution(tmp_path):
    config, evidence, authority, token = setup(tmp_path)
    evidence.write_text(json.dumps({"stage": "T3-B", "completed": False}))
    executor = MockT3CExecutor()
    with pytest.raises(ValueError):
        run_t3c(
            proposal={"action_id": ACTION_ID},
            config=config,
            prerequisite_path=evidence,
            authority=authority,
            approval_token=token,
            executor=executor,
            kill_switch=KillSwitch(tmp_path / "kill"),
        )
    assert executor.invocation_count == 0


def test_no_approval_kill_switch_and_reuse_are_denied(tmp_path):
    config, evidence, authority, token = setup(tmp_path)
    executor = MockT3CExecutor()
    first = run_t3c(
        proposal={"action_id": ACTION_ID},
        config=config,
        prerequisite_path=evidence,
        authority=authority,
        approval_token=token,
        executor=executor,
        kill_switch=KillSwitch(tmp_path / "kill"),
    )
    second = run_t3c(
        proposal={"action_id": ACTION_ID},
        config=config,
        prerequisite_path=evidence,
        authority=authority,
        approval_token=token,
        executor=executor,
        kill_switch=KillSwitch(tmp_path / "kill"),
    )
    assert result(first)["completed"] is True
    assert result(second)["rule"] == "t3c_approval_invalid"
    assert executor.invocation_count == 1


def test_t3c_requires_separate_stage_bound_approval(tmp_path):
    config, evidence, authority, _ = setup(tmp_path)
    fingerprint = binding(config, digest_file(evidence))
    earlier_stage_token = authority.issue(
        config.source_asset_id,
        "t3b.readonly_posture_check.v1",
        fingerprint,
        credential_id=config.credential_ref,
        action_fingerprint=fingerprint,
    )
    executor = MockT3CExecutor()
    for token in ("", earlier_stage_token):
        path = run_t3c(
            proposal={"action_id": ACTION_ID},
            config=config,
            prerequisite_path=evidence,
            authority=authority,
            approval_token=token,
            executor=executor,
            kill_switch=KillSwitch(tmp_path / "kill"),
        )
        assert result(path)["rule"] == "t3c_approval_invalid"
    assert executor.invocation_count == 0


def test_kill_switch_prevents_consumption_and_execution(tmp_path):
    config, evidence, authority, token = setup(tmp_path)
    kill = tmp_path / "kill"
    kill.touch()
    executor = MockT3CExecutor()
    path = run_t3c(
        proposal={"action_id": ACTION_ID},
        config=config,
        prerequisite_path=evidence,
        authority=authority,
        approval_token=token,
        executor=executor,
        kill_switch=KillSwitch(kill),
    )
    assert result(path)["rule"] == "kill_switch_engaged"
    assert result(path)["authorization_consumed"] is False
    assert executor.invocation_count == 0


def test_concurrent_reuse_executes_at_most_once(tmp_path):
    config, evidence, authority, token = setup(tmp_path)
    executor = MockT3CExecutor()

    def invoke():
        return run_t3c(
            proposal={"action_id": ACTION_ID},
            config=config,
            prerequisite_path=evidence,
            authority=authority,
            approval_token=token,
            executor=executor,
            kill_switch=KillSwitch(tmp_path / "kill"),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        paths = list(pool.map(lambda _: invoke(), range(2)))
    assert sum(result(path)["completed"] for path in paths) == 1
    assert executor.invocation_count == 1


def test_denied_target_overrides_allowlist(tmp_path):
    config, evidence, authority, _ = setup(tmp_path)
    with pytest.raises(ValueError, match="denied"):
        from core.t3.impact import validate_readiness

        validate_readiness(
            config.model_copy(update={"denied_networks": ("10.77.0.0/24",)}),
            evidence,
            seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
        )


def test_missing_denied_networks_fail_closed(tmp_path):
    config, evidence, authority, _ = setup(tmp_path)
    from core.t3.impact import validate_readiness

    with pytest.raises(ValueError, match="denied networks are required"):
        validate_readiness(
            config.model_copy(update={"denied_networks": ()}),
            evidence,
            seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
        )


def test_single_asset_scenario_is_rejected():
    config = {
        "assurance_profile": "poc",
        "scenario_id": "lab.synthetic-marker.v1",
        "source_asset_id": "asset:only-approved",
        "source_target": "10.77.0.10",
        "destination_asset_id": None,
        "destination_target": None,
        "credential_ref": "credential:lab-t3c",
        "proof_marker": "T3C_SYNTHETIC_PROOF_7F91",
        "rollback_checkpoint": "snapshot:lab-clean",
        "evidence_root": "runs/t3c",
        "hexstrike_url": "http://127.0.0.1:8888",
        "executor_type": "hexstrike_t3c_v1",
        "allowlisted_targets": ["10.77.0.10"],
        "denied_networks": ["10.88.0.0/16"],
        "isolated_lab": True,
        "rollback_ready": True,
    }
    with pytest.raises(ValidationError, match="separately approved destination"):
        T3CConfig.model_validate(config)


def test_same_asset_or_public_target_is_rejected(tmp_path):
    config, evidence, authority, _ = setup(tmp_path)
    with pytest.raises(ValidationError, match="must be distinct"):
        T3CConfig.model_validate(
            config.model_dump()
            | {
                "destination_asset_id": config.source_asset_id,
            }
        )
    public = config.model_copy(
        update={
            "destination_target": "8.8.8.8",
            "allowlisted_targets": (config.source_target, "8.8.8.8"),
        }
    )
    from core.t3.impact import validate_readiness

    with pytest.raises(ValueError, match="private non-loopback"):
        validate_readiness(
            public,
            evidence,
            seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
        )
