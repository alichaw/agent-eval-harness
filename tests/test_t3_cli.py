import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.cli import _t3_composition, main
from core.safety import ApprovalAuthority
from core.t3.access import T3AccessProposal
from core.t3.runtime import compose_t3_runtime
from tests.test_t3_controller import initial_state
from tests.test_t3_lab_executor import PINNED_HOST_KEY


def runtime_files(tmp_path):
    assets = tmp_path / "assets.yaml"
    assets.write_text(
        """
assets:
  asset-source:
    asset_type: host
    target: lab-host.invalid
    ports: "22"
    execution_scope: isolated_lab
    platform: windows_openssh
    ssh_port: 22
"""
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
default: deny
allowed_targets: [lab-host.invalid]
denied_targets: []
t3_allowed_capabilities: [t3-access-bounded]
t3_allowed_stages: [initial_access]
"""
    )
    state = tmp_path / "state.json"
    state.write_text(initial_state().model_dump_json())
    config = tmp_path / "t3-runtime.json"
    config.write_text(
        json.dumps(
            {
                "asset_id": "asset-source",
                "profile_id": "t3-access-bounded",
                "credential_ref": "credential:test-runtime",
                "username": "synthetic-operator",
                "private_key_path": str(tmp_path / "operator-key"),
                "pinned_host_key": PINNED_HOST_KEY,
                "assurance": {"profile": "poc"},
            }
        )
    )
    config.chmod(0o600)
    return assets, policy, state, config


def common_args(tmp_path, files):
    assets, policy, state, config = files
    return [
        "--asset-id",
        "asset-source",
        "--profile-id",
        "t3-access-bounded",
        "--objective",
        "Verify bounded access",
        "--command-id",
        "current_identity",
        "--runtime-config",
        str(config),
        "--assets",
        str(assets),
        "--profiles",
        "profiles.yaml",
        "--policy",
        str(policy),
        "--investigation-state",
        str(state),
    ]


def approve(tmp_path, files, monkeypatch):
    monkeypatch.setenv("HARNESS_APPROVAL_SECRET", "a" * 32)
    token_file = tmp_path / "approval.token"
    rc = main(["t3-approve", *common_args(tmp_path, files), "--output", str(token_file)])
    assert rc == 0
    assert token_file.stat().st_mode & 0o777 == 0o600
    return token_file


def test_approval_presents_canonical_action_without_secret(tmp_path, monkeypatch, capsys):
    files = runtime_files(tmp_path)
    token_file = approve(tmp_path, files, monkeypatch)
    output = capsys.readouterr().out
    assert "Canonical approval request:" in output
    assert '"asset_id": "asset-source"' in output
    assert '"action_ids": [' in output
    assert '"assurance_profile": "poc"' in output
    assert "resolved_target_identity" in output
    assert token_file.read_text().strip() not in output


def composition(tmp_path, files):
    assets, policy, state, config = files
    return compose_t3_runtime(
        proposal=T3AccessProposal(
            asset_id="asset-source",
            profile_id="t3-access-bounded",
            objective="Verify bounded access",
            command_ids=["current_identity"],
        ),
        runtime_config_path=config,
        assets_path=assets,
        profiles_path="profiles.yaml",
        policy_path=policy,
        investigation_state_path=state,
    )


def test_composition_resolves_assurance_once_from_operator_config(tmp_path):
    selected_files = runtime_files(tmp_path)
    selected = composition(tmp_path, selected_files)
    value = json.loads(selected_files[-1].read_text())
    value["assurance"]["profile"] = "hardened"
    selected_files[-1].write_text(json.dumps(value))
    selected_files[-1].chmod(0o600)
    assert selected.assurance.profile.value == "poc"


def test_readiness_resolves_no_credential_and_opens_no_network(tmp_path, monkeypatch, capsys):
    files = runtime_files(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("network or credential access attempted")

    monkeypatch.setattr(
        "core.t3.runtime.OperatorFileLabSshCredentialResolver.resolve_for_lab_ssh",
        forbidden,
    )
    monkeypatch.setattr(
        "core.t3.runtime.ParamikoBoundedSshTransport.open",
        forbidden,
    )

    assert main(["t3-ready", *common_args(tmp_path, files)]) == 0
    output = capsys.readouterr().out
    assert '"assurance_profile": "poc"' in output
    assert '"status": "SKIPPED_BY_PROFILE"' in output
    assert '"production_ready": false' in output
    assert '"aisvs_level_2_or_3_compliance_claimed": false' in output
    assert "network : not contacted" in output
    assert "credential: not resolved" in output


def test_scope_is_unsigned_and_does_not_require_approval_secret(tmp_path, monkeypatch, capsys):
    files = runtime_files(tmp_path)
    monkeypatch.delenv("HARNESS_APPROVAL_SECRET", raising=False)
    assert main(["t3-scope", *common_args(tmp_path, files)]) == 0
    output = capsys.readouterr().out
    assert "Canonical approval request (unsigned):" in output
    assert '"action_ids": [' in output
    assert '"assurance_profile": "poc"' in output
    assert not list(tmp_path.glob("*.token"))


def test_cli_rejects_raw_commands_targets_ports_and_ssh_options(tmp_path):
    files = runtime_files(tmp_path)
    for forbidden in (
        ["--raw-command", "whoami"],
        ["--target", "other.invalid"],
        ["--port", "22"],
        ["--ssh-option", "anything"],
        ["--password", "not-a-secret"],
        ["--assurance-profile", "poc"],
    ):
        with pytest.raises(SystemExit):
            main(["t3-ready", *common_args(tmp_path, files), *forbidden])


def test_invalid_host_key_fails_before_approval_or_credential(tmp_path, monkeypatch):
    files = runtime_files(tmp_path)
    config = files[-1]
    value = json.loads(config.read_text())
    value["pinned_host_key"] = "invalid"
    config.write_text(json.dumps(value))
    config.chmod(0o600)
    monkeypatch.setattr(
        "core.t3.runtime.OperatorFileLabSshCredentialResolver.resolve_for_lab_ssh",
        lambda *args: pytest.fail("credential resolved"),
    )
    with pytest.raises(SystemExit, match="not ready"):
        main(["t3-ready", *common_args(tmp_path, files)])


def test_disabled_run_uses_controller_and_preserves_approval(tmp_path, monkeypatch):
    files = runtime_files(tmp_path)
    token_file = approve(tmp_path, files, monkeypatch)
    monkeypatch.delenv("T3_LAB_EXECUTION_ENABLED", raising=False)
    monkeypatch.setattr(
        "core.t3.runtime.ParamikoBoundedSshTransport.open",
        lambda *args: pytest.fail("network opened"),
    )
    rc = main(
        [
            "t3-run",
            *common_args(tmp_path, files),
            "--approval-token-file",
            str(token_file),
            "--runs-root",
            str(tmp_path / "runs"),
            "--approval-spent-dir",
            str(tmp_path / "spent"),
        ]
    )
    assert rc == 1
    result_path = next((tmp_path / "runs").glob("*/result.json"))
    result = json.loads(result_path.read_text())
    assert result["rule"] == "lab_execution_disabled"

    built = composition(tmp_path, files)
    ApprovalAuthority(b"a" * 32, tmp_path / "spent").verify_and_consume(
        token_file.read_text().strip(),
        built.request.source_asset_id,
        built.request.capability_id,
        built.fingerprint,
        credential_id=built.config.credential_ref,
        action_fingerprint=built.fingerprint,
    )


def test_kill_switch_blocks_controller_before_credential_and_session(tmp_path, monkeypatch):
    files = runtime_files(tmp_path)
    token_file = approve(tmp_path, files, monkeypatch)
    monkeypatch.setenv("T3_LAB_EXECUTION_ENABLED", "true")
    kill_file = tmp_path / "KILL"
    kill_file.touch()
    monkeypatch.setattr(
        "core.t3.runtime.OperatorFileLabSshCredentialResolver.resolve_for_lab_ssh",
        lambda *args: pytest.fail("credential resolved"),
    )
    monkeypatch.setattr(
        "core.t3.runtime.ParamikoBoundedSshTransport.open",
        lambda *args: pytest.fail("network opened"),
    )
    assert (
        main(
            [
                "t3-run",
                *common_args(tmp_path, files),
                "--approval-token-file",
                str(token_file),
                "--runs-root",
                str(tmp_path / "runs"),
                "--approval-spent-dir",
                str(tmp_path / "spent"),
                "--kill-switch-file",
                str(kill_file),
            ]
        )
        == 1
    )
    result = json.loads(next((tmp_path / "runs").glob("*/result.json")).read_text())
    assert result["rule"] == "kill_switch_engaged"


def test_credential_reference_change_rejects_approval_before_network(tmp_path, monkeypatch):
    files = runtime_files(tmp_path)
    token_file = approve(tmp_path, files, monkeypatch)
    config = files[-1]
    value = json.loads(config.read_text())
    value["credential_ref"] = "credential:different-runtime"
    config.write_text(json.dumps(value))
    config.chmod(0o600)
    monkeypatch.setenv("T3_LAB_EXECUTION_ENABLED", "true")
    monkeypatch.setattr(
        "core.t3.runtime.OperatorFileLabSshCredentialResolver.resolve_for_lab_ssh",
        lambda *args: pytest.fail("credential resolved"),
    )
    monkeypatch.setattr(
        "core.t3.runtime.ParamikoBoundedSshTransport.open",
        lambda *args: pytest.fail("network opened"),
    )
    assert (
        main(
            [
                "t3-run",
                *common_args(tmp_path, files),
                "--approval-token-file",
                str(token_file),
                "--runs-root",
                str(tmp_path / "runs"),
                "--approval-spent-dir",
                str(tmp_path / "spent"),
            ]
        )
        == 1
    )
    result = json.loads(next((tmp_path / "runs").glob("*/result.json")).read_text())
    assert result["rule"] == "t3_approval_invalid"


def test_fixed_command_and_one_session_limits_are_structural(tmp_path):
    files = runtime_files(tmp_path)
    args = common_args(tmp_path, files)
    for command in (
        "whoami",
        "unknown",
        "current_identity;host_identity",
        "current_identity\nhost_identity",
    ):
        replaced = list(args)
        replaced[replaced.index("current_identity")] = command
        with pytest.raises(SystemExit):
            main(["t3-ready", *replaced])

    overflow = list(args)
    for _ in range(4):
        overflow.extend(["--command-id", "host_identity"])
    with pytest.raises(SystemExit, match="not ready"):
        main(["t3-ready", *overflow])

    source = Path("core/t3/access.py").read_text()
    assert "max_sessions: int = 1" in source
    assert "self.transport.open(" in source
    assert source.count("self.transport.open(") == 1


def test_t3b_parser_does_not_require_investigation_state(monkeypatch):
    captured = {}

    def fake(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr("core.cli.cmd_t3_ready", fake)
    assert (
        main(
            [
                "t3-ready",
                "--asset-id",
                "asset:winsrv2025-01",
                "--profile-id",
                "windows-host-enumeration-readonly",
                "--runtime-config",
                "config/local/t3-runtime.json",
                "--prerequisite-run-dir",
                "runs/original-t3a",
            ]
        )
        == 0
    )
    assert captured["args"].investigation_state is None


def test_t3b_rejects_command_selection_before_composition():
    with pytest.raises(SystemExit, match="canonical five-action set is fixed"):
        _t3_composition(
            SimpleNamespace(
                profile_id="windows-host-enumeration-readonly",
                prerequisite_run_dir="runs/original-t3a",
                command_id=["windows_os_version"],
                approval_spent_dir="config/local/approval-spent",
            )
        )


def test_authorized_t3a_rejects_command_selection_before_composition():
    with pytest.raises(SystemExit, match="canonical three-action set is fixed"):
        _t3_composition(
            SimpleNamespace(
                profile_id="t3-authorized-access-bounded",
                command_id=["current_identity"],
            )
        )
