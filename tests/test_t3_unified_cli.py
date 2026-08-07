import json
import os
from pathlib import Path

import pytest

from core.cli import main
from core.t3.poc_approval import ApprovalStore
from core.t3.poc_runner import load_authorization
from core.t3.poc_runtime import load_runtime
from tests.test_t3_poc_foundation import runtime_value


def protected_runtime(tmp_path):
    value = runtime_value(tmp_path)
    path = tmp_path / "t3-unified-runtime.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    runtime = load_runtime(path)
    store = ApprovalStore(runtime.approval_database)
    store.initialize()
    return path, runtime, store


def authorization_file(tmp_path, authorization_id, **extra):
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps({"authorization_id": authorization_id, **extra}))
    path.chmod(0o600)
    return path


def test_authorization_file_is_exact_owner_only_regular_and_not_symlink(tmp_path):
    selected = authorization_file(tmp_path, "synthetic_authorization_0001")
    assert load_authorization(selected) == "synthetic_authorization_0001"
    selected.chmod(0o644)
    with pytest.raises(ValueError, match="protected authorization invalid"):
        load_authorization(selected)
    selected.chmod(0o600)
    with pytest.raises(ValueError, match="protected authorization invalid"):
        load_authorization(selected, owner_uid=os.geteuid() + 1)
    link = tmp_path / "authorization-link.json"
    link.symlink_to(selected)
    with pytest.raises(ValueError, match="protected authorization invalid"):
        load_authorization(link)


def test_authorization_file_rejects_extra_fields(tmp_path):
    selected = authorization_file(
        tmp_path,
        "synthetic_authorization_0002",
        target="caller-controlled",
    )
    with pytest.raises(ValueError, match="protected authorization invalid"):
        load_authorization(selected)


def test_runtime_rejects_wrong_owner_and_0644(tmp_path):
    path, _runtime, _store = protected_runtime(tmp_path)
    with pytest.raises(ValueError, match="protected runtime invalid"):
        load_runtime(path, owner_uid=os.geteuid() + 1)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="protected runtime invalid"):
        load_runtime(path)


def test_cli_uses_only_protected_paths_and_never_prints_authorization(
    tmp_path, monkeypatch, capsys
):
    path, runtime, store = protected_runtime(tmp_path)
    authorization_id = store.issue(
        "t3a.ssh22_reachability.v1",
        "asset:winsrv2025-01",
        str(runtime.runtime_revision),
        runtime.digest,
        approving_uid=os.geteuid(),
    )
    authorization = authorization_file(tmp_path, authorization_id)
    captured = {}

    def fake_run(selected_runtime, *, authorization_id, action_id, session):
        captured.update(
            runtime=selected_runtime,
            authorization_id=authorization_id,
            action_id=action_id,
            session=session,
        )
        return {
            "schema_version": "hexstrike-t3-result/v1",
            "action_id": action_id,
            "status": "completed",
            "runtime_digest": selected_runtime.digest,
            "evidence_ref": "synthetic/evidence.json",
        }

    monkeypatch.setattr("core.t3.poc_runner.run", fake_run)
    assert (
        main(
            [
                "t3-unified-run",
                "--runtime-file",
                str(path),
                "--authorization-file",
                str(authorization),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert authorization_id not in output
    assert captured["action_id"] == "t3a.ssh22_reachability.v1"
    assert captured["authorization_id"] == authorization_id


def test_cli_parser_exposes_no_execution_parameter_options():
    source = Path("core/cli.py").read_text(encoding="utf-8")
    section = source.split('"t3-unified-run"', 1)[1].split("set_defaults", 1)[0]
    assert "--runtime-file" in section
    assert "--authorization-file" in section
    for forbidden in (
        "--target",
        "--port",
        "--username",
        "--credential",
        "--private-key",
        "--command",
        "--limit",
        "--assurance",
        "--authorization-id",
    ):
        assert forbidden not in section


def test_authorize_command_creates_owner_only_file_without_printing_id(tmp_path, capsys):
    path, runtime, _store = protected_runtime(tmp_path)
    output = tmp_path / "new-authorization.json"
    assert (
        main(
            [
                "t3-unified-authorize-reachability",
                "--runtime-file",
                str(path),
                "--authorization-file",
                str(output),
            ]
        )
        == 0
    )
    assert output.stat().st_mode & 0o777 == 0o600
    authorization_id = load_authorization(output)
    assert authorization_id not in capsys.readouterr().out
    assert (
        ApprovalStore(runtime.approval_database).inspect_pending(
            authorization_id,
            "asset:winsrv2025-01",
            str(runtime.runtime_revision),
            runtime.digest,
        )
        == "t3a.ssh22_reachability.v1"
    )


def test_cli_kill_switch_fails_before_runner(tmp_path, monkeypatch):
    path, runtime, store = protected_runtime(tmp_path)
    authorization_id = store.issue(
        "t3a.ssh22_reachability.v1",
        "asset:winsrv2025-01",
        str(runtime.runtime_revision),
        runtime.digest,
        approving_uid=os.geteuid(),
    )
    authorization = authorization_file(tmp_path, authorization_id)
    Path(runtime.kill_switch_file).touch()

    def denied(selected_runtime, **_kwargs):
        assert Path(selected_runtime.kill_switch_file).exists()
        raise ValueError("kill_switch_engaged")

    monkeypatch.setattr("core.t3.poc_runner.run", denied)
    with pytest.raises(SystemExit, match="kill_switch_engaged"):
        main(
            [
                "t3-unified-run",
                "--runtime-file",
                str(path),
                "--authorization-file",
                str(authorization),
            ]
        )
