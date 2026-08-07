import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

SCRIPT = Path("scripts/prepare_t3_poc_protected_config.py")


def legacy():
    return {
        "asset_id": "asset:winsrv2025-01",
        "profile_id": "legacy",
        "credential_ref": "credential:synthetic",
        "username": "synthetic-user",
        "private_key_path": "/protected/not-read",
        "pinned_host_key": "ssh-ed25519 " + "A" * 43,
        "assurance": {"profile": "poc"},
    }


def policy():
    from core.t3.poc_registry import ACTIONS

    return {"unified_t3": {"enabled_action_ids": list(ACTIONS)}}


def test_help_has_no_protected_values_or_repair_surface():
    result = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "--runtime-config" in result.stdout and "--unified-policy-config" in result.stdout
    for forbidden in ("--confirm-target", "--confirm-host-key", "--repair-authoritative-bindings"):
        assert forbidden not in result.stdout


def test_output_is_separate_atomic_owner_only_and_loadable(tmp_path):
    from core.t3.poc_runtime import load_runtime
    from scripts.prepare_t3_poc_protected_config import atomic_json, build_unified_runtime

    old = tmp_path / "t3-runtime.json"
    old.write_text(json.dumps(legacy()))
    old.chmod(0o600)
    before = old.read_bytes()
    value = build_unified_runtime(
        asset={"target": "192.0.2.25", "credential_ref": "credential:synthetic"},
        legacy_runtime=legacy(),
        policy=policy(),
        state_root=tmp_path / "state",
        runtime_revision="12345678-1234-5678-1234-567812345678",
    )
    output = tmp_path / "t3-unified-runtime.json"
    atomic_json(output, value, uid=os.geteuid(), gid=os.getegid(), mode=0o600)
    loaded = load_runtime(output)
    assert loaded.schema_version == "hexstrike-t3-runtime/v1" and old.read_bytes() == before
    assert output.stat().st_mode & 0o777 == 0o600
    assert all(
        Path(value[field]).is_absolute()
        for field in ("approval_database", "evidence_root", "kill_switch_file")
    )


def test_legacy_is_not_unified_and_symlink_output_is_rejected(tmp_path):
    from core.t3.poc_runtime import load_runtime
    from scripts.prepare_t3_poc_protected_config import atomic_json

    old = tmp_path / "old.json"
    old.write_text(json.dumps(legacy()))
    old.chmod(0o600)
    with pytest.raises(ValueError, match="protected runtime invalid"):
        load_runtime(old)
    destination = tmp_path / "destination"
    destination.write_text("unchanged")
    link = tmp_path / "runtime.json"
    link.symlink_to(destination)
    with pytest.raises(ValueError, match="output_symlink_rejected"):
        atomic_json(link, {}, uid=os.geteuid(), gid=os.getegid(), mode=0o600)
    assert destination.read_text() == "unchanged"


def test_state_modes_and_policy_registry_agreement(tmp_path):
    from core.t3.poc_registry import ACTIONS
    from scripts.prepare_t3_poc_protected_config import prepare_unified_state

    runtime = {
        "approval_database": str(tmp_path / "state" / "approvals.sqlite3"),
        "evidence_root": str(tmp_path / "state" / "evidence"),
    }
    prepare_unified_state(runtime, uid=os.geteuid(), gid=os.getegid())
    assert Path(runtime["approval_database"]).stat().st_mode & 0o777 == 0o600
    assert Path(runtime["evidence_root"]).stat().st_mode & 0o777 == 0o700
    tracked = yaml.safe_load(Path("policy.yaml").read_text())
    assert tracked["unified_t3"]["enabled_action_ids"] == list(ACTIONS)


def test_real_prepare_main_migrates_without_external_tool_or_overwrite(tmp_path, monkeypatch):
    import pwd

    from scripts.prepare_t3_poc_protected_config import main

    harness = tmp_path / "harness"
    local = harness / "config" / "local"
    local.mkdir(parents=True)
    legacy_path = local / "t3-runtime.json"
    legacy_path.write_text(json.dumps(legacy()))
    legacy_path.chmod(0o600)
    before = legacy_path.read_bytes()
    (local / "assets.yaml").write_text(
        yaml.safe_dump(
            {
                "assets": {
                    "asset:winsrv2025-01": {
                        "target": "192.0.2.25",
                        "credential_ref": "credential:synthetic",
                    }
                }
            }
        )
    )
    (harness / "policy.yaml").write_text(yaml.safe_dump(policy()))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()),
    )
    protected = tmp_path / "protected"
    state = tmp_path / "state"
    assert (
        main(
            [
                "--harness-root",
                str(harness),
                "--protected-dir",
                str(protected),
                "--state-root",
                str(state),
            ]
        )
        == 0
    )
    assert legacy_path.read_bytes() == before
    assert (protected / "t3-unified-runtime.json").stat().st_mode & 0o777 == 0o600
    assert not (protected / "t3-poc-runtime.json").exists()


@pytest.mark.parametrize("change", ["relative", "schema", "missing_action"])
def test_runtime_rejects_relative_unknown_schema_and_missing_registry(tmp_path, change):
    from core.t3.poc_runtime import PocRuntime
    from scripts.prepare_t3_poc_protected_config import build_unified_runtime

    value = build_unified_runtime(
        asset={"target": "192.0.2.25", "credential_ref": "credential:synthetic"},
        legacy_runtime=legacy(),
        policy=policy(),
        state_root=tmp_path,
        runtime_revision="12345678-1234-5678-1234-567812345678",
    )
    if change == "relative":
        value["evidence_root"] = "relative"
    elif change == "schema":
        value["schema_version"] = "unknown"
    else:
        value["action_policy"]["enabled_action_ids"] = value["action_policy"]["enabled_action_ids"][
            :-1
        ]
    with pytest.raises(ValueError):
        PocRuntime.model_validate(value)
