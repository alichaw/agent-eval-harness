import importlib.util
import json
from argparse import Namespace
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "verify_t3_operator_readiness.py"
SPEC = importlib.util.spec_from_file_location("t3_readiness_verifier", SCRIPT)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def _protected_result(value):
    return value, {
        "owner": "root",
        "group": "hexstrike",
        "mode": "0640",
        "owner_pass": True,
        "group_pass": True,
        "mode_pass": True,
    }


def test_poc_checks_common_controls_and_skips_only_hardened_controls(tmp_path, monkeypatch):
    harness = tmp_path / "harness"
    hexstrike = tmp_path / "hexstrike"
    (harness / "config/local").mkdir(parents=True)
    (harness / "config/local/assets.yaml").write_text(
        "assets:\n  asset:winsrv2025-01:\n    target: 192.0.2.25\n"
    )
    hexstrike.mkdir()
    (hexstrike / "hexstrike_t3_authorization.py").write_text(
        'AUTHORIZATION_TTL_SECONDS = 60\n_STAGE_TAGS = {"a1", "b1", "c1"}\n'
        'PRIMARY KEY\nisolation_level="IMMEDIATE"\nIntegrityError\n'
    )
    (hexstrike / "hexstrike_t3a.py").write_text(
        'kill_switch_path.exists()\nlimits.get("max_sessions") != 1'
    )
    (hexstrike / "hexstrike_t3b.py").write_text("kill_switch_path.exists()")
    (hexstrike / "hexstrike_t3_poc.py").write_text(
        '"max_commands": 5\n"max_sessions": 1\n'
        '"per_command_timeout_seconds": 15\n"total_timeout_seconds": 60\n'
    )

    binding = verifier.hashlib.sha256(b"asset:winsrv2025-01\x00192.0.2.25\x0022").hexdigest()
    values = {
        "t3-reachability.json": {
            "asset_id": "asset:winsrv2025-01",
            "target": "192.0.2.25",
            "port": 22,
        },
        "t3-poc-runtime.json": {
            "assurance_profile": "poc",
            "asset_id": "asset:winsrv2025-01",
            "target_binding": binding,
            "pinned_host_key": "ssh-ed25519 " + "A" * 43,
        },
        "job-targets.json": {"allowed_targets": ["192.0.2.25/32"]},
        "t3a-credentials.json": {
            "credentials": {
                "credential:ssh-winsrv2025-01": {
                    "asset_id": "asset:winsrv2025-01",
                    "username": "poc_websvc",
                    "identity_agent": "/protected/agent.sock",
                }
            }
        },
        "t3c-runtime.json": {
            "assurance_profile": "poc",
            "scenario_id": "lab.synthetic-marker.v2",
            "asset_id": "asset:winsrv2025-01",
            "target": "192.0.2.25",
            "credential_ref": "credential:ssh-winsrv2025-01",
            "identity_agent": "/protected/agent.sock",
            "username": "poc_websvc",
            "pinned_host_key_file": "/protected/known-hosts",
            "marker_path": r"C:\ProgramData\HexStrike\t3c-synthetic-marker.txt",
            "marker_content_sha256": verifier.hashlib.sha256(
                b"HEXSTRIKE_T3C_SYNTHETIC_MARKER_V2"
            ).hexdigest(),
            "cleanup_required": True,
            "rollback_verification_required": True,
            "maximum_duration_seconds": 60,
            "maximum_tool_calls": 6,
            "isolated_lab_ready": True,
        },
    }
    monkeypatch.setattr(
        verifier,
        "_protected_json_result",
        lambda path: _protected_result(values[path.name]),
    )
    monkeypatch.setattr(verifier, "_command", lambda *args: "LISTEN 127.0.0.1:8888")
    monkeypatch.setattr(verifier, "_poc_endpoint_rejects_invalid_authorization", lambda *a: True)

    report, passed = verifier._verify_poc(
        Namespace(harness_root=str(harness), hexstrike_root=str(hexstrike))
    )
    assert passed is True
    assert report["assurance_profile"] == "poc"
    assert report["credential_mapping"]["identity_loaded"] is False
    for name in ("signed_permits", "approval_key_isolation", "hardened_routes", "uid_firewall"):
        assert report[name]["status"] == "SKIPPED_BY_PROFILE"


def test_profile_selection_is_explicit_and_never_falls_back(monkeypatch, capsys):
    monkeypatch.setattr(verifier.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit):
        verifier.main([])

    monkeypatch.setattr(verifier, "_verify_poc", lambda args: ({"selected": "poc"}, True))
    assert verifier.main(["--assurance-profile", "poc"]) == 0
    assert json.loads(capsys.readouterr().out)["selected"] == "poc"

    monkeypatch.setattr(verifier, "_verify_hardened", lambda args: ({"selected": "hardened"}, True))
    assert verifier.main(["--assurance-profile", "hardened"]) == 0
    assert json.loads(capsys.readouterr().out)["selected"] == "hardened"
