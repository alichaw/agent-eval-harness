import importlib.util
import json
import pwd
import stat
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

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
    harness.mkdir(parents=True)
    (harness / "assets.yaml").write_text(
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
                    "identity_agent": "/run/hexstrike-t3-ssh-agent/agent.sock",
                }
            }
        },
        "t3c-runtime.json": {
            "assurance_profile": "poc",
            "scenario_id": "lab.synthetic-marker.v2",
            "asset_id": "asset:winsrv2025-01",
            "target": "192.0.2.25",
            "credential_ref": "credential:ssh-winsrv2025-01",
            "identity_agent": "/run/hexstrike-t3-ssh-agent/agent.sock",
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
    monkeypatch.setattr(
        verifier,
        "_pinned_host_source_result",
        lambda *a: {
            "owner_pass": True,
            "group_pass": True,
            "mode_pass": True,
            "key_binding_pass": True,
            "status": "PASS",
            "error_codes": [],
        },
    )
    monkeypatch.setattr(
        verifier,
        "_identity_agent_result",
        lambda *a: {"status": "PASS"},
    )

    monkeypatch.setattr(
        verifier,
        "_kill_switch_inactive",
        lambda path: True,
    )

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


def test_configuration_failure_reports_sanitized_check_code(monkeypatch, capsys):
    monkeypatch.setattr(verifier.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        verifier,
        "_verify_poc",
        lambda args: (_ for _ in ()).throw(
            verifier.ReadinessCheckError("t3_poc_runtime", "configuration_missing")
        ),
    )
    assert verifier.main(["--assurance-profile", "poc"]) == 2
    value = json.loads(capsys.readouterr().out)
    assert value == {
        "assurance_profile": "poc",
        "overall_pass": False,
        "failed_check": "t3_poc_runtime",
        "error_code": "configuration_missing",
    }
    assert "/etc/" not in json.dumps(value)


@pytest.mark.parametrize(
    "contents,code",
    [(None, "configuration_missing"), ("not-json", "configuration_json_invalid")],
)
def test_protected_json_failures_have_stable_sanitized_codes(tmp_path, contents, code):
    path = tmp_path / "protected.json"
    if contents is not None:
        path.write_text(contents)
    with pytest.raises(verifier.ReadinessCheckError) as caught:
        verifier._protected_json_result(path, "poc_runtime_configuration")
    assert caught.value.check == "poc_runtime_configuration"
    assert caught.value.code == code
    assert str(path) not in str(caught.value)


def _identity_runtime_fixture(tmp_path):
    harness = tmp_path / "harness"
    systemd = tmp_path / "systemd"
    (harness / "config").mkdir(parents=True)
    systemd.mkdir()
    contract = {
        "unit_name": "hexstrike-t3-ssh-agent.service",
        "service_account": "hexstrike",
        "runtime_directory": "/run/hexstrike-t3-ssh-agent",
        "socket_path": "/run/hexstrike-t3-ssh-agent/agent.sock",
        "provisioning_marker_path": ("/run/hexstrike-t3-ssh-agent/identity-provisioned"),
    }
    (harness / "config/t3-identity-agent-runtime.json").write_text(json.dumps(contract))
    (systemd / contract["unit_name"]).write_text(
        "User=hexstrike\nGroup=hexstrike\nUMask=0077\n"
        "RuntimeDirectory=hexstrike-t3-ssh-agent\nRuntimeDirectoryMode=0700\n"
        "ExecStart=/usr/bin/ssh-agent -D -a " + contract["socket_path"] + "\n"
    )
    return harness, systemd, contract


def test_identity_agent_missing_socket_has_sanitized_code(tmp_path, monkeypatch):
    harness, systemd, contract = _identity_runtime_fixture(tmp_path)
    uid = pwd.getpwnam("hexstrike").pw_uid
    monkeypatch.setattr(verifier, "_systemd_unit_active", lambda _: True)
    monkeypatch.setattr(
        verifier,
        "_lstat",
        lambda path: (
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=uid)
            if str(path) == contract["runtime_directory"]
            else (_ for _ in ()).throw(FileNotFoundError())
        ),
    )
    result = verifier._identity_agent_result(
        harness, (contract["socket_path"],), systemd_root=systemd
    )
    assert result["error_code"] == "identity_agent_socket_unavailable"
    assert contract["socket_path"] not in json.dumps(result)


@pytest.mark.parametrize(
    "configured",
    ["/run/user/1000/transient-agent.sock", "/tmp/agent.sock", "/protected/key"],
)
def test_identity_agent_rejects_non_contract_and_private_key_references(tmp_path, configured):
    harness, systemd, _ = _identity_runtime_fixture(tmp_path)
    result = verifier._identity_agent_result(harness, (configured,), systemd_root=systemd)
    assert result["error_code"] == "identity_agent_binding_invalid"
    assert configured not in json.dumps(result)


def test_regular_file_is_not_accepted_as_agent_socket(tmp_path, monkeypatch):
    harness, systemd, contract = _identity_runtime_fixture(tmp_path)
    uid = pwd.getpwnam("hexstrike").pw_uid
    monkeypatch.setattr(verifier, "_systemd_unit_active", lambda _: True)

    def fake_lstat(path):
        mode = stat.S_IFDIR | 0o700
        if str(path) == contract["socket_path"]:
            mode = stat.S_IFREG | 0o600
        return SimpleNamespace(st_mode=mode, st_uid=uid)

    monkeypatch.setattr(verifier, "_lstat", fake_lstat)
    result = verifier._identity_agent_result(
        harness, (contract["socket_path"],), systemd_root=systemd
    )
    assert result["error_code"] == "identity_agent_socket_wrong_type"


def test_available_empty_agent_is_not_fully_ready(tmp_path, monkeypatch):
    harness, systemd, contract = _identity_runtime_fixture(tmp_path)
    uid = pwd.getpwnam("hexstrike").pw_uid
    calls = 0

    def fake_lstat(_):
        nonlocal calls
        calls += 1
        if calls == 1:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=uid)
        if calls == 2:
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=uid)
        raise FileNotFoundError

    monkeypatch.setattr(verifier, "_systemd_unit_active", lambda _: True)
    monkeypatch.setattr(verifier, "_lstat", fake_lstat)
    result = verifier._identity_agent_result(
        harness, (contract["socket_path"],), systemd_root=systemd
    )
    assert result["socket_available"] is True
    assert result["identity_provisioning_completed"] is False
    assert result["error_code"] == "identity_agent_identity_unprovisioned"


def test_missing_repository_contract_has_distinct_sanitized_code(tmp_path):
    harness = tmp_path / "harness"
    harness.mkdir()
    result = verifier._identity_agent_result(harness, ("ignored",))
    assert result["error_code"] == "identity_agent_runtime_contract_missing"
    assert str(harness) not in json.dumps(result)


def test_missing_installed_unit_has_distinct_sanitized_code(tmp_path):
    harness, _, contract = _identity_runtime_fixture(tmp_path)
    empty_systemd = tmp_path / "empty-systemd"
    empty_systemd.mkdir()
    result = verifier._identity_agent_result(
        harness, (contract["socket_path"],), systemd_root=empty_systemd
    )
    assert result["error_code"] == "identity_agent_unit_missing"


@pytest.mark.parametrize(
    "socket_uid,socket_mode,error_code",
    [
        (0, stat.S_IFSOCK | 0o600, "identity_agent_socket_owner_invalid"),
        (None, stat.S_IFSOCK | 0o400, "identity_agent_socket_inaccessible"),
    ],
)
def test_socket_owner_and_access_failures_have_distinct_codes(
    tmp_path, monkeypatch, socket_uid, socket_mode, error_code
):
    harness, systemd, contract = _identity_runtime_fixture(tmp_path)
    uid = pwd.getpwnam("hexstrike").pw_uid

    def fake_lstat(path):
        if str(path) == contract["runtime_directory"]:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=uid)
        return SimpleNamespace(
            st_mode=socket_mode,
            st_uid=uid if socket_uid is None else socket_uid,
        )

    monkeypatch.setattr(verifier, "_systemd_unit_active", lambda _: True)
    monkeypatch.setattr(verifier, "_lstat", fake_lstat)
    result = verifier._identity_agent_result(
        harness, (contract["socket_path"],), systemd_root=systemd
    )
    assert result["error_code"] == error_code
