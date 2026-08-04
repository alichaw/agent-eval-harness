import json
import os
import stat
from types import SimpleNamespace

import pytest


class FakeSocketPath:
    def __fspath__(self):
        return "/synthetic/agent.sock"

    def __str__(self):
        return "/synthetic/agent.sock"

    @staticmethod
    def lstat():
        return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=os.getuid())


def protected_inputs(tmp_path):
    key = tmp_path / "approved-key"
    key.write_bytes(b"synthetic-private-key-material")
    key.chmod(0o600)
    runtime = tmp_path / "legacy-runtime.json"
    runtime.write_text(
        json.dumps(
            {
                "asset_id": "asset:winsrv2025-01",
                "profile_id": "legacy",
                "credential_ref": "credential:synthetic",
                "username": "synthetic-user",
                "private_key_path": str(key),
                "pinned_host_key": "ssh-ed25519 " + "A" * 43,
                "assurance": {"profile": "poc"},
            }
        )
    )
    runtime.chmod(0o600)
    return runtime, key


def test_provision_uses_stdin_not_key_path_and_verifies_agent(tmp_path, monkeypatch):
    import scripts.provision_t3_poc_ssh_agent as module

    runtime, key = protected_inputs(tmp_path)
    marker = tmp_path / "identity-provisioned"
    monkeypatch.setattr(module, "PROVISIONED_MARKER", marker)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    monkeypatch.setattr(
        module.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()),
    )
    monkeypatch.setattr(module, "AGENT_SOCKET", FakeSocketPath())
    monkeypatch.setattr(os, "access", lambda *_args: True)
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    module.provision(runtime, confirmation=lambda _prompt: "PROVISION", runner=runner)
    assert len(calls) == 2 and calls[0][0][-2:] == ["ssh-add", "-"]
    assert calls[1][0][-2:] == ["ssh-add", "-l"]
    assert str(key) not in json.dumps(calls, default=str)
    assert calls[0][1]["input"] == b"synthetic-private-key-material"
    assert marker.stat().st_mode & 0o777 == 0o600


def test_provision_rejects_confirmation_and_permissive_key(tmp_path, monkeypatch):
    import scripts.provision_t3_poc_ssh_agent as module

    runtime, key = protected_inputs(tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    monkeypatch.setattr(
        module.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()),
    )
    monkeypatch.setattr(module, "AGENT_SOCKET", FakeSocketPath())
    monkeypatch.setattr(os, "access", lambda *_args: True)
    monkeypatch.setattr(module, "PROVISIONED_MARKER", tmp_path / "marker")
    with pytest.raises(ValueError, match="operator_confirmation_rejected"):
        module.provision(runtime, confirmation=lambda _prompt: "NO", runner=lambda *_a, **_k: None)
    key.chmod(0o644)
    with pytest.raises(ValueError, match="private_key_invalid"):
        module.provision(
            runtime, confirmation=lambda _prompt: "PROVISION", runner=lambda *_a, **_k: None
        )
