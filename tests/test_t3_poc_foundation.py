import json
import os
import sqlite3
from pathlib import Path

import pytest

from core.t3.poc_approval import ApprovalStore, authorization_digest
from core.t3.poc_registry import ACTIONS, action
from core.t3.poc_runner import ENDPOINT, run
from core.t3.poc_runtime import PocRuntime, load_runtime

KEY = "ssh-ed25519 " + "A" * 43


def runtime_value(tmp_path: Path):
    return {
        "schema_version": "hexstrike-t3-runtime/v1",
        "runtime_revision": "12345678-1234-5678-1234-567812345678",
        "assets": {
            "asset:winsrv2025-01": {
                "target": "192.0.2.25",
                "port": 22,
                "credential_ref": "credential:ssh-winsrv2025-01",
                "username": "poc_websvc",
                "identity_agent": str(tmp_path / "agent.sock"),
                "pinned_host_key": KEY,
            }
        },
        "approval_database": str(tmp_path / "state/approvals.sqlite3"),
        "evidence_root": str(tmp_path / "evidence"),
        "kill_switch_file": str(tmp_path / "KILL"),
        "action_policy": {"enabled_action_ids": list(ACTIONS)},
    }


def test_runtime_is_exact_digest_bound_and_derives_single_host_network(tmp_path):
    value = runtime_value(tmp_path)
    runtime = PocRuntime.model_validate(value)
    assert runtime.target_network == "192.0.2.25/32"
    changed = PocRuntime.model_validate(
        {**value, "runtime_revision": "22345678-1234-5678-1234-567812345678"}
    )
    assert changed.digest != runtime.digest
    with pytest.raises(ValueError):
        PocRuntime.model_validate({**value, "unknown": True})


def test_runtime_loader_rejects_symlink_and_permissive_file(tmp_path):
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(runtime_value(tmp_path)), encoding="utf-8")
    path.chmod(0o600)
    assert load_runtime(path).schema_version == "hexstrike-t3-runtime/v1"
    path.chmod(0o640)
    with pytest.raises(ValueError, match="protected runtime invalid"):
        load_runtime(path)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="protected runtime unavailable"):
        load_runtime(link)


def test_registry_rejects_aliases_and_preserves_existing_action_ids():
    for expected in (
        "t3a.ssh22_reachability.v1",
        "windows.ssh.readonly_identity.v1",
    ):
        assert action(expected).action_id == expected
    with pytest.raises(ValueError, match="unknown_action"):
        action("t3c")


def test_hexstrike_is_sole_atomic_consumer_and_runtime_change_invalidates_pending(tmp_path):
    store = ApprovalStore(tmp_path / "state/approvals.sqlite3")
    store.initialize()
    revision = "12345678-1234-5678-1234-567812345678"
    first = store.issue(
        "windows.ssh.readonly_identity.v1",
        "asset:winsrv2025-01",
        revision,
        "a" * 64,
        approving_uid=os.geteuid(),
        now=10,
    )
    second = store.issue(
        "windows.ssh.readonly_identity.v1",
        "asset:winsrv2025-01",
        revision,
        "b" * 64,
        approving_uid=os.geteuid(),
        now=20,
    )
    with pytest.raises(ValueError, match="authorization_rejected"):
        store.consume(
            first,
            "windows.ssh.readonly_identity.v1",
            "asset:winsrv2025-01",
            revision,
            "b" * 64,
            now=21,
        )
    store.consume(
        second,
        "windows.ssh.readonly_identity.v1",
        "asset:winsrv2025-01",
        revision,
        "b" * 64,
        now=21,
    )
    with pytest.raises(ValueError, match="authorization_rejected"):
        store.consume(
            second,
            "windows.ssh.readonly_identity.v1",
            "asset:winsrv2025-01",
            revision,
            "b" * 64,
            now=22,
        )
    with sqlite3.connect(store.path) as database:
        rows = dict(database.execute("SELECT authorization_id_digest,state FROM approvals"))
    assert rows[authorization_digest(first)] == "invalidated"
    assert rows[authorization_digest(second)] == "consumed"
    with (
        sqlite3.connect(store.path) as database,
        pytest.raises(sqlite3.IntegrityError, match="consumed approval immutable"),
    ):
        database.execute(
            "UPDATE approvals SET state='pending', consumed_at=NULL "
            "WHERE authorization_id_digest=?",
            (authorization_digest(second),),
        )
    assert first not in store.path.read_bytes().decode("latin1")
    assert second not in store.path.read_bytes().decode("latin1")


class Response:
    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value

    def raise_for_status(self):
        return None


class Session:
    def __init__(self, authorization_id, runtime):
        self.authorization_id = authorization_id
        self.runtime = runtime
        self.calls = []

    def post(self, url, *, json, timeout):
        self.calls.append((url, json, timeout))
        return Response(
            {
                "schema_version": "hexstrike-t3-result/v1",
                "authorization_id_digest": authorization_digest(self.authorization_id),
                "action_id": json["canonical_action"],
                "status": "completed",
                "runtime_digest": self.runtime.digest,
                "executor_family": "WINDOWS_SSH",
                "tool_calls": 1,
                "evidence_ref": "synthetic/evidence.json",
                "evidence_digest": "0" * 64,
            }
        )


def test_runner_submits_only_two_fields_and_never_consumes_or_persists_raw_id(tmp_path):
    runtime = PocRuntime.model_validate(runtime_value(tmp_path))
    authorization_id = "synthetic-authorization-value"
    session = Session(authorization_id, runtime)
    result = run(
        runtime,
        authorization_id=authorization_id,
        action_id="windows.ssh.readonly_identity.v1",
        session=session,
    )
    assert session.calls == [
        (
            ENDPOINT,
            {
                "authorization_id": authorization_id,
                "canonical_action": "windows.ssh.readonly_identity.v1",
            },
            70,
        )
    ]
    assert authorization_id not in json.dumps(result)
