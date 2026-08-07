import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from flask import Flask

from core.t3.poc_approval import ApprovalStore, authorization_digest
from core.t3.poc_registry import ACTIONS as HARNESS_ACTIONS
from core.t3.poc_runner import run
from core.t3.poc_runtime import PocRuntime

HEXSTRIKE = Path("/home/kali/hexstrike-ai")
sys.path.insert(0, str(HEXSTRIKE))
from hexstrike_t3_execution import (  # noqa: E402
    ACTIONS,
    FakeWindowsSshAdapter,
    UnifiedT3Service,
    register_unified_t3_route,
)


class FlaskSession:
    def __init__(self, client):
        self.client = client

    def post(self, url, *, json, timeout):
        response = self.client.post(url.replace("http://127.0.0.1:8888", ""), json=json)

        class Response:
            def json(self):
                return response.get_json()

            def raise_for_status(self):
                if response.status_code >= 400:
                    raise RuntimeError("request_failed")

        return Response()


def test_real_harness_runner_to_real_hexstrike_route_without_socket(tmp_path, monkeypatch):
    assert set(HARNESS_ACTIONS) == set(ACTIONS)
    value = {
        "schema_version": "hexstrike-t3-runtime/v1",
        "runtime_revision": "12345678-1234-5678-1234-567812345678",
        "assets": {
            "asset:winsrv2025-01": {
                "target": "192.0.2.25",
                "port": 22,
                "credential_ref": "credential:synthetic",
                "username": "synthetic-user",
                "identity_agent": str(tmp_path / "agent.sock"),
                "pinned_host_key": "ssh-ed25519 " + "A" * 43,
            }
        },
        "approval_database": str(tmp_path / "approvals.sqlite3"),
        "evidence_root": str(tmp_path / "evidence"),
        "kill_switch_file": str(tmp_path / "KILL"),
        "action_policy": {"enabled_action_ids": list(HARNESS_ACTIONS)},
    }
    runtime = PocRuntime.model_validate(value)
    store = ApprovalStore(runtime.approval_database)
    store.initialize()
    monkeypatch.setattr(
        "socket.create_connection",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("socket used")),
    )
    monkeypatch.setattr(
        "subprocess.run", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("process used"))
    )
    adapter = FakeWindowsSshAdapter(
        connector=lambda *_: None,
        process=lambda argv, timeout: subprocess.CompletedProcess(argv, 0, "synthetic", ""),
    )
    service = UnifiedT3Service(runtime.model_dump(mode="json"), adapter=adapter, clock=lambda: 100)
    app = Flask(__name__)
    register_unified_t3_route(app, service)
    session = FlaskSession(app.test_client())
    auth = "synthetic_authorization_0001"
    issued = store.issue(
        "t3a.ssh22_reachability.v1",
        "asset:winsrv2025-01",
        str(runtime.runtime_revision),
        runtime.digest,
        approving_uid=os.geteuid(),
        now=99,
    )
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE approvals SET authorization_id_digest=? WHERE authorization_id_digest=?",
            (authorization_digest(auth), authorization_digest(issued)),
        )
    result = run(
        runtime, authorization_id=auth, action_id="t3a.ssh22_reachability.v1", session=session
    )
    assert result["status"] == "completed"
