import hashlib
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from core.artifacts import ArtifactSealAuthority
from core.safety import ApprovalAuthority, KillSwitch
from core.t3.impact import (
    ACTION_ID,
    SCENARIO_ID,
    MockT3CExecutor,
    T3CAgentProposal,
    T3CConfig,
    T3CExecutorResult,
    binding,
    digest_file,
    run_t3c,
    validate_readiness,
)

MARKER_PATH = r"C:\ProgramData\HexStrike\t3c-synthetic-marker.txt"
MARKER_DIGEST = hashlib.sha256(b"HEXSTRIKE_T3C_SYNTHETIC_MARKER_V2").hexdigest()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("socket attempted"))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("DNS attempted"))


def setup(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    authority = ApprovalAuthority(b"fixture-secret-material-at-least-32-bytes", tmp_path / "spent")
    seal = ArtifactSealAuthority.from_approval_authority(authority)
    t3a = tmp_path / "t3a"
    t3a.mkdir()
    (t3a / "result.json").write_text(
        json.dumps({"stage": "T3-A", "completed": True, "asset_id": "asset:winsrv2025-01"})
    )
    (t3a / "manifest.json").write_text(json.dumps({"run_id": "fixture-t3a"}))
    (t3a / "trace.jsonl").write_text("{}\n")
    seal.seal(t3a)
    t3a_result = t3a / "result.json"
    t3b = tmp_path / "t3b"
    t3b.mkdir()
    (t3b / "result.json").write_text(
        json.dumps(
            {
                "stage": "T3-B",
                "completed": True,
                "prerequisite_evidence_ref": "t3a-run:fixture-t3a",
                "prerequisite_evidence_fingerprint": hashlib.sha256(
                    (t3a / "trace.jsonl").read_bytes()
                ).hexdigest(),
            }
        )
    )
    (t3b / "manifest.json").write_text("{}")
    (t3b / "trace.jsonl").write_text("{}\n")
    seal.seal(t3b)
    config = T3CConfig(
        assurance_profile="poc",
        scenario_id=SCENARIO_ID,
        asset_id="asset:winsrv2025-01",
        target="192.0.2.25",
        credential_ref="credential:fixture",
        marker_path=MARKER_PATH,
        marker_content_sha256=MARKER_DIGEST,
        evidence_root=str(tmp_path / "runs"),
        hexstrike_url="http://127.0.0.1:8888",
        executor_type="hexstrike_t3c_v2",
        allowlisted_targets=("192.0.2.25",),
        denied_networks=("198.51.100.0/24",),
        cleanup_required=True,
        rollback_verification_required=True,
        maximum_duration_seconds=60,
        maximum_tool_calls=6,
        isolated_lab_ready=True,
    )
    digests = validate_readiness(config, t3a_result, t3b / "result.json", seal_authority=seal)
    fingerprint = binding(config, *digests)
    token = authority.issue(
        config.asset_id,
        ACTION_ID,
        fingerprint,
        credential_id=config.credential_ref,
        action_fingerprint=fingerprint,
    )
    return config, t3a_result, t3b / "result.json", authority, token


def invoke(values, executor=None, token=None):
    config, t3a, t3b, authority, approved = values
    return run_t3c(
        proposal={"action_id": ACTION_ID},
        config=config,
        t3a_path=t3a,
        t3b_path=t3b,
        authority=authority,
        approval_token=approved if token is None else token,
        executor=executor or MockT3CExecutor(),
        kill_switch=KillSwitch(Path(config.evidence_root).parent / "KILL"),
    )


def result(path):
    return json.loads((path / "result.json").read_text())


def test_success_is_single_asset_sanitized_and_requires_full_lifecycle(tmp_path):
    values = setup(tmp_path)
    path = invoke(values)
    value = result(path)
    assert value["completed"] and value["status"] == "succeeded"
    manifest = json.loads((path / "manifest.json").read_text())
    assert manifest["approved_asset_references"] == ["asset:winsrv2025-01"]
    artifacts = "".join(p.read_text() for p in path.iterdir())
    assert values[0].credential_ref not in artifacts and values[4] not in artifacts
    assert "destination" not in artifacts.lower() and "lateral" not in artifacts.lower()


@pytest.mark.parametrize(
    "field",
    [
        "asset_id",
        "target",
        "port",
        "source",
        "destination",
        "path",
        "content",
        "command",
        "username",
        "credential",
        "ssh_key",
        "agent_socket",
        "limits",
        "assurance_profile",
        "cleanup",
        "rollback",
    ],
)
def test_agent_surface_rejects_every_execution_field(field):
    with pytest.raises(ValidationError):
        T3CAgentProposal.model_validate({"action_id": ACTION_ID, field: "attacker"})


def test_prerequisites_and_t3b_binding_fail_before_approval_or_executor(tmp_path):
    for which in ("t3a_missing", "t3b_missing", "t3b_failed", "binding"):
        values = list(setup(tmp_path / which))
        executor = MockT3CExecutor()
        if which == "t3a_missing":
            values[1] = Path("/missing/result.json")
        elif which == "t3b_missing":
            values[2] = Path("/missing/result.json")
        else:
            selected = values[2]
            payload = json.loads(selected.read_text())
            payload[
                "completed" if which == "t3b_failed" else "prerequisite_evidence_fingerprint"
            ] = False if which == "t3b_failed" else "0" * 64
            selected.write_text(json.dumps(payload))
        with pytest.raises(ValueError):
            invoke(tuple(values), executor)
        assert executor.invocation_count == 0


@pytest.mark.parametrize(
    "status",
    ["marker_preexisting", "create_failed", "proof_failed", "cleanup_failed", "rollback_failed"],
)
def test_failure_statuses_never_succeed_and_warning_is_sanitized(tmp_path, status):
    values = setup(tmp_path)
    outcome = T3CExecutorResult(
        status,
        status != "marker_preexisting",
        status not in {"marker_preexisting", "create_failed"},
        status not in {"marker_preexisting", "create_failed", "proof_failed"},
        status not in {"marker_preexisting", "create_failed", "cleanup_failed"},
        False,
        True,
        "operator_action_required" if status in {"cleanup_failed", "rollback_failed"} else None,
    )
    value = result(invoke(values, MockT3CExecutor(outcome)))
    assert not value["completed"] and value["status"] == status


def test_separate_stage_bound_single_use_and_concurrent_approval(tmp_path):
    values = setup(tmp_path)
    executor = MockT3CExecutor()
    assert result(invoke(values, executor))["completed"]
    assert result(invoke(values, executor))["status"] == "authorization_rejected"
    assert executor.invocation_count == 1
    other = setup(tmp_path / "wrong")
    config, t3a, t3b, authority, _ = other
    fp = binding(config, digest_file(t3a), digest_file(t3b))
    wrong = authority.issue(
        config.asset_id,
        "t3b.readonly_posture_check.v1",
        fp,
        credential_id=config.credential_ref,
        action_fingerprint=fp,
    )
    assert result(invoke(other, MockT3CExecutor(), wrong))["status"] == "authorization_rejected"

    concurrent = setup(tmp_path / "concurrent")
    shared = MockT3CExecutor()
    with ThreadPoolExecutor(max_workers=2) as pool:
        paths = list(pool.map(lambda _: invoke(concurrent, shared), range(2)))
    assert sum(result(path)["completed"] for path in paths) == 1 and shared.invocation_count == 1


@pytest.mark.parametrize(
    "updates",
    [
        {"assurance_profile": "unknown"},
        {"asset_id": "asset:other"},
        {"cleanup_required": False},
        {"rollback_verification_required": False},
        {"isolated_lab_ready": False},
        {"maximum_tool_calls": 7},
    ],
)
def test_configuration_fails_closed(updates, tmp_path):
    config = setup(tmp_path)[0].model_dump()
    config.update(updates)
    with pytest.raises(ValidationError):
        T3CConfig.model_validate(config)


def test_registered_public_lab_target_is_allowed_by_exact_binding(tmp_path):
    config, t3a, t3b, authority, _ = setup(tmp_path)
    public = config.model_copy(
        update={
            "target": "8.8.8.8",
            "allowlisted_targets": ("8.8.8.8",),
        }
    )
    validate_readiness(
        public,
        t3a,
        t3b,
        seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
    )


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255"],
)
def test_forbidden_address_classes_are_rejected(tmp_path, target):
    config, t3a, t3b, authority, _ = setup(tmp_path)
    selected = config.model_copy(update={"target": target, "allowlisted_targets": (target,)})
    with pytest.raises(ValueError, match="forbidden address class"):
        validate_readiness(
            selected,
            t3a,
            t3b,
            seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
        )


def test_http_adapter_payload_has_only_authorization_and_action(monkeypatch):
    captured = {}

    class Response:
        def json(self):
            return {
                "schema_version": "hexstrike-t3c-result/v2",
                "canonical_action": ACTION_ID,
                "scenario_id": SCENARIO_ID,
                "status": "succeeded",
                "marker_absent_preflight": True,
                "marker_created": True,
                "proof_verified": True,
                "cleanup_completed": True,
                "rollback_verified": True,
                "connector_invoked": True,
                "operator_warning": None,
            }

        def raise_for_status(self):
            pass

    def post(url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(post=post))
    from core.t3.impact import HexStrikeT3CExecutor, T3CPlan

    HexStrikeT3CExecutor().run(T3CPlan("opaque"))
    assert captured["json"] == {"authorization_id": "opaque", "canonical_action": ACTION_ID}
