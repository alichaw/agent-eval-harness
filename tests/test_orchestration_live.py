import json

from core.enforcement import effective_approval_fingerprint, resolve_effective_action
from core.orchestration.catalog import CapabilityCatalog
from core.orchestration.live import LiveHexStrikeExecutor
from core.orchestration.models import RunContext
from core.orchestration.observations import normalize
from core.policy import Policy
from core.profiles import AssetRegistry, ProfileCatalog
from core.safety import ApprovalAuthority, KillSwitch


class Response:
    def __init__(self, document, status=200):
        self.document, self.status_code = document, status
        self.ok = 200 <= status < 300

    def json(self):
        return self.document


def composition(tmp_path):
    profiles = ProfileCatalog.from_yaml("profiles.yaml")
    assets = AssetRegistry(
        {
            "asset:test": {
                "asset_type": "host",
                "target": "192.0.2.10",
                "ports": "1,2,65535",
                "tool_args": {"nmap": {"ports": "9,10"}},
            }
        }
    )
    executor = LiveHexStrikeExecutor(
        profiles=profiles,
        assets=assets,
        policy=Policy.from_yaml("policy.yaml"),
        job_create_token="create-secret",
        kill_switch=KillSwitch(tmp_path / "KILL"),
        runs_root=tmp_path,
    )
    capability = CapabilityCatalog.from_yaml("capabilities.yaml", profiles).get(
        "network.service_discovery"
    )
    run = RunContext(run_id="live-test", principal="p", asset_id="asset:test", task="discover")
    return executor, capability, run


def test_live_ssh_posture_uses_fixed_endpoint_and_records_negative_evidence(tmp_path, monkeypatch):
    profiles = ProfileCatalog.from_yaml("profiles.yaml")
    assets = AssetRegistry({"asset:test": {"asset_type": "host", "target": "192.0.2.10"}})
    capability = CapabilityCatalog.from_yaml("capabilities.yaml", profiles).get("ssh.posture_check")
    authority = ApprovalAuthority(b"offline-approval-secret-material-32-bytes", tmp_path / "spent")
    action = resolve_effective_action(profiles, assets, "asset:test", capability.profile_id or "")
    token = authority.issue(
        "asset:test",
        capability.profile_id or "",
        effective_approval_fingerprint(action),
        action_fingerprint=action.fingerprint,
    )
    executor = LiveHexStrikeExecutor(
        profiles=profiles,
        assets=assets,
        policy=Policy.from_yaml("policy.yaml"),
        job_create_token="create-secret",
        kill_switch=KillSwitch(tmp_path / "KILL"),
        runs_root=tmp_path,
        approval_authority=authority,
        approval_tokens={"ssh.posture_check": token},
    )
    posts = []

    def post(url, **kwargs):
        posts.append((url, kwargs))
        if url.endswith("/api/cache/clear"):
            return Response({})
        assert url.endswith("/api/jobs/ssh-posture")
        assert kwargs["json"] == {"target": "192.0.2.10"}
        return Response({"job_id": "ssh-job", "job_token": "job-secret"}, 202)

    monkeypatch.setattr("core.adapters.hexstrike.requests.post", post)

    def get(url, **kwargs):
        if url.endswith("/health"):
            return Response({"status": "healthy"})
        return Response(
            {
                "status": "succeeded",
                "result": {
                    "success": True,
                    "return_code": 0,
                    "stdout": "22/tcp open ssh OpenSSH\nssh-hostkey: RSA 3072\nAlgorithms: safe",
                    "stderr": "",
                },
            }
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", get)
    run = RunContext(run_id="ssh-live", principal="p", asset_id="asset:test", task="assess")
    result = executor.execute(capability, run)
    observation = normalize(capability.capability_id, run.asset_id, result, 65536)
    assert result.status == "succeeded" and result.evidence_ids
    assert any(fact.type == "posture_check_completed" for fact in observation.facts)
    assert any(fact.type == "posture_finding" for fact in observation.facts)
    assert posts[1][1]["json"] == {"target": "192.0.2.10"}
    trace = (tmp_path / "ssh-live" / "trace.jsonl").read_text()
    assert "offline-approval-secret" not in trace and "job-secret" not in trace


def test_live_executor_uses_hardened_job_and_records_evidence(tmp_path, monkeypatch):
    executor, capability, run = composition(tmp_path)
    posts = []

    def get(url, **kwargs):
        if url.endswith("/health"):
            return Response({"status": "healthy"})
        assert kwargs["headers"] == {"X-Job-Token": "job-secret"}
        return Response(
            {
                "job_id": "real-job-id",
                "status": "succeeded",
                "result": {
                    "success": True,
                    "return_code": 0,
                    "stdout": "22/tcp filtered ssh\n80/tcp open http\nNmap done: 1 IP address",
                    "stderr": "",
                },
            }
        )

    def post(url, **kwargs):
        posts.append((url, kwargs))
        if url.endswith("/api/cache/clear"):
            return Response({})
        assert url.endswith("/api/jobs/nmap")
        assert kwargs["headers"] == {"X-Job-Create-Token": "create-secret"}
        assert kwargs["json"] == {
            "target": "192.0.2.10",
            "scan_type": "-sV",
            "ports": "22,80,139,443,445,3389",
            "use_recovery": False,
        }
        return Response(
            {"job_id": "real-job-id", "job_token": "job-secret", "status": "running"}, 202
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", get)
    monkeypatch.setattr("core.adapters.hexstrike.requests.post", post)
    assert executor.health()
    result = executor.execute(capability, run)

    assert result.status == "succeeded"
    assert executor.last_job_id == "real-job-id"
    assert executor.last_job_status == "succeeded"
    assert executor.job_states == ["running", "succeeded"]
    assert result.evidence_ids[0].startswith("evidence:hexstrike:")
    observation = normalize("network.service_discovery", run.asset_id, result, 65536)
    assert [
        (fact.values["port"], fact.values["service"])
        for fact in observation.facts
        if fact.type == "open_port"
    ] == [
        (80, "http"),
    ]
    assert [fact.values["port"] for fact in observation.facts if fact.type == "scanned_port"] == [
        22,
        80,
        139,
        443,
        445,
        3389,
    ]
    trace = (tmp_path / "live-test" / "trace.jsonl").read_text()
    assert "real-job-id" in trace
    assert "job-secret" not in trace and "create-secret" not in trace
    assert any(item[0].endswith("/api/jobs/nmap") for item in posts)


def test_second_dispatch_create_failure_cannot_reuse_first_job_or_output(tmp_path, monkeypatch):
    executor, discovery, run = composition(tmp_path)
    ssh = CapabilityCatalog.from_yaml("capabilities.yaml", executor.profiles).get(
        "ssh.posture_check"
    )

    def post(url, **kwargs):
        if url.endswith("/api/cache/clear"):
            return Response({})
        if url.endswith("/api/jobs/nmap"):
            return Response({"job_id": "job-a", "job_token": "secret", "status": "running"}, 202)
        assert url.endswith("/api/jobs/ssh-posture")
        return Response({"error": "tool not enabled"}, 403)

    def get(url, **kwargs):
        if url.endswith("/health"):
            return Response({"status": "healthy"})
        assert url.endswith("/api/jobs/job-a")
        return Response(
            {
                "job_id": "job-a",
                "status": "succeeded",
                "result": {
                    "return_code": 0,
                    "stdout": "22/tcp open ssh\nNmap done: 1 IP address",
                    "stderr": "",
                },
            }
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.post", post)
    monkeypatch.setattr("core.adapters.hexstrike.requests.get", get)

    first = executor.execute(discovery, run)
    second = executor.execute(ssh, run)

    assert first.status == "succeeded"
    assert second.status == "failed"
    assert second.output == ""
    assert second.parser_warnings == ["cancellable job rejected: tool not enabled"]
    assert "Nmap" not in second.model_dump_json()
    assert executor.executions[0]["job_id"] == "job-a"
    assert executor.executions[1]["job_id"] == ""
    assert executor.executions[0]["execution_id"] != executor.executions[1]["execution_id"]
    assert executor.last_job_id == ""


def test_poll_job_id_mismatch_fails_closed_before_parser(tmp_path, monkeypatch):
    executor, capability, run = composition(tmp_path)

    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.post",
        lambda url, **kwargs: (
            Response({})
            if url.endswith("/api/cache/clear")
            else Response({"job_id": "expected", "job_token": "secret", "status": "running"}, 202)
        ),
    )

    def get(url, **kwargs):
        if url.endswith("/health"):
            return Response({"status": "healthy"})
        return Response(
            {
                "job_id": "wrong",
                "status": "succeeded",
                "result": {"return_code": 0, "stdout": "80/tcp open http", "stderr": ""},
            }
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", get)
    result = executor.execute(capability, run)

    assert result.status == "failed"
    assert result.run_fatal is True
    assert result.failure_stage == "result_correlation"
    assert result.output == "" and result.evidence_ids == [] and result.facts == []


def test_live_executor_fails_closed_on_unknown_job_state(tmp_path, monkeypatch):
    executor, capability, run = composition(tmp_path)
    calls = []

    def get(url, **kwargs):
        calls.append(url)
        if url.endswith("/health"):
            return Response({"status": "healthy"})
        return Response({"status": "mystery"})

    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.get",
        get,
    )
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.post",
        lambda url, **kwargs: (
            Response({})
            if url.endswith("/api/cache/clear")
            else Response({"job_id": "job", "job_token": "secret"}, 202)
        ),
    )
    result = executor.execute(capability, run)
    assert result.status == "failed"
    assert not result.evidence_ids
    events = [
        json.loads(line)
        for line in (tmp_path / "live-test" / "trace.jsonl").read_text().splitlines()
    ]
    assert any(item.get("error_class") == "request_failed" for item in events)


def test_flat_completed_job_schema_normalizes_and_creates_evidence(tmp_path, monkeypatch):
    executor, capability, run = composition(tmp_path)

    def get(url, **kwargs):
        if url.endswith("/health"):
            return Response({"status": "healthy"})
        return Response(
            {
                "job_id": "offline-job",
                "status": "completed",
                "return_code": 0,
                "stdout": "80/tcp open http",
                "stderr": "",
            }
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", get)
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.post",
        lambda url, **kwargs: (
            Response({})
            if url.endswith("/api/cache/clear")
            else Response(
                {"job_id": "offline-job", "job_token": "secret", "status": "running"}, 202
            )
        ),
    )
    result = executor.execute(capability, run)
    observation = normalize("network.service_discovery", run.asset_id, result, 65536)
    assert result.status == "succeeded" and result.evidence_ids
    assert next(fact for fact in observation.facts if fact.type == "open_port").values == {
        "port": 80,
        "service": "http",
    }
    assert executor.last_error == ""
    assert "192.0.2.10" not in (tmp_path / "live-test" / "trace.jsonl").read_text()


def test_failed_job_preserves_bounded_sanitized_diagnostic(tmp_path, monkeypatch):
    executor, capability, run = composition(tmp_path)

    def get(url, **kwargs):
        if url.endswith("/health"):
            return Response({"status": "healthy"})
        return Response(
            {
                "job_id": "offline-job",
                "status": "failed",
                "return_code": 1,
                "stdout": "",
                "stderr": "synthetic nmap diagnostic password=DoNotStore 192.0.2.10",
            }
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", get)
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.post",
        lambda url, **kwargs: (
            Response({})
            if url.endswith("/api/cache/clear")
            else Response(
                {"job_id": "offline-job", "job_token": "secret", "status": "running"}, 202
            )
        ),
    )
    result = executor.execute(capability, run)
    trace = (tmp_path / "live-test" / "trace.jsonl").read_text()
    assert result.status == "failed" and not result.evidence_ids
    assert "synthetic nmap diagnostic" in executor.last_error
    assert "DoNotStore" not in executor.last_error and "192.0.2.10" not in executor.last_error
    assert result.parser_warnings == [executor.last_error]
    assert "synthetic nmap diagnostic" in trace
    assert "DoNotStore" not in trace and "192.0.2.10" not in trace


def test_explicit_compatible_nested_job_schema_preserves_error(tmp_path, monkeypatch):
    executor, capability, run = composition(tmp_path)

    def get(url, **kwargs):
        if url.endswith("/health"):
            return Response({"status": "healthy"})
        return Response(
            {
                "status": "failed",
                "result": {
                    "exit_code": 1,
                    "output": "",
                    "error": "synthetic nested diagnostic",
                },
            }
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", get)
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.post",
        lambda url, **kwargs: (
            Response({})
            if url.endswith("/api/cache/clear")
            else Response(
                {"job_id": "offline-job", "job_token": "secret", "status": "running"}, 202
            )
        ),
    )
    result = executor.execute(capability, run)
    assert result.status == "failed"
    assert executor.last_error == "synthetic nested diagnostic"


def test_unrecognized_terminal_schema_fails_closed(tmp_path, monkeypatch):
    executor, capability, run = composition(tmp_path)
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.get",
        lambda url, **kwargs: (
            Response({"status": "healthy"})
            if url.endswith("/health")
            else Response({"status": "failed", "message": "ambiguous"})
        ),
    )
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.post",
        lambda url, **kwargs: (
            Response({})
            if url.endswith("/api/cache/clear")
            else Response(
                {"job_id": "offline-job", "job_token": "secret", "status": "running"}, 202
            )
        ),
    )
    result = executor.execute(capability, run)
    assert result.status == "failed" and not result.evidence_ids
    assert executor.last_error == "malformed HexStrike job response"
