"""tests/test_hexstrike_adapter.py — test the adapter's LOGIC without a live server.

We fake requests.get/post so CI (and you, offline) can verify the parts that
actually matter and that W1 taught us the hard way:
  * "filtered" port state  -> completed=False (firewall blocked it)
  * "open" port state      -> completed=True
  * server down            -> completed=False, error event, no crash
  * "Host is up" alone must NOT be treated as success (the -Pn trap)
"""

from pathlib import Path

import pytest

from core.adapters.base import RunContext
from core.adapters.hexstrike import HexStrikeAdapter
from core.safety import ExecutionState, KillSwitch
from core.schemas.models import AgentResult, TaskSpec, TraceEvent, TraceEventType
from core.trace.writer import TraceWriter

# ---- fakes ---------------------------------------------------------------


class _FakeResp:
    def __init__(self, payload, status=200, ok=True):
        self._payload = payload
        self.status_code = status
        self.ok = ok

    def json(self):
        return self._payload


def _ctx(tmp_path: Path) -> RunContext:
    return RunContext(
        run_id="t", run_dir=tmp_path, trace=TraceWriter("t", tmp_path / "trace.jsonl")
    )


def _task(target="172.18.0.2", **params) -> TaskSpec:
    return TaskSpec(
        id="recon",
        category="c",
        task="scan it",
        scoring={"success_predicate": "x"},
        target=target,
        agent_params={"scan_type": "-sV", "ports": "3000", **params},
    )


def _events(p: Path) -> list[TraceEvent]:
    return [
        TraceEvent.model_validate_json(line)
        for line in (p / "trace.jsonl").read_text().splitlines()
    ]


# nmap output where the port is OPEN (target reachable)
_OPEN = (
    "Nmap scan report for 172.18.0.2\n"
    "Host is up (0.001s latency).\n\n"
    "PORT     STATE SERVICE\n"
    "3000/tcp open  ppp?\n"
)
# nmap output where the port is FILTERED, but still says "Host is up".
# The -Pn result must not be interpreted as successful reachability.
_FILTERED = (
    "Nmap scan report for 1.1.1.1\nHost is up.\n\nPORT   STATE    SERVICE\n80/tcp filtered http\n"
)


@pytest.fixture
def healthy(monkeypatch):
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.get", lambda *a, **k: _FakeResp({"status": "healthy"})
    )
    # cache-clear POST is fire-and-forget; make it a no-op unless overridden
    monkeypatch.setattr("core.adapters.hexstrike.requests.post", lambda *a, **k: _FakeResp({}))


def _patch_nmap(monkeypatch, stdout, return_code=0, status=200):
    def fake_post(url, **kwargs):
        if url.endswith("/api/cache/clear"):
            return _FakeResp({})
        return _FakeResp(
            {"return_code": return_code, "stdout": stdout, "execution_time": 1.2}, status=status
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.post", fake_post)


def test_open_port_is_completed(tmp_path, monkeypatch, healthy):
    _patch_nmap(monkeypatch, _OPEN)
    res = HexStrikeAdapter().run(_task(), _ctx(tmp_path))
    assert isinstance(res, AgentResult)
    assert res.completed is True
    assert res.tool_calls[0].name == "nmap"


def test_filtered_port_is_not_completed(tmp_path, monkeypatch, healthy):
    # THE W1 LESSON: "Host is up" is present, but the port is filtered -> blocked.
    # completed must be False; we must not be fooled by the -Pn "Host is up".
    _patch_nmap(monkeypatch, _FILTERED)
    res = HexStrikeAdapter().run(_task(target="1.1.1.1"), _ctx(tmp_path))
    assert res.completed is False


def test_server_down_fails_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.get",
        lambda *a, **k: _FakeResp({"status": "dead"}, ok=False),
    )
    res = HexStrikeAdapter().run(_task(), _ctx(tmp_path))
    assert res.completed is False
    kinds = {e.type for e in _events(tmp_path)}
    assert TraceEventType.ERROR in kinds


def test_trace_is_schema_valid(tmp_path, monkeypatch, healthy):
    _patch_nmap(monkeypatch, _OPEN)
    HexStrikeAdapter().run(_task(), _ctx(tmp_path))
    events = _events(tmp_path)  # every line must parse
    assert [e.seq for e in events] == list(range(len(events)))  # gapless
    kinds = {e.type for e in events}
    assert TraceEventType.TOOL_CALL in kinds
    assert TraceEventType.CLAIMED_ACTION in kinds  # seeds W4 verification


# -- data-driven tool registry (TOOL_SPECS) --------------------------------


def test_tool_specs_registry_covers_declared_tools():
    from core.adapters.hexstrike import HexStrikeAdapter

    a = HexStrikeAdapter()
    # every tool in the registry can build a request without error
    for tool in a.TOOL_SPECS:
        endpoint, body, claim = a._build_request(tool, "172.18.0.2", {"ports": "3000"})
        assert endpoint.endswith(f"/api/tools/{tool}") or "endpoint" in a.TOOL_SPECS[tool]
        assert body and claim
        # web tools must carry the port in the URL
        if a.TOOL_SPECS[tool]["target_style"] == "url":
            field = a.TOOL_SPECS[tool]["target_field"]
            assert ":3000" in body[field]


def test_unsupported_tool_raises():
    import pytest

    from core.adapters.hexstrike import HexStrikeAdapter, HexStrikeError

    a = HexStrikeAdapter()
    with pytest.raises(HexStrikeError):
        a._build_request("metasploit", "1.2.3.4", {})


def test_web_judge_completes_even_with_zero_findings():
    # a scan that ran successfully but found nothing is still "completed"
    from core.adapters.hexstrike import HexStrikeAdapter

    a = HexStrikeAdapter()
    completed, summary = a._judge("nuclei", 200, {"success": True, "stdout": ""})
    assert completed is True


def test_asset_tool_args_override_profile(tmp_path):
    # asset's tool_args should merge over profile params (target-specific quirks)
    from pathlib import Path

    from core.executor import gate
    from core.profiles import AssetRegistry, ProfileCatalog

    ROOT = Path(__file__).resolve().parent.parent
    cat = ProfileCatalog.from_yaml(ROOT / "profiles.yaml")
    assets = AssetRegistry.from_yaml(ROOT / "assets.yaml")
    decision, resolved = gate(cat, assets, None, "asset:web-lab-01", "web-directory-enum-low")
    # the exclude-length from the asset's tool_args must be present in params
    assert "exclude-length" in resolved["params"].get("additional_args", "")


def test_kill_switch_cancels_active_nmap_job(tmp_path, monkeypatch):
    kill_file = tmp_path / "KILL"
    kill_file.touch()
    cancelled = []

    def fake_get(url, **kwargs):
        if url.endswith("/health"):
            return _FakeResp({"status": "healthy"})
        if cancelled:
            return _FakeResp(
                {
                    "status": "cancelled",
                    "result": {
                        "success": False,
                        "return_code": -15,
                        "stdout": "",
                        "stderr": "terminated",
                        "cancelled": True,
                    },
                }
            )
        return _FakeResp({"status": "running"})

    def fake_post(url, **kwargs):
        if url.endswith("/api/cache/clear"):
            return _FakeResp({})
        if url.endswith("/api/jobs/nmap"):
            assert kwargs["headers"]["X-Job-Create-Token"] == "create-secret"
            return _FakeResp(
                {"job_id": "opaque-job", "job_token": "secret-capability"},
                status=202,
            )
        raise AssertionError(url)

    def fake_delete(url, **kwargs):
        cancelled.append((url, kwargs["headers"]["X-Job-Token"]))
        return _FakeResp({"status": "cancelling"}, status=202)

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", fake_get)
    monkeypatch.setattr("core.adapters.hexstrike.requests.post", fake_post)
    monkeypatch.setattr("core.adapters.hexstrike.requests.delete", fake_delete)
    ctx = _ctx(tmp_path)
    ctx.kill_switch = KillSwitch(kill_file)
    ctx.job_create_token = "create-secret"

    result = HexStrikeAdapter().run(_task(), ctx)
    states = [
        event.state for event in _events(tmp_path) if event.type is TraceEventType.EXECUTION_STATE
    ]

    assert result.completed is False
    assert result.claimed_actions == []
    assert cancelled == [("http://127.0.0.1:8888/api/jobs/opaque-job", "secret-capability")]
    assert ExecutionState.CANCELLING.value in states
    assert ExecutionState.KILLED.value in states
    trace_text = (tmp_path / "trace.jsonl").read_text()
    assert "secret-capability" not in trace_text


def test_cancellable_nmap_job_completes_normally(tmp_path, monkeypatch):
    def fake_get(url, **kwargs):
        if url.endswith("/health"):
            return _FakeResp({"status": "healthy"})
        return _FakeResp(
            {
                "status": "succeeded",
                "result": {
                    "success": True,
                    "return_code": 0,
                    "stdout": _OPEN,
                    "stderr": "",
                },
            }
        )

    def fake_post(url, **kwargs):
        if url.endswith("/api/cache/clear"):
            return _FakeResp({})
        assert kwargs["headers"]["X-Job-Create-Token"] == "create-secret"
        assert kwargs["json"]["ports"] == ""
        return _FakeResp(
            {"job_id": "opaque-job", "job_token": "secret-capability"},
            status=202,
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", fake_get)
    monkeypatch.setattr("core.adapters.hexstrike.requests.post", fake_post)
    ctx = _ctx(tmp_path)
    ctx.kill_switch = KillSwitch(tmp_path / "KILL")
    ctx.job_create_token = "create-secret"

    result = HexStrikeAdapter().run(_task(scan_type="-sn", ports="22,80,443"), ctx)

    assert result.completed is True
    assert "secret-capability" not in (tmp_path / "trace.jsonl").read_text()


def test_cancellable_job_requires_create_capability(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.get",
        lambda *args, **kwargs: _FakeResp({"status": "healthy"}),
    )
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.post",
        lambda *args, **kwargs: _FakeResp({}),
    )
    ctx = _ctx(tmp_path)
    ctx.kill_switch = KillSwitch(tmp_path / "KILL")

    result = HexStrikeAdapter().run(_task(), ctx)

    assert result.completed is False
    errors = [event for event in _events(tmp_path) if event.type is TraceEventType.ERROR]
    assert errors
    assert "creation capability is required" in errors[-1].text


def test_cancellable_httpx_job_uses_structured_authenticated_request(tmp_path, monkeypatch):
    def fake_get(url, **kwargs):
        if url.endswith("/health"):
            return _FakeResp({"status": "healthy"})
        return _FakeResp(
            {
                "status": "succeeded",
                "result": {
                    "success": True,
                    "return_code": 0,
                    "stdout": "http://172.18.0.2:3000 [200]",
                    "stderr": "",
                },
            }
        )

    def fake_post(url, **kwargs):
        if url.endswith("/api/cache/clear"):
            return _FakeResp({})
        assert url.endswith("/api/jobs/httpx")
        assert kwargs["headers"]["X-Job-Create-Token"] == "create-secret"
        assert kwargs["json"]["target"] == "http://172.18.0.2:3000"
        assert kwargs["json"]["threads"] == 10
        assert "additional_args" not in kwargs["json"]
        return _FakeResp(
            {"job_id": "opaque-job", "job_token": "secret-capability"},
            status=202,
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", fake_get)
    monkeypatch.setattr("core.adapters.hexstrike.requests.post", fake_post)
    ctx = _ctx(tmp_path)
    ctx.kill_switch = KillSwitch(tmp_path / "KILL")
    ctx.job_create_token = "create-secret"

    result = HexStrikeAdapter().run(
        _task(
            tool="httpx",
            probe=True,
            tech_detect=True,
            status_code=True,
            title=True,
            web_server=True,
            threads=10,
        ),
        ctx,
    )

    assert result.completed is True
    trace_text = (tmp_path / "trace.jsonl").read_text()
    assert "create-secret" not in trace_text
    assert "secret-capability" not in trace_text


def test_cancellable_gobuster_job_converts_only_safe_asset_argument(tmp_path, monkeypatch):
    def fake_get(url, **kwargs):
        if url.endswith("/health"):
            return _FakeResp({"status": "healthy"})
        return _FakeResp(
            {
                "status": "succeeded",
                "result": {
                    "success": True,
                    "return_code": 0,
                    "stdout": "/api (Status: 200)",
                    "stderr": "",
                },
            }
        )

    def fake_post(url, **kwargs):
        if url.endswith("/api/cache/clear"):
            return _FakeResp({})
        assert url.endswith("/api/jobs/gobuster")
        assert kwargs["headers"]["X-Job-Create-Token"] == "create-secret"
        assert kwargs["json"] == {
            "url": "http://172.18.0.2:3000",
            "mode": "dir",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "exclude_length": 9903,
        }
        return _FakeResp(
            {"job_id": "opaque-job", "job_token": "secret-capability"},
            status=202,
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", fake_get)
    monkeypatch.setattr("core.adapters.hexstrike.requests.post", fake_post)
    ctx = _ctx(tmp_path)
    ctx.kill_switch = KillSwitch(tmp_path / "KILL")
    ctx.job_create_token = "create-secret"

    result = HexStrikeAdapter().run(
        _task(
            tool="gobuster",
            mode="dir",
            wordlist="/usr/share/wordlists/dirb/common.txt",
            additional_args="--exclude-length 9903",
        ),
        ctx,
    )

    assert result.completed is True
    assert "secret-capability" not in (tmp_path / "trace.jsonl").read_text()


def test_cancellable_gobuster_rejects_unstructured_asset_arguments(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.get",
        lambda *args, **kwargs: _FakeResp({"status": "healthy"}),
    )
    monkeypatch.setattr(
        "core.adapters.hexstrike.requests.post",
        lambda *args, **kwargs: _FakeResp({}),
    )
    ctx = _ctx(tmp_path)
    ctx.kill_switch = KillSwitch(tmp_path / "KILL")
    ctx.job_create_token = "create-secret"

    result = HexStrikeAdapter().run(
        _task(tool="gobuster", additional_args="--exclude-length 1; id"),
        ctx,
    )

    assert result.completed is False
    errors = [event.text for event in _events(tmp_path) if event.type is TraceEventType.ERROR]
    assert any("unsupported gobuster asset arguments" in text for text in errors)



def test_cancellable_nuclei_job_uses_only_bounded_structured_fields(tmp_path, monkeypatch):
    def fake_get(url, **kwargs):
        if url.endswith("/health"):
            return _FakeResp({"status": "healthy"})
        return _FakeResp(
            {
                "status": "succeeded",
                "result": {
                    "success": False,
                    "return_code": 1,
                    "stdout": "",
                    "stderr": "template configuration unavailable",
                },
            }
        )

    def fake_post(url, **kwargs):
        if url.endswith("/api/cache/clear"):
            return _FakeResp({})
        assert url.endswith("/api/jobs/nuclei")
        assert kwargs["headers"]["X-Job-Create-Token"] == "create-secret"
        assert kwargs["json"] == {
            "target": "http://172.18.0.2:3000",
            "template_set": "baseline-web-v1",
            "rate_limit": 5,
            "concurrency": 1,
            "timeout": 5,
        }
        return _FakeResp(
            {"job_id": "opaque-job", "job_token": "secret-capability"},
            status=202,
        )

    monkeypatch.setattr("core.adapters.hexstrike.requests.get", fake_get)
    monkeypatch.setattr("core.adapters.hexstrike.requests.post", fake_post)
    ctx = _ctx(tmp_path)
    ctx.kill_switch = KillSwitch(tmp_path / "KILL")
    ctx.job_create_token = "create-secret"

    result = HexStrikeAdapter().run(
        _task(
            tool="nuclei",
            template_set="baseline-web-v1",
            rate_limit=5,
            concurrency=1,
            timeout=5,
        ),
        ctx,
    )

    assert result.completed is False
    assert result.final_output == "template configuration unavailable"
    assert result.claimed_actions == []
    trace_text = (tmp_path / "trace.jsonl").read_text()
    assert "create-secret" not in trace_text
    assert "secret-capability" not in trace_text
    assert "additional_args" not in trace_text
