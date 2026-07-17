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
