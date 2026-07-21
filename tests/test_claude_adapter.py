from datetime import datetime, timezone
from pathlib import Path

from core.adapters.base import RunContext
from core.adapters.claude import ClaudeAdapter, _safe_parse
from core.investigation.models import Evidence, InvestigationState, ServiceObservation
from core.policy import Policy
from core.profiles import AssetRegistry, ProfileCatalog
from core.schemas.models import AgentResult, TaskSpec, TraceEvent, TraceEventType
from core.trace.writer import TraceWriter

ROOT = Path(__file__).resolve().parent.parent


class _Executor:
    name = "fake"

    def __init__(self):
        self.calls = []

    def run(self, task, ctx):
        self.calls.append((task.target, task.agent_params["tool"]))
        tool = task.agent_params["tool"]
        output = (
            "80/tcp open http Apache httpd 2.4.52\nNmap done: 1 host up\n"
            if tool == "nmap"
            else "HTTP 200 Apache"
        )
        return AgentResult(
            task_id=task.id,
            completed=True,
            final_output=output,
            raw_trace_path=str(ctx.trace.path),
        )


def _catalog():
    return ProfileCatalog.from_yaml(ROOT / "profiles.yaml")


def _assets():
    return AssetRegistry.from_yaml(ROOT / "assets.yaml")


def _policy(*tools):
    return Policy(default="deny", allowed_tools=list(tools), allowed_targets=["juiceshop"])


def _task(asset_id="asset:web-lab-01"):
    return TaskSpec(
        id="t",
        category="c",
        task="assess the authorised lab",
        asset_id=asset_id,
        scoring={"success_predicate": "x"},
    )


def _ctx(tmp_path):
    return RunContext(
        run_id="t",
        run_dir=tmp_path,
        trace=TraceWriter("t", tmp_path / "trace.jsonl"),
    )


def _events(tmp_path):
    return [
        TraceEvent.model_validate_json(line)
        for line in (tmp_path / "trace.jsonl").read_text().splitlines()
    ]


def _web_state():
    evidence = Evidence(
        evidence_id="inv-1-1",
        asset_id="asset:web-lab-01",
        capability_id="network.service.inventory",
        tool_name="nmap",
        execution_status="completed",
        raw_output_sha256="a" * 64,
        observed_at=datetime.now(timezone.utc),
        complete=True,
    )
    return InvestigationState(
        investigation_id="inv-1",
        asset_id="asset:web-lab-01",
        objective="assess risks",
        evidence=[evidence],
        services=[
            ServiceObservation(
                asset_id="asset:web-lab-01",
                port=80,
                state="open",
                service="http",
                evidence_id=evidence.evidence_id,
            )
        ],
        executed_capabilities={"network.service.inventory"},
    )


def test_parser_discards_profile_tool_target_and_flags():
    proposal = _safe_parse(
        '{"action":{"asset_id":"asset:web-lab-01",'
        '"capability_id":"web.http.metadata","profile_id":"shell",'
        '"tool":"bash","target":"8.8.8.8","flags":"-x"}}'
    )
    assert proposal.capability_id == "web.http.metadata"
    assert not hasattr(proposal, "profile_id")
    assert not hasattr(proposal, "tool")


def test_initial_prompt_offers_only_inventory(tmp_path):
    prompts = []

    def llm(system, user):
        prompts.append(user)
        return '{"reasoning":"stop","done":true}'

    adapter = ClaudeAdapter(_catalog(), _assets(), llm_fn=llm)
    assert adapter.run(_task(), _ctx(tmp_path)).completed is True
    assert "network.service.inventory" in prompts[0]
    assert "web.http.metadata" not in prompts[0]
    assert "profile_id" not in prompts[0]


def test_candidate_maps_to_fixed_profile_and_updates_state(tmp_path):
    outputs = iter(
        [
            '{"action":{"asset_id":"asset:web-lab-01","capability_id":"web.http.metadata"}}',
            '{"reasoning":"enough","done":true}',
        ]
    )
    executor = _Executor()
    adapter = ClaudeAdapter(
        _catalog(),
        _assets(),
        llm_fn=lambda system, user: next(outputs),
        executor=executor,
        policy=_policy("httpx", "gobuster", "nuclei"),
        state=_web_state(),
    )
    result = adapter.run(_task(), _ctx(tmp_path))
    assert result.completed is True
    assert executor.calls == [("juiceshop", "httpx")]
    assert "web.http.metadata" in adapter.state.executed_capabilities
    assert adapter.state.evidence[-1].facts["profile_id"] == "http-fingerprint-low"


def test_capability_outside_candidates_fails_closed(tmp_path):
    executor = _Executor()
    adapter = ClaudeAdapter(
        _catalog(),
        _assets(),
        llm_fn=lambda system, user: (
            '{"action":{"asset_id":"asset:web-lab-01","capability_id":"exploit.shell"}}'
        ),
        executor=executor,
        policy=_policy("httpx"),
        state=_web_state(),
    )
    assert adapter.run(_task(), _ctx(tmp_path)).completed is False
    assert executor.calls == []
    assert any(
        event.rule == "capability_not_offered" and event.verdict == "deny"
        for event in _events(tmp_path)
        if event.type is TraceEventType.POLICY_EVENT
    )


def test_different_asset_fails_closed(tmp_path):
    executor = _Executor()
    adapter = ClaudeAdapter(
        _catalog(),
        _assets(),
        llm_fn=lambda system, user: (
            '{"action":{"asset_id":"asset:vm-lab-01","capability_id":"web.http.metadata"}}'
        ),
        executor=executor,
        policy=_policy("httpx"),
        state=_web_state(),
    )
    adapter.run(_task(), _ctx(tmp_path))
    assert executor.calls == []
    assert any(event.rule == "asset_mismatch" for event in _events(tmp_path))


def test_approval_requirement_is_pending_not_blocked(tmp_path):
    executor = _Executor()
    adapter = ClaudeAdapter(
        _catalog(),
        _assets(),
        llm_fn=lambda system, user: (
            '{"action":{"asset_id":"asset:web-lab-01","capability_id":"network.service.inventory"}}'
        ),
        executor=executor,
        policy=_policy("nmap"),
    )
    result = adapter.run(_task(), _ctx(tmp_path))
    assert result.completed is False
    assert executor.calls == []
    assert "network.service.inventory" in adapter.state.pending_approval_capabilities
    assert "network.service.inventory" not in adapter.state.blocked_capabilities
    checkpoint = InvestigationState.model_validate_json(
        (tmp_path / "investigation_state.json").read_text()
    )
    assert "network.service.inventory" in checkpoint.pending_approval_capabilities
