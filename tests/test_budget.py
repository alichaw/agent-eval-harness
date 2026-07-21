"""Autonomous-loop token and cost budget tests."""

from pathlib import Path

from core.adapters.base import RunContext
from core.adapters.claude import ClaudeAdapter, LLMResponse
from core.profiles import AssetRegistry, ProfileCatalog
from core.schemas.models import TaskSpec, TraceEvent, TraceEventType
from core.trace.writer import TraceWriter

ROOT = Path(__file__).resolve().parent.parent


def _catalog():
    return ProfileCatalog.from_yaml(ROOT / "profiles.yaml")


def _assets():
    return AssetRegistry.from_yaml(ROOT / "assets.yaml")


def _task():
    return TaskSpec(
        id="b",
        category="budget",
        task="inventory",
        asset_id="asset:web-lab-01",
        scoring={"success_predicate": "x"},
    )


def _ctx(tmp_path):
    return RunContext("b", tmp_path, TraceWriter("b", tmp_path / "trace.jsonl"))


def _events(tmp_path):
    return [
        TraceEvent.model_validate_json(line)
        for line in (tmp_path / "trace.jsonl").read_text().splitlines()
    ]


def test_token_budget_exhaustion_fails_closed(tmp_path):
    response = LLMResponse(
        '{"reasoning":"continue","action":{"asset_id":"asset:web-lab-01",'
        '"profile_id":"http-metadata-fetch-low"}}',
        input_tokens=80,
        output_tokens=40,
    )
    adapter = ClaudeAdapter(
        _catalog(),
        _assets(),
        llm_fn=lambda _system, _user: response,
        max_tokens_total=100,
    )

    result = adapter.run(_task(), _ctx(tmp_path))

    assert result.completed is False
    budget_events = [event for event in _events(tmp_path) if event.type is TraceEventType.BUDGET]
    assert budget_events and budget_events[0].text == "max_tokens"


def test_cost_budget_exhaustion_fails_closed(tmp_path):
    response = LLMResponse('{"reasoning":"done","done":true}', 1, 1, cost_usd=0.2)
    adapter = ClaudeAdapter(
        _catalog(),
        _assets(),
        llm_fn=lambda _system, _user: response,
        max_tokens_total=1_000,
        max_cost_usd=0.1,
    )

    result = adapter.run(_task(), _ctx(tmp_path))

    assert result.completed is False
    budget_events = [event for event in _events(tmp_path) if event.type is TraceEventType.BUDGET]
    assert budget_events and budget_events[0].text == "max_cost_usd"
