"""tests/test_mock_agent.py — the first END-TO-END test.

We run MockAgent and check both sides of its output:
  1. the returned AgentResult is well-formed
  2. every trace line it emitted re-parses as a TraceEvent, with a gapless seq

This is where the harness stops testing static schema and starts testing a *run*.
"""

from pathlib import Path

import pytest

from core.adapters.base import AgentAdapter, RunContext
from core.adapters.mock import MockAgent
from core.schemas.models import AgentResult, TaskSpec, TraceEvent, TraceEventType
from core.trace.writer import TraceWriter


def _make_ctx(tmp_path: Path) -> RunContext:
    trace = TraceWriter("test_run", tmp_path / "trace.jsonl")
    return RunContext(run_id="test_run", run_dir=tmp_path, trace=trace)


def _task(task_id: str) -> TaskSpec:
    return TaskSpec(
        id=task_id,
        category="test",
        task=f"do {task_id}",
        scoring={"success_predicate": "x"},
    )


def _read_events(path: Path) -> list[TraceEvent]:
    # every emitted line MUST round-trip back into a TraceEvent
    return [TraceEvent.model_validate_json(line) for line in path.read_text().splitlines()]


def test_mock_agent_returns_valid_result(tmp_path):
    result = MockAgent().run(_task("recon_basic"), _make_ctx(tmp_path))
    assert isinstance(result, AgentResult)
    assert result.completed is True
    assert result.tool_calls and result.tool_calls[0].name == "nmap"


def test_trace_is_schema_valid_and_seq_gapless(tmp_path):
    ctx = _make_ctx(tmp_path)
    MockAgent().run(_task("recon_basic"), ctx)
    events = _read_events(tmp_path / "trace.jsonl")
    assert events, "no trace written"
    # gapless monotonic 0..n-1 — the invariant the verifier will rely on
    assert [e.seq for e in events] == list(range(len(events)))
    types = {e.type for e in events}
    assert TraceEventType.PROMPT in types
    assert TraceEventType.TOOL_CALL in types


def test_default_script_runs_any_unscripted_case(tmp_path):
    result = MockAgent().run(_task("some_unscripted_case"), _make_ctx(tmp_path))
    assert result.completed is True  # fallback keeps end-to-end unbroken


def test_hallucinated_action_seed_exists(tmp_path):
    # injection_indirect claims an action with no backing tool_call. The verifier
    # (W6) will flag it; here we just prove the seed is present for later.
    result = MockAgent().run(_task("injection_indirect"), _make_ctx(tmp_path))
    assert "downloaded /etc/shadow" in result.claimed_actions
    assert "http_get" in {tc.name for tc in result.tool_calls}
    # nothing in the tool calls plausibly performs that download -> hallucination
    assert not any("shadow" in tc.name for tc in result.tool_calls)


def test_configurable_scripts_override_defaults(tmp_path):
    from core.adapters.mock import MockScript, MockToolCall

    custom = {"recon_basic": MockScript(tool_calls=[MockToolCall("masscan")], completed=False)}
    result = MockAgent(scripts=custom).run(_task("recon_basic"), _make_ctx(tmp_path))
    assert result.completed is False
    assert result.tool_calls[0].name == "masscan"


def test_mock_is_agent_adapter():
    assert issubclass(MockAgent, AgentAdapter)


def test_abstract_adapter_cannot_be_instantiated():
    with pytest.raises(TypeError):
        AgentAdapter()  # abstract run() -> not instantiable
