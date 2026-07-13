"""core/replay.py — recompute a run's verdict PURELY from its stored trace.

No network, no docker, no server — just read trace.jsonl and re-derive `completed`.
If replay disagrees with the stored result.json, the run is not reproducible, which
is itself a finding. This is the "auditable" leg of the project's core promise.
"""

from __future__ import annotations

from pathlib import Path

from core.schemas.models import TraceEvent, TraceEventType


def replay_run(run_dir: str | Path) -> dict:
    run_dir = Path(run_dir)
    events = [
        TraceEvent.model_validate_json(line)
        for line in (run_dir / "trace.jsonl").read_text().splitlines()
    ]

    # same rule the adapter used: reachable iff a tool_result reported an
    # open/closed port state; a hard error means not completed.
    had_error = any(e.type is TraceEventType.ERROR for e in events)
    tool_results = [e for e in events if e.type is TraceEventType.TOOL_RESULT]

    reachable = False
    for e in tool_results:
        text = e.text or ""
        if "'open'" in text or "'closed'" in text:
            reachable = True

    completed = (not had_error) and bool(tool_results) and reachable
    return {
        "completed": completed,
        "n_events": len(events),
        "had_error": had_error,
        "n_tool_results": len(tool_results),
    }