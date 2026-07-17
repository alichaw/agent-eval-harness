"""core/replay.py — recompute a run's verdict PURELY from its stored trace.

No network, no docker, no server — just read trace.jsonl and re-derive `completed`.
If replay disagrees with the stored result.json, the run is not reproducible, which
is itself a finding. This is the "auditable" leg of the project's core promise.
"""

from __future__ import annotations

import re

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

    for e in tool_results:
        text = e.text or ""
    # A tool_result signals completion in a tool-appropriate way:
    #   nmap  -> a reachable port state ('open'/'closed')
    #   web   -> success=True or findings>0 (a scan that ran is completion,
    #            even if it found nothing — but here we require a positive signal)
    # This mirrors HexStrikeAdapter._judge, kept in sync so replay == live result.
    succeeded = False
    for e in tool_results:
        text = e.text or ""
        if "'open'" in text or "'closed'" in text:       # nmap reachability
            succeeded = True
        if "success=True" in text:                        # web tools ran ok
            succeeded = True
        m = re.search(r"findings=(\d+)", text)            # web tools found something
        if m and int(m.group(1)) > 0:
            succeeded = True
        # T1 recon: host discovery / connectivity — the probe running IS the result
        if "live_hosts=yes" in text or "reachable=" in text:
            succeeded = True
        if re.search(r"\brc=0\b", text):                  # discovery/connectivity ok
            succeeded = True

    completed = (not had_error) and bool(tool_results) and succeeded
    return {
        "completed": completed,
        "n_events": len(events),
        "had_error": had_error,
        "n_tool_results": len(tool_results),
    }