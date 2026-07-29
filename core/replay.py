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
    rules = {event.rule for event in events if event.rule}
    t3_access = "credential_lease_created" in rules or "session_requested" in rules
    if t3_access:
        commands = [
            event
            for event in tool_results
            if event.tool == "t3-fixed-observation"
        ]
        approval = "t3_approval_verified" in rules
        authenticated = "authentication_succeeded" in rules
        closed = "session_closed" in rules
        lease_invalidated = "credential_lease_invalidated" in rules
        cleanup = "cleanup_failed" not in rules and closed and lease_invalidated
        commands_succeeded = sum(
            event.outcome == "succeeded"
            and event.return_code == 0
            and event.evidence_predicate_passed is True
            for event in commands
        )
        stopped = "kill_switch_activated" in rules
        completed = bool(commands) and commands_succeeded == len(commands)
        assessment_succeeded = (
            completed
            and approval
            and authenticated
            and cleanup
            and not stopped
        )
        return {
            "completed": completed,
            "assessment_succeeded": assessment_succeeded,
            "approval_succeeded": approval,
            "authentication_succeeded": authenticated,
            "commands_attempted": len(commands),
            "commands_succeeded": commands_succeeded,
            "stopped_by_kill_switch": stopped,
            "session_closed": closed,
            "cleanup_succeeded": cleanup,
            "credential_lease_invalidated": lease_invalidated,
            "n_events": len(events),
            "had_error": had_error,
            "n_tool_results": len(tool_results),
        }

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
        if "'open'" in text or "'closed'" in text:  # nmap reachability
            succeeded = True
        if "success=True" in text:  # web tools ran ok
            succeeded = True
        m = re.search(r"findings=(\d+)", text)  # web tools found something
        if m and int(m.group(1)) > 0:
            succeeded = True
        # T1 recon: host discovery / connectivity — the probe running IS the result
        if "live_hosts=yes" in text or "reachable=" in text:
            succeeded = True
        if re.search(r"\brc=0\b", text):  # discovery/connectivity ok
            succeeded = True
        if "assessment_ran=yes" in text:
            # Security assessments can produce a valid negative result with rc=1
            # (for example anonymous SMB access denied).
            succeeded = True

    completed = (not had_error) and bool(tool_results) and succeeded
    return {
        "completed": completed,
        "n_events": len(events),
        "had_error": had_error,
        "n_tool_results": len(tool_results),
    }
