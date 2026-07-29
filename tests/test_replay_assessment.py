"""Replay must preserve valid negative security-assessment results."""

from core.replay import replay_run
from core.schemas.models import ToolMode, TraceEventType
from core.trace.writer import TraceWriter


def test_replay_completes_negative_smb_assessment(tmp_path):
    writer = TraceWriter("assessment", tmp_path / "trace.jsonl")
    writer.emit(TraceEventType.POLICY_EVENT, verdict="allow", rule="test_allow")
    binding = {
        "tool": "smb-anonymous-access",
        "mode": ToolMode.REAL,
        "executed": True,
        "action_id": "assessment-action",
        "asset_id": "asset:test",
        "profile_id": "profile:test",
        "policy_verdict": "allow",
    }
    writer.emit(TraceEventType.TOOL_CALL, **binding)
    writer.emit(
        TraceEventType.TOOL_RESULT,
        **binding,
        outcome="succeeded",
        return_code=1,
        evidence_predicate_passed=True,
        result_digest="a" * 64,
    )

    replayed = replay_run(tmp_path)

    assert replayed["completed"] is True
    assert replayed["had_error"] is False
